"""Append-only, hash-chained, signed log of agent events.

Each record:
    seq          position in the log, starting at 0
    ts           UTC timestamp when the record was written
    event        the agent event (a dict); sensitive values replaced by commitments
    prev_hash    hash of the previous record (GENESIS for the first)
    hash         SHA-256(prev_hash || canonical(body))
    sig          Ed25519 signature over hash (omitted when signing is off)

Sensitive values are never written to the log. Instead the event carries
    event["commitments"][key] = SHA-256(salt || canonical(value))
and the value plus salt go to a separate vault file, so an auditor can verify
the chain without seeing content, and the operator can later reveal one value.
"""

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

import rfc8785

from recorder.signer import sign

GENESIS = "0" * 64


def canonical(obj) -> bytes:
    """RFC 8785 canonical JSON, so the same data always hashes the same."""
    return rfc8785.dumps(obj)


def compute_hash(prev_hash: str, body: dict) -> str:
    return hashlib.sha256(bytes.fromhex(prev_hash) + canonical(body)).hexdigest()


def commit(salt_hex: str, value) -> str:
    """Salted commitment. The salt stops guessing of short or predictable values."""
    return hashlib.sha256(bytes.fromhex(salt_hex) + canonical(value)).hexdigest()


class ChainWriter:
    def __init__(
        self,
        log_path: str | Path,
        private_key=None,
        vault_path: str | Path | None = None,
        witness=None,
        checkpoint_every: int = 0,
        log_id: str = "agent-log",
    ):
        """
        private_key       Ed25519 key, or None to write an unsigned (hash-only) chain
        vault_path        where revealed-later sensitive values go
        witness           object with .countersign(checkpoint) -> receipt, or None
        checkpoint_every  send the head hash to the witness every N records (0 = never)
        """
        self.log_path = Path(log_path)
        self.private_key = private_key
        self.vault_path = Path(vault_path) if vault_path else None
        self.witness = witness
        self.checkpoint_every = checkpoint_every
        self.log_id = log_id
        self._lock = threading.Lock()
        self._log = self.log_path.open("a")
        self._vault = self.vault_path.open("a") if self.vault_path else None
        self.seq, self.prev_hash = self._resume()

    def _resume(self) -> tuple[int, str]:
        """Continue an existing log instead of starting a new chain."""
        last = None
        if self.log_path.stat().st_size:
            with self.log_path.open() as f:
                for line in f:
                    if line.strip():
                        last = json.loads(line)
        if last is None:
            return 0, GENESIS
        return last["seq"] + 1, last["hash"]

    def append(self, event: dict, sensitive: dict | None = None, checkpoint: bool = False) -> dict:
        """checkpoint=True forces a witness checkpoint right after this record (risk-triggered)."""
        with self._lock:
            event = dict(event)
            vault_rows = []
            if sensitive:
                commitments = {}
                for key, value in sensitive.items():
                    salt = os.urandom(16).hex()
                    commitments[key] = commit(salt, value)
                    vault_rows.append({"seq": self.seq, "key": key, "salt": salt, "value": value})
                event["commitments"] = commitments

            body = {
                "seq": self.seq,
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": event,
                "prev_hash": self.prev_hash,
            }
            record_hash = compute_hash(self.prev_hash, body)
            record = {**body, "hash": record_hash}
            if self.private_key is not None:
                record["sig"] = sign(self.private_key, bytes.fromhex(record_hash))

            self._log.write(json.dumps(record) + "\n")
            self._log.flush()
            if self._vault is not None:
                for row in vault_rows:
                    self._vault.write(json.dumps(row) + "\n")
                self._vault.flush()

            self.seq += 1
            self.prev_hash = record_hash

            periodic = self.checkpoint_every and self.seq % self.checkpoint_every == 0
            if self.witness is not None and (periodic or checkpoint):
                self._checkpoint()
            return record

    def _checkpoint(self) -> None:
        """Send the current head (last seq + hash) to the external witness."""
        checkpoint = {"log_id": self.log_id, "seq": self.seq - 1, "head_hash": self.prev_hash}
        if self.private_key is not None:
            checkpoint["operator_sig"] = sign(self.private_key, canonical(checkpoint))
        self.witness.countersign(checkpoint)

    def checkpoint_now(self) -> None:
        """Force a checkpoint, e.g. at a clean shutdown."""
        with self._lock:
            if self.witness is not None and self.seq > 0 and not self._log.closed:
                self._checkpoint()

    def close(self) -> None:
        self._log.close()
        if self._vault is not None:
            self._vault.close()
