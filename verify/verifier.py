"""Auditor-side verification of a hash-chained log.

Three modes, each adding one layer, so the experiment can measure what each layer buys:
    hash       sequence numbers + hash chain only
    signed     + Ed25519 signature on every record
    witnessed  + every witness checkpoint must appear in the log with the same hash
"""

import json
from pathlib import Path

from recorder.chain import GENESIS, commit, compute_hash
from recorder.signer import verify_signature
from witness.witness import load_receipts

BODY_FIELDS = ("seq", "ts", "event", "prev_hash")
MODES = ("hash", "signed", "witnessed")


def _read_records(log_path) -> tuple[list[dict], list[str]]:
    records, problems = [], []
    with Path(log_path).open() as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                problems.append(f"line {line_no}: not valid JSON")
    return records, problems


def verify_log(
    log_path,
    public_key=None,
    mode: str = "signed",
    witness_receipts=None,
    witness_public_key=None,
) -> list[str]:
    """Return a list of problems found. An empty list means no tampering was detected."""
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    if mode in ("signed", "witnessed") and public_key is None:
        raise ValueError("signed and witnessed modes need the operator public key")
    if mode == "witnessed" and (witness_receipts is None or witness_public_key is None):
        raise ValueError("witnessed mode needs the witness receipts and witness public key")

    records, problems = _read_records(log_path)
    expected_seq, expected_prev = 0, GENESIS
    hash_by_seq = {}

    for i, rec in enumerate(records):
        seq = rec.get("seq")
        where = f"record {i} (seq {seq})"

        if seq != expected_seq:
            problems.append(f"{where}: expected seq {expected_seq} (record deleted, inserted or reordered)")
        if rec.get("prev_hash") != expected_prev:
            problems.append(f"{where}: prev_hash does not link to the previous record (chain broken)")

        body = {k: rec.get(k) for k in BODY_FIELDS}
        try:
            recomputed = compute_hash(rec.get("prev_hash", GENESIS), body)
        except (ValueError, TypeError):
            recomputed = None
        if recomputed != rec.get("hash"):
            problems.append(f"{where}: hash does not match contents (record modified)")

        if mode in ("signed", "witnessed"):
            try:
                msg = bytes.fromhex(rec.get("hash", ""))
            except ValueError:
                msg = b""
            if not verify_signature(public_key, msg, rec.get("sig", "")):
                problems.append(f"{where}: missing or invalid operator signature (forged or altered)")

        if isinstance(seq, int):
            hash_by_seq[seq] = rec.get("hash")
            expected_seq = seq + 1
        else:
            expected_seq += 1
        expected_prev = rec.get("hash", expected_prev)

    if mode == "witnessed":
        checkpoints, receipt_problems = load_receipts(witness_receipts, witness_public_key)
        problems.extend(receipt_problems)
        for cp in checkpoints:
            got = hash_by_seq.get(cp["seq"])
            if got is None:
                problems.append(f"witness checkpoint at seq {cp['seq']}: record missing from log (truncated or deleted)")
            elif got != cp["head_hash"]:
                problems.append(f"witness checkpoint at seq {cp['seq']}: hash differs from witnessed value (log rewritten)")

    return problems


def verify_reveal(log_path, vault_row: dict) -> bool:
    """Check that a revealed value + salt matches the commitment stored in the log."""
    records, _ = _read_records(log_path)
    for rec in records:
        if rec.get("seq") == vault_row["seq"]:
            stored = rec.get("event", {}).get("commitments", {}).get(vault_row["key"])
            return stored is not None and stored == commit(vault_row["salt"], vault_row["value"])
    return False
