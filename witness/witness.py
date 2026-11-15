"""An independent witness that countersigns log checkpoints.

In production this would be a separate organisation or service (like a
Certificate Transparency log or an RFC 3161 timestamping authority). Here it
is a separate object with its own key and its own storage, which the operator
is assumed not to be able to modify.

Each receipt line in the witness log:
    checkpoint    {log_id, seq, head_hash, operator_sig?} as sent by the operator
    witness_ts    when the witness saw it
    witness_sig   witness's Ed25519 signature over canonical({checkpoint, witness_ts})
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from recorder.chain import canonical
from recorder.signer import sign, verify_signature


class Witness:
    def __init__(self, receipts_path: str | Path, private_key):
        self.receipts_path = Path(receipts_path)
        self.private_key = private_key
        self._out = self.receipts_path.open("a")

    def countersign(self, checkpoint: dict) -> dict:
        payload = {"checkpoint": checkpoint, "witness_ts": datetime.now(timezone.utc).isoformat()}
        receipt = {**payload, "witness_sig": sign(self.private_key, canonical(payload))}
        self._out.write(json.dumps(receipt) + "\n")
        self._out.flush()
        return receipt

    def close(self) -> None:
        self._out.close()


def load_receipts(receipts_path: str | Path, witness_public_key) -> tuple[list[dict], list[str]]:
    """Return (valid checkpoints, problems). Receipts with bad witness signatures are rejected."""
    checkpoints, problems = [], []
    with Path(receipts_path).open() as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue
            receipt = json.loads(line)
            payload = {"checkpoint": receipt["checkpoint"], "witness_ts": receipt["witness_ts"]}
            if verify_signature(witness_public_key, canonical(payload), receipt.get("witness_sig", "")):
                checkpoints.append(receipt["checkpoint"])
            else:
                problems.append(f"witness receipt {line_no}: invalid witness signature")
    return checkpoints, problems
