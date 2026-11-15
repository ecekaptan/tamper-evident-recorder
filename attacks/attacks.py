"""Tampering attacks against a recorded log.

Each attack takes the original records and a context, and returns tampered
records. Attackers:
    operator   controls log storage AND holds the operator signing key
    outsider   can write to log storage but has no operator key

Target positions are drawn at random from ctx["rng"] so detection can be
reported as a rate over many trials rather than a single hand-picked case.
"""

import copy

from recorder.chain import compute_hash
from recorder.signer import sign

BODY_FIELDS = ("seq", "ts", "event", "prev_hash")


def _rehash(record: dict, prev_hash: str, key) -> dict:
    """Recompute hash (and signature, if a key is given) after changing a record."""
    record["prev_hash"] = prev_hash
    record["hash"] = compute_hash(prev_hash, {k: record[k] for k in BODY_FIELDS})
    if key is not None:
        record["sig"] = sign(key, bytes.fromhex(record["hash"]))
    else:
        record.pop("sig", None)
    return record


def _disguise(record: dict) -> None:
    """The edit the operator wants: make an action look like something harmless."""
    attrs = record["event"]["attributes"]
    attrs["gen_ai.tool.name"] = "read_file"
    record["event"]["span_name"] = "execute_tool read_file"


def _pick(ctx, low=1, high=None) -> int:
    n = len(ctx["records"])
    return ctx["rng"].randint(low, (high if high is not None else n - 2))


def _pick_sensitive_action(ctx) -> int:
    """A random action worth hiding: a payment or an email (never a no-op edit)."""
    records = ctx["records"]
    candidates = [
        i for i, r in enumerate(records[1:-1], start=1)
        if r["event"]["attributes"].get("gen_ai.tool.name") in ("transfer_funds", "send_email")
    ]
    if not candidates:  # e.g. a real model that never called a side-effecting tool
        candidates = [i for i, r in enumerate(records[1:-1], start=1)
                      if r["event"]["attributes"].get("gen_ai.tool.name") not in (None, "read_file")]
    if not candidates:
        candidates = list(range(1, len(records) - 1))
    return ctx["rng"].choice(candidates)


def edit_field(records, ctx):
    """Operator edits a record in place, without touching hashes."""
    out = copy.deepcopy(records)
    _disguise(out[_pick_sensitive_action(ctx)])
    return out


def edit_and_resign_one(records, ctx):
    """Operator edits a record, then recomputes its hash and re-signs it."""
    out = copy.deepcopy(records)
    i = _pick_sensitive_action(ctx)
    _disguise(out[i])
    _rehash(out[i], out[i - 1]["hash"], ctx["operator_priv"])
    return out


def delete_middle(records, ctx):
    """Operator removes one record from the middle of the log."""
    out = copy.deepcopy(records)
    del out[_pick(ctx)]
    return out


def reorder(records, ctx):
    """Operator swaps two adjacent records."""
    out = copy.deepcopy(records)
    i = _pick(ctx)
    out[i], out[i + 1] = out[i + 1], out[i]
    return out


def insert_signed(records, ctx):
    """Operator inserts a fabricated, correctly signed record mid-log (later records untouched)."""
    out = copy.deepcopy(records)
    i = _pick(ctx)
    fake = copy.deepcopy(out[i - 1])
    fake["seq"] = out[i - 1]["seq"] + 1
    fake["event"]["span_name"] = "execute_tool human_approval"
    fake["event"]["attributes"] = {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "human_approval"}
    fake["event"].pop("commitments", None)
    _rehash(fake, out[i - 1]["hash"], ctx["operator_priv"])
    out.insert(i, fake)
    return out


def append_outsider(records, ctx):
    """Outsider appends a correctly hash-linked record, signed with their own key."""
    out = copy.deepcopy(records)
    fake = copy.deepcopy(out[-1])
    fake["seq"] = out[-1]["seq"] + 1
    fake["event"]["span_name"] = "execute_tool transfer_funds"
    fake["event"]["attributes"] = {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "transfer_funds"}
    _rehash(fake, out[-1]["hash"], ctx["outsider_priv"])
    out.append(fake)
    return out


def truncate_tail(records, ctx):
    """Operator deletes everything after a random point."""
    return copy.deepcopy(records[: _pick(ctx, 1, len(records) - 1)])


def full_rewrite(records, ctx):
    """Operator edits a record and re-signs every record from there to the end."""
    out = copy.deepcopy(records)
    i = _pick_sensitive_action(ctx)
    _disguise(out[i])
    for j in range(i, len(out)):
        _rehash(out[j], out[j - 1]["hash"], ctx["operator_priv"])
    return out


def write_time_lie(records, ctx):
    """The recorder was fed a false event when it was written. Nothing to tamper later."""
    return copy.deepcopy(records)


ATTACKS = {
    "edit_field": ("Edit a field", "operator", edit_field),
    "edit_and_resign_one": ("Edit and re-sign one record", "operator", edit_and_resign_one),
    "delete_middle": ("Delete a middle record", "operator", delete_middle),
    "reorder": ("Swap two adjacent records", "operator", reorder),
    "insert_signed": ("Insert a signed fake record", "operator", insert_signed),
    "append_outsider": ("Append a fake record (no operator key)", "outsider", append_outsider),
    "truncate_tail": ("Truncate the tail", "operator", truncate_tail),
    "full_rewrite": ("Rewrite and re-sign the whole chain", "operator", full_rewrite),
    "write_time_lie": ("Log a false event at write time", "operator", write_time_lie),
}
