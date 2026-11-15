"""Risk-triggered checkpoints: does checkpointing right after a payment close the window?

Scenario: the agent makes a payment (record i). The operator notices and, k records
later, disguises the payment and re-signs the chain from that record. At that moment
the witness only holds the receipts issued so far. The cover-up is detected only if
some receipt covers a record at or after the payment.

Compares periodic checkpoints alone against periodic + a checkpoint after every payment.

    python -m experiment.run_risk_checkpoints
"""

import argparse
import copy
import json
import tempfile
from pathlib import Path

from attacks.attacks import _disguise, _rehash
from experiment.common import generate_run, read_jsonl, write_jsonl
from verify.verifier import verify_log

RESULTS = Path(__file__).resolve().parent.parent / "results"
DELAYS = (0, 1, 2, 5, 10, 20)
HIGH_RISK = ("transfer_funds",)


def cover_up_detected(run, records, receipts, i: int, k: int, scratch: Path) -> bool:
    """State of the world k records after payment i; operator rewrites from i."""
    log_then = copy.deepcopy(records[: i + 1 + k])
    receipts_then = [r for r in receipts if r["checkpoint"]["seq"] <= i + k]
    _disguise(log_then[i])
    for j in range(i, len(log_then)):
        _rehash(log_then[j], log_then[j - 1]["hash"], run["operator_priv"])
    log_path, rec_path = scratch / "log.jsonl", scratch / "receipts.jsonl"
    write_jsonl(log_path, log_then)
    write_jsonl(rec_path, receipts_then)
    return bool(verify_log(log_path, run["operator_pub"], "witnessed", rec_path, run["witness_pub"]))


def main(seeds: int, every: int) -> None:
    RESULTS.mkdir(exist_ok=True)
    scratch = Path(tempfile.mkdtemp())
    configs = {"periodic": (), "periodic_plus_risk": HIGH_RISK}
    stats = {c: {k: [0, 0] for k in DELAYS} for c in configs}
    receipts_count = {c: 0 for c in configs}
    n_records = n_payments = 0

    for seed in range(seeds):
        for config, tools in configs.items():
            run = generate_run(scratch / f"{config}_{seed}", n_tasks=30, checkpoint_every=every, seed=seed, checkpoint_on_tools=tools)
            records, receipts = read_jsonl(run["log"]), read_jsonl(run["receipts"])
            receipts_count[config] += len(receipts)
            payments = [i for i, r in enumerate(records) if i > 0 and r["event"]["attributes"].get("gen_ai.tool.name") == "transfer_funds"]
            if config == "periodic":
                n_records += len(records)
                n_payments += len(payments)
            for i in payments:
                for k in DELAYS:
                    if i + k < len(records):
                        stats[config][k][1] += 1
                        stats[config][k][0] += cover_up_detected(run, records, receipts, i, k, scratch)

    out = {
        "checkpoint_every": every, "seeds": seeds, "records": n_records, "payments": n_payments,
        "witness_receipts": receipts_count,
        "detected": {c: {str(k): {"detected": d, "trials": t} for k, (d, t) in s.items()} for c, s in stats.items()},
    }
    (RESULTS / "risk_checkpoints.json").write_text(json.dumps(out, indent=2))

    def cell(c, k):
        d, t = stats[c][k]
        return f"{d}/{t} ({d / t:.0%})"

    lines = [
        f"Cover-up of a payment attempted k records after it. {seeds} runs of {n_records // seeds} records, "
        f"{n_payments} payments in total, periodic checkpoint every {every} records.",
        "",
        "| Cover-up delay (records after payment) | Periodic only | Periodic + checkpoint after each payment |",
        "|---|---|---|",
        *[f"| {k} | {cell('periodic', k)} | {cell('periodic_plus_risk', k)} |" for k in DELAYS],
        f"| Witness receipts (total) | {receipts_count['periodic']} | {receipts_count['periodic_plus_risk']} |",
    ]
    text = "\n".join(lines) + "\n"
    (RESULTS / "risk_checkpoints.md").write_text(text)
    print(text)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--seeds", type=int, default=5)
    p.add_argument("--every", type=int, default=25)
    a = p.parse_args()
    main(a.seeds, a.every)
