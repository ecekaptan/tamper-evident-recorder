"""Detection experiment.

Part 1: every attack x every verification mode, N random trials each.
Part 2: checkpoint-interval sweep for the two attacks only the witness can catch.

Outputs go to results/.
"""

import argparse
import csv
import json
import random
import tempfile
from pathlib import Path

from attacks.attacks import ATTACKS
from experiment.common import generate_run, read_jsonl, write_jsonl
from verify.verifier import MODES, verify_log

RESULTS = Path(__file__).resolve().parent.parent / "results"
MODE_LABELS = {"plain": "Plain logs", "hash": "Hash chain", "signed": "+ Signatures", "witnessed": "+ Witness checkpoints"}


def run_trials(run: dict, attack_names, modes, trials: int, seed: int, scratch: Path) -> dict:
    records = read_jsonl(run["log"])
    rng = random.Random(seed)
    counts = {a: {m: 0 for m in modes} for a in attack_names}
    for attack in attack_names:
        fn = ATTACKS[attack][2]
        for _ in range(trials):
            ctx = {"records": records, "rng": rng, **run}
            tampered_path = scratch / "tampered.jsonl"
            write_jsonl(tampered_path, fn(records, ctx))
            for mode in modes:
                problems = verify_log(tampered_path, run["operator_pub"], mode, run["receipts"], run["witness_pub"])
                counts[attack][mode] += bool(problems)
    return counts


def main(trials: int, seed: int) -> None:
    RESULTS.mkdir(exist_ok=True)
    scratch = Path(tempfile.mkdtemp())

    # Part 1: detection matrix
    run = generate_run(scratch / "main", n_tasks=30, checkpoint_every=25, seed=seed)
    n_records = len(read_jsonl(run["log"]))
    n_receipts = len(read_jsonl(run["receipts"]))
    counts = run_trials(run, list(ATTACKS), MODES, trials, seed, scratch)

    rows = []
    for attack, (label, actor, _) in ATTACKS.items():
        row = {"attack": attack, "label": label, "actor": actor, "trials": trials, "plain": 0}
        row.update({m: counts[attack][m] for m in MODES})
        rows.append(row)

    with (RESULTS / "detection.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    def cell(n):
        if n == trials:
            return f"✓ {n}/{trials}"
        if n == 0:
            return f"✗ 0/{trials}"
        return f"◐ {n}/{trials}"

    cols = ["plain", *MODES]
    md = [
        f"Detection over {trials} random trials per attack. Log: {n_records} records, "
        f"witness checkpoint every 25 records ({n_receipts} receipts), seed {seed}.",
        "",
        "| Attack | Attacker | " + " | ".join(MODE_LABELS[c] for c in cols) + " |",
        "|---|---|" + "---|" * len(cols),
    ]
    for r in rows:
        md.append(f"| {r['label']} | {r['actor']} | " + " | ".join(cell(r[c]) for c in cols) + " |")
    (RESULTS / "detection_table.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))

    # Part 2: checkpoint interval sweep (witnessed mode only)
    sweep = []
    for interval in (1, 5, 10, 25, 50, 100):
        r = generate_run(scratch / f"sweep_{interval}", n_tasks=30, checkpoint_every=interval, seed=seed)
        c = run_trials(r, ["truncate_tail", "full_rewrite"], ["witnessed"], trials * 2, seed, scratch)
        receipts = len(read_jsonl(r["receipts"]))
        sweep.append({
            "checkpoint_every": interval,
            "witness_receipts": receipts,
            "worst_case_unprotected_records": interval - 1,
            "unprotected_tail_records": n_records - (read_jsonl(r["receipts"])[-1]["checkpoint"]["seq"] + 1),
            "truncate_tail_detected": c["truncate_tail"]["witnessed"] / (trials * 2),
            "full_rewrite_detected": c["full_rewrite"]["witnessed"] / (trials * 2),
        })
    (RESULTS / "checkpoint_sweep.json").write_text(json.dumps(sweep, indent=2))

    print("\nCheckpoint interval sweep (witnessed mode):")
    header = f"{'every':>6} {'receipts':>9} {'worst-case window':>18} {'window this run':>16} {'truncate':>9} {'rewrite':>8}"
    print(header)
    lines = ["| Checkpoint every | Witness receipts | Worst-case unprotected records | Unprotected this run | Truncation detected | Rewrite detected |",
             "|---|---|---|---|---|---|"]
    for s in sweep:
        print(f"{s['checkpoint_every']:>6} {s['witness_receipts']:>9} {s['worst_case_unprotected_records']:>18} "
              f"{s['unprotected_tail_records']:>16} {s['truncate_tail_detected']:>9.0%} {s['full_rewrite_detected']:>8.0%}")
        lines.append(f"| {s['checkpoint_every']} | {s['witness_receipts']} | {s['worst_case_unprotected_records']} | "
                     f"{s['unprotected_tail_records']} | {s['truncate_tail_detected']:.0%} | {s['full_rewrite_detected']:.0%} |")
    (RESULTS / "checkpoint_sweep.md").write_text(
        f"Witnessed mode, {trials * 2} random trials per cell, {n_records}-record log.\n\n" + "\n".join(lines) + "\n")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--trials", type=int, default=50)
    p.add_argument("--seed", type=int, default=0)
    a = p.parse_args()
    main(a.trials, a.seed)
