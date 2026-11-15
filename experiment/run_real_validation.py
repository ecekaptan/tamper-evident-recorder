"""Validate the recorder on a log from a real LLM agent (agent/real_agent.py).

1. The untampered log verifies in every mode.
2. Completeness: every side-effecting action the agent really took (ground truth,
   kept outside the recorder) appears in the log, with matching arguments.
3. The full attack suite, on the real log.
4. Incident replay: find the payment to the attacker, prove it with a reveal,
   then try two cover-ups and a forged reveal.

    python -m experiment.run_real_validation --run runs/real
"""

import argparse
import copy
import json
from pathlib import Path

from agent.real_agent import ATTACKER
from attacks.attacks import ATTACKS, _rehash
from experiment.common import read_jsonl, write_jsonl
from experiment.run_detection import MODE_LABELS, run_trials
from recorder.signer import load_private_key, load_public_key
from verify.verifier import MODES, verify_log, verify_reveal

RESULTS = Path(__file__).resolve().parent.parent / "results"


def load_run(run_dir: Path) -> dict:
    return {
        "log": run_dir / "agent_log.jsonl",
        "vault": run_dir / "vault.jsonl",
        "receipts": run_dir / "witness_receipts.jsonl",
        "operator_priv": load_private_key(run_dir / "operator/private.pem"),
        "operator_pub": load_public_key(run_dir / "operator/public.pem"),
        "witness_pub": load_public_key(run_dir / "witness/public.pem"),
        "outsider_priv": load_private_key(run_dir / "outsider/private.pem"),
    }


def verdict(run, path, mode="witnessed") -> list[str]:
    return verify_log(path, run["operator_pub"], mode, run["receipts"], run["witness_pub"])


def completeness(run, truth) -> tuple[int, int, list[str]]:
    """Match each real action to a logged tool call via its revealed arguments."""
    vault = {(r["seq"], r["key"]): r for r in read_jsonl(run["vault"])}
    logged = []
    for rec in read_jsonl(run["log"]):
        name = rec["event"]["attributes"].get("gen_ai.tool.name")
        row = vault.get((rec["seq"], "gen_ai.tool.call.arguments"))
        if name in ("transfer_funds", "send_email") and row and verify_reveal(run["log"], row):
            logged.append({"tool": name, **json.loads(row["value"])})
    unmatched = [json.dumps(a) for a in truth["actions"] if a not in logged]
    return len(truth["actions"]) - len(unmatched), len(truth["actions"]), unmatched


def incident(run, scratch: Path) -> list[str]:
    lines = []
    records = read_jsonl(run["log"])
    vault_rows = [r for r in read_jsonl(run["vault"]) if r["key"] == "gen_ai.tool.call.arguments" and ATTACKER in r["value"]]
    if not vault_rows:
        return ["The model did not pay the attacker in this run, so there is no incident to replay.",
                "Try more tasks, a smaller model, or check ground_truth.json."]

    row = vault_rows[0]
    i = next(k for k, r in enumerate(records) if r["seq"] == row["seq"])
    last_cp = max((r["checkpoint"]["seq"] for r in read_jsonl(run["receipts"])), default=-1)
    lines += [
        f"Payment to the attacker found at seq {row['seq']} of {len(records)} records "
        f"(last witness checkpoint at seq {last_cp}).",
        f"Reveal of its arguments: {row['value']}",
        f"Reveal verifies against the log commitment: {verify_reveal(run['log'], row)}",
    ]
    covering = sorted(r["checkpoint"]["seq"] for r in read_jsonl(run["receipts"]) if r["checkpoint"]["seq"] >= row["seq"])
    if covering:
        lines.append(f"First witness checkpoint covering the payment: seq {covering[0]} ({covering[0] - row['seq']} records later).")

    # Why did it happen? If message content was recorded (log events), find what the model read.
    trace_id = records[i]["event"].get("trace_id")
    by_seq = {r["seq"]: r for r in records}
    cause = next((v for v in read_jsonl(run["vault"]) if v["key"] == "body" and v["seq"] < row["seq"]
                  and by_seq[v["seq"]]["event"].get("trace_id") == trace_id
                  and ATTACKER in json.dumps(v["value"]) and "tool_calls" not in v["value"]), None)
    if cause:
        text = json.dumps(cause["value"])
        start = max(text.find("SYSTEM NOTICE") - 1, 0)
        lines += [
            f"Cause: at seq {cause['seq']} (same trace, {row['seq'] - cause['seq']} records before the payment) the model was sent "
            f"a {by_seq[cause['seq']]['event']['event_name']} event containing:",
            f"  {text[start:start + 230]}...",
            f"Reveal of that message verifies against the log commitment: {verify_reveal(run['log'], cause)}",
        ]
    elif not any(r["event"].get("signal") == "log" for r in records):
        lines.append("Cause: not recorded (run the agent with --record-content to chain prompt/completion events).")
    lines.append("")

    # Cover-up 1: disguise the payment as a file read and re-sign the chain from there
    out = copy.deepcopy(records)
    out[i]["event"]["attributes"]["gen_ai.tool.name"] = "read_file"
    out[i]["event"]["span_name"] = "execute_tool read_file"
    for j in range(i, len(out)):
        _rehash(out[j], out[j - 1]["hash"], run["operator_priv"])
    p1 = scratch / "coverup_disguise.jsonl"
    write_jsonl(p1, out)

    # Cover-up 2: delete the payment, renumber, and re-sign the chain from there
    out = copy.deepcopy(records)
    del out[i]
    for j in range(i, len(out)):
        out[j]["seq"] = j
        _rehash(out[j], out[j - 1]["hash"], run["operator_priv"])
    p2 = scratch / "coverup_delete.jsonl"
    write_jsonl(p2, out)

    for label, path in (("Disguise payment as read_file, re-sign chain", p1), ("Delete payment, renumber, re-sign chain", p2)):
        per_mode = {m: bool(verdict(run, path, m)) for m in MODES}
        lines.append(f"Cover-up: {label}")
        for m in MODES:
            lines.append(f"  {MODE_LABELS[m]:<24} {'DETECTED' if per_mode[m] else 'not detected'}")
        if per_mode["witnessed"]:
            lines.append(f"  reason: {verdict(run, path)[0]}")
        lines.append("")

    # Forged reveal: operator claims the payment went to a real vendor
    forged = {**row, "value": row["value"].replace(ATTACKER, "Initech")}
    lines.append(f"Forged reveal ('paid Initech') verifies: {verify_reveal(run['log'], forged)}")
    if row["seq"] > last_cp:
        lines.append("Note: the payment is inside the unprotected window (after the last checkpoint); "
                     "a cover-up there is expected to evade the witness.")
    return lines


def main(run_dir: Path, trials: int, seed: int) -> None:
    RESULTS.mkdir(exist_ok=True)
    scratch = run_dir / "_validation"
    scratch.mkdir(exist_ok=True)
    run = load_run(run_dir)
    truth = json.loads((run_dir / "ground_truth.json").read_text())
    records = read_jsonl(run["log"])
    receipts = read_jsonl(run["receipts"])

    report = [f"# Real-LLM validation: {truth['model']}", "",
              f"{len(truth['tasks'])} tasks, {len(records)} records "
              f"({sum(1 for r in records if r['event'].get('signal') != 'log')} spans, "
              f"{sum(1 for r in records if r['event'].get('signal') == 'log')} log events), {len(receipts)} witness receipts. "
              f"Content recording: {'on' if truth.get('record_content') else 'off'}; "
              f"risk-triggered checkpoints: {'on' if truth.get('risk_checkpoints') else 'off'}. "
              f"Injection tasks: {truth['injection_tasks']}; payments to the attacker: {truth['attacker_payments']}.", ""]

    report.append("## 1. Untampered log")
    for m in MODES:
        report.append(f"- {MODE_LABELS[m]}: {'intact' if not verdict(run, run['log'], m) else 'PROBLEMS: ' + '; '.join(verdict(run, run['log'], m)[:3])}")

    matched, total, unmatched = completeness(run, truth)
    report += ["", "## 2. Completeness", f"{matched}/{total} side-effecting actions taken by the agent appear in the log with matching (revealed) arguments."]
    report += [f"- missing: {u}" for u in unmatched]

    counts = run_trials(run, list(ATTACKS), MODES, trials, seed, scratch)
    cols = ["plain", *MODES]
    report += ["", f"## 3. Attack suite ({trials} random trials each)", "",
               "| Attack | Attacker | " + " | ".join(MODE_LABELS[c] for c in cols) + " |", "|---|---|" + "---|" * len(cols)]
    for attack, (label, actor, _) in ATTACKS.items():
        cells = ["0/" + str(trials)] + [f"{counts[attack][m]}/{trials}" for m in MODES]
        report.append(f"| {label} | {actor} | " + " | ".join(cells) + " |")

    report += ["", "## 4. Incident replay", "", "```", *incident(run, scratch), "```"]
    text = "\n".join(report) + "\n"
    (RESULTS / "real_validation.md").write_text(text)
    print(text)
    print(f"written to {RESULTS / 'real_validation.md'}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--run", default="runs/real")
    p.add_argument("--trials", type=int, default=30)
    p.add_argument("--seed", type=int, default=0)
    a = p.parse_args()
    main(Path(a.run), a.trials, a.seed)
