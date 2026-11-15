"""Tests: the expected detection table, privacy reveals, witness integrity and resume."""

import json
import random

import pytest

from attacks.attacks import ATTACKS
from experiment.common import generate_run, read_jsonl, write_jsonl
from recorder.chain import ChainWriter
from verify.verifier import verify_log, verify_reveal

# Expected detection per attack: (hash, signed, witnessed).
# The run below checkpoints every 5 of 35 records, so no unprotected window remains.
EXPECTED = {
    "edit_field": (True, True, True),
    "edit_and_resign_one": (True, True, True),
    "delete_middle": (True, True, True),
    "reorder": (True, True, True),
    "insert_signed": (True, True, True),
    "append_outsider": (False, True, True),
    "truncate_tail": (False, False, True),
    "full_rewrite": (False, False, True),
    "write_time_lie": (False, False, False),
}
MODES = ("hash", "signed", "witnessed")


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    return generate_run(tmp_path_factory.mktemp("run"), n_tasks=5, checkpoint_every=5, seed=1)


def _verify(run, path, mode):
    return verify_log(path, run["operator_pub"], mode, run["receipts"], run["witness_pub"])


def test_clean_log_passes_every_mode(run):
    for mode in MODES:
        assert _verify(run, run["log"], mode) == []


def test_no_unprotected_window_in_fixture(run):
    last_cp = read_jsonl(run["receipts"])[-1]["checkpoint"]["seq"]
    assert last_cp == len(read_jsonl(run["log"])) - 1


@pytest.mark.parametrize("attack", list(EXPECTED))
def test_attack_detection_matches_expected(run, tmp_path, attack):
    records = read_jsonl(run["log"])
    fn = ATTACKS[attack][2]
    for trial in range(10):
        ctx = {"records": records, "rng": random.Random(trial), **run}
        path = tmp_path / f"{attack}_{trial}.jsonl"
        write_jsonl(path, fn(records, ctx))
        for mode, expected in zip(MODES, EXPECTED[attack]):
            detected = bool(_verify(run, path, mode))
            assert detected == expected, f"{attack} trial {trial}: {mode} mode detected={detected}, expected {expected}"


def test_log_contains_no_sensitive_content(run):
    text = run["log"].read_text()
    assert "gen_ai.tool.call.arguments\": \"{" not in text
    assert "amount" not in text
    assert "commitments" in text


def test_reveal_accepts_true_value_and_rejects_forgery(run):
    rows = read_jsonl(run["vault"])
    row = next(r for r in rows if r["key"] == "gen_ai.tool.call.arguments")
    assert verify_reveal(run["log"], row)
    forged = {**row, "value": json.dumps({"to": "Nobody", "amount": 1})}
    assert not verify_reveal(run["log"], forged)
    wrong_salt = {**row, "salt": "00" * 16}
    assert not verify_reveal(run["log"], wrong_salt)


def test_forged_witness_receipt_is_rejected(run, tmp_path):
    receipts = read_jsonl(run["receipts"])
    receipts[0]["checkpoint"]["head_hash"] = "ab" * 32
    forged = tmp_path / "receipts.jsonl"
    write_jsonl(forged, receipts)
    problems = verify_log(run["log"], run["operator_pub"], "witnessed", forged, run["witness_pub"])
    assert any("invalid witness signature" in p for p in problems)


def test_writer_resumes_existing_chain(run, tmp_path):
    log = tmp_path / "log.jsonl"
    w = ChainWriter(log, run["operator_priv"])
    w.append({"step": 1})
    w.close()
    w = ChainWriter(log, run["operator_priv"])
    w.append({"step": 2})
    w.close()
    assert [r["seq"] for r in read_jsonl(log)] == [0, 1]
    assert verify_log(log, run["operator_pub"], "signed") == []


def test_nanosecond_timestamps_are_strings(run):
    rec = read_jsonl(run["log"])[0]
    assert isinstance(rec["event"]["start_time_unix_nano"], str)


def test_risk_triggered_checkpoint_covers_every_payment(tmp_path):
    run = generate_run(tmp_path, n_tasks=10, checkpoint_every=1000, seed=3, checkpoint_on_tools=("transfer_funds",))
    payments = [r["seq"] for r in read_jsonl(run["log"]) if r["event"]["attributes"].get("gen_ai.tool.name") == "transfer_funds"]
    witnessed = [r["checkpoint"]["seq"] for r in read_jsonl(run["receipts"])]
    assert payments and witnessed == payments
