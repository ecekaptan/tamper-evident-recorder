"""The real-agent pipeline, end to end, against the stand-in LLM server."""

import json

from agent import real_agent
from experiment.common import read_jsonl
from experiment.run_real_validation import completeness, load_run
from tests.fake_llm_server import start
from verify.verifier import verify_log


def test_real_agent_pipeline_records_every_action(tmp_path):
    server = start()
    try:
        truth = real_agent.main("fake", f"http://127.0.0.1:{server.server_address[1]}/v1", 5, tmp_path, 10, 8)
    finally:
        server.shutdown()

    run = load_run(tmp_path)
    for mode in ("hash", "signed", "witnessed"):
        assert verify_log(run["log"], run["operator_pub"], mode, run["receipts"], run["witness_pub"]) == []

    matched, total, unmatched = completeness(run, truth)
    assert total > 0 and matched == total, unmatched
    assert truth["attacker_payments"] == 1

    records = read_jsonl(run["log"])
    chat = [r for r in records if r["event"]["attributes"].get("gen_ai.operation.name") == "chat"]
    assert chat, "chat spans from the official instrumentation should be recorded"
    assert "Offshore" not in run["log"].read_text(), "tool arguments must be committed, not stored"
    assert any("Offshore" in json.dumps(r["value"]) for r in read_jsonl(run["vault"]))


def test_content_recording_chains_prompts_and_explains_the_incident(tmp_path):
    server = start()
    try:
        real_agent.main("fake", f"http://127.0.0.1:{server.server_address[1]}/v1", 5, tmp_path, 10, 8,
                        record_content=True, risk_checkpoints=True)
    finally:
        server.shutdown()

    run = load_run(tmp_path)
    assert verify_log(run["log"], run["operator_pub"], "witnessed", run["receipts"], run["witness_pub"]) == []
    records = read_jsonl(run["log"])
    assert any(r["event"].get("signal") == "log" for r in records)
    assert "SYSTEM NOTICE" not in run["log"].read_text(), "prompt content must be committed, not stored"
    assert any(v["key"] == "body" and "SYSTEM NOTICE" in json.dumps(v["value"]) for v in read_jsonl(run["vault"]))

    payment_seqs = [r["seq"] for r in records if r["event"]["attributes"].get("gen_ai.tool.name") == "transfer_funds"]
    witnessed = {r["checkpoint"]["seq"] for r in read_jsonl(run["receipts"])}
    assert payment_seqs and set(payment_seqs) <= witnessed
