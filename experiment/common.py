"""Shared setup: keys, witness, recorder, OTel processor and toy agent for one run."""

import json
from pathlib import Path

from agent.toy_agent import make_tracer, run_agent
from recorder.chain import ChainWriter
from recorder.otel_processor import TamperEvidentSpanProcessor
from recorder.signer import generate_keypair, load_private_key, load_public_key
from witness.witness import Witness


def generate_run(out_dir, n_tasks: int = 30, checkpoint_every: int = 25, seed: int = 0, clean_shutdown: bool = False, checkpoint_on_tools=()) -> dict:
    """Run the toy agent with the full recorder and return paths and keys.

    clean_shutdown=False leaves the records written since the last checkpoint
    unwitnessed, which is the realistic state at any moment between checkpoints
    (and the moment an operator would choose to tamper).
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for name in ("operator", "witness", "outsider"):
        if not (out / name / "private.pem").exists():
            generate_keypair(out / name)

    keys = {
        "operator_priv": load_private_key(out / "operator/private.pem"),
        "operator_pub": load_public_key(out / "operator/public.pem"),
        "witness_priv": load_private_key(out / "witness/private.pem"),
        "witness_pub": load_public_key(out / "witness/public.pem"),
        "outsider_priv": load_private_key(out / "outsider/private.pem"),
    }
    paths = {"log": out / "agent_log.jsonl", "vault": out / "vault.jsonl", "receipts": out / "witness_receipts.jsonl"}
    for p in paths.values():
        p.unlink(missing_ok=True)

    witness = Witness(paths["receipts"], keys["witness_priv"])
    writer = ChainWriter(paths["log"], keys["operator_priv"], vault_path=paths["vault"], witness=witness, checkpoint_every=checkpoint_every)
    processor = TamperEvidentSpanProcessor(writer, checkpoint_on_tools=checkpoint_on_tools)
    provider, tracer = make_tracer(processor)
    run_agent(tracer, n_tasks=n_tasks, seed=seed)
    if clean_shutdown:
        provider.shutdown()
    writer.close()
    witness.close()
    return {**paths, **keys}


def read_jsonl(path) -> list[dict]:
    with Path(path).open() as f:
        return [json.loads(line) for line in f if line.strip()]


def write_jsonl(path, records) -> None:
    with Path(path).open("w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
