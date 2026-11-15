"""Overhead benchmark: cost per span and storage per record for each configuration.

Configurations (each adds one layer):
    plain       spans written as plain JSONL (baseline logger)
    hash        + canonical JSON and hash chain
    signed      + Ed25519 signature per record
    committed   + salted commitments for content attributes (vault file)
    witnessed   + witness checkpoint every 25 records (in-process witness)

Each configuration runs the toy agent end to end through the OTel SDK and
reports wall time per span, so the numbers include OTel's own cost.
The witness here is in-process; a real witness adds a network round trip per
checkpoint, which is amortised over the checkpoint interval.
"""

import argparse
import json
import statistics
import tempfile
import time
from pathlib import Path

from opentelemetry.sdk.trace import SpanProcessor

from agent.toy_agent import SPANS_PER_TASK, make_tracer, run_agent
from recorder.chain import ChainWriter
from recorder.otel_processor import DEFAULT_SENSITIVE_ATTRIBUTES, TamperEvidentSpanProcessor
from recorder.signer import generate_keypair, load_private_key
from witness.witness import Witness

RESULTS = Path(__file__).resolve().parent.parent / "results"
CONFIGS = ("plain", "hash", "signed", "committed", "witnessed")


class PlainJSONLProcessor(SpanProcessor):
    """Baseline: what an ordinary file logger would do."""

    def __init__(self, path):
        self._f = open(path, "a")

    def on_start(self, span, parent_context=None):
        pass

    def on_end(self, span):
        ctx = span.get_span_context()
        self._f.write(json.dumps({
            "span_name": span.name,
            "trace_id": format(ctx.trace_id, "032x"),
            "span_id": format(ctx.span_id, "016x"),
            "start_time_unix_nano": str(span.start_time),
            "end_time_unix_nano": str(span.end_time),
            "attributes": {k: v for k, v in (span.attributes or {}).items()},
        }) + "\n")
        self._f.flush()

    def shutdown(self):
        self._f.close()

    def force_flush(self, timeout_millis=30000):
        return True


def build(config: str, d: Path, keys: Path):
    """Return (processor, files to measure, closer)."""
    log = d / "log.jsonl"
    if config == "plain":
        p = PlainJSONLProcessor(log)
        return p, [log], p.shutdown

    priv = load_private_key(keys / "operator/private.pem") if config != "hash" else None
    vault = d / "vault.jsonl" if config in ("committed", "witnessed") else None
    witness = Witness(d / "receipts.jsonl", load_private_key(keys / "witness/private.pem")) if config == "witnessed" else None
    writer = ChainWriter(log, priv, vault_path=vault, witness=witness, checkpoint_every=25 if witness else 0)
    sensitive = DEFAULT_SENSITIVE_ATTRIBUTES if vault else frozenset()
    proc = TamperEvidentSpanProcessor(writer, sensitive_attributes=sensitive)
    files = [f for f in (log, vault, d / "receipts.jsonl" if witness else None) if f]

    def close():
        writer.close()
        if witness:
            witness.close()

    return proc, files, close


def run_once(config: str, n_tasks: int, keys: Path) -> tuple[float, int, int]:
    d = Path(tempfile.mkdtemp())
    proc, files, close = build(config, d, keys)
    _, tracer = make_tracer(proc)
    t0 = time.perf_counter()
    run_agent(tracer, n_tasks=n_tasks, seed=0)
    elapsed = time.perf_counter() - t0
    close()
    n_spans = n_tasks * SPANS_PER_TASK
    log_bytes = files[0].stat().st_size
    total_bytes = sum(f.stat().st_size for f in files if f.exists())
    return elapsed / n_spans * 1e6, log_bytes / n_spans, total_bytes / n_spans


def main(n_tasks: int, repeats: int) -> None:
    RESULTS.mkdir(exist_ok=True)
    keys = Path(tempfile.mkdtemp())
    generate_keypair(keys / "operator")
    generate_keypair(keys / "witness")

    for config in CONFIGS:  # warm-up
        run_once(config, 20, keys)

    rows = []
    for config in CONFIGS:
        times, log_b, total_b = [], 0, 0
        for _ in range(repeats):
            us, log_b, total_b = run_once(config, n_tasks, keys)
            times.append(us)
        rows.append({
            "config": config,
            "us_per_span_median": statistics.median(times),
            "us_per_span_p10": sorted(times)[max(0, len(times) // 10)],
            "us_per_span_p90": sorted(times)[min(len(times) - 1, len(times) * 9 // 10)],
            "log_bytes_per_record": log_b,
            "total_bytes_per_record": total_b,
            "spans_per_run": n_tasks * SPANS_PER_TASK,
            "repeats": repeats,
        })

    base = rows[0]["us_per_span_median"]
    base_b = rows[0]["total_bytes_per_record"]
    for r in rows:
        r["added_us_vs_plain"] = r["us_per_span_median"] - base
        r["storage_ratio_vs_plain"] = r["total_bytes_per_record"] / base_b

    (RESULTS / "overhead.json").write_text(json.dumps(rows, indent=2))
    lines = ["| Configuration | µs per span (median) | Added vs plain | Log bytes / record | Total bytes / record (incl. vault, receipts) |",
             "|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['config']} | {r['us_per_span_median']:.1f} | +{r['added_us_vs_plain']:.1f} µs | "
                     f"{r['log_bytes_per_record']:.0f} | {r['total_bytes_per_record']:.0f} ({r['storage_ratio_vs_plain']:.2f}×) |")
    md = f"{rows[0]['spans_per_run']} spans per run, {repeats} runs per configuration, wall time through the OTel SDK.\n\n" + "\n".join(lines) + "\n"
    (RESULTS / "overhead.md").write_text(md)
    print(md)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--tasks", type=int, default=300, help="agent tasks per run (7 spans each)")
    p.add_argument("--repeats", type=int, default=15)
    a = p.parse_args()
    main(a.tasks, a.repeats)
