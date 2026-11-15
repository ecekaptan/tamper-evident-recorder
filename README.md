# Tamper-evident action recorder for AI agents

A drop-in OpenTelemetry `SpanProcessor` that turns an agent's GenAI traces into a
signed, hash-chained, privacy-preserving log, with external witness checkpoints,
so an auditor can detect after-the-fact edits, deletions, reordering, truncation
and rewrites of what the agent did.

Built during the Apart Research AI x Epistemics Research Sprint (Track 2: Trust
Infrastructure), November 13-15, 2026. No code was written before the sprint.

## The problem

When an AI agent takes a consequential action, the only record is usually the
operator's own logs, and the operator can edit them. This project asks: what is
the minimal layer on top of OpenTelemetry's GenAI conventions that makes those
records tamper-evident to an outside auditor, which attacks does it catch and
miss, and what does it cost?

## Design

```
agent ─► OTel span ─► TamperEvidentSpanProcessor ─► commit sensitive attributes ─► vault (operator-held)
                                │
                                ▼
                     canonical JSON (RFC 8785) ─► hash chain ─► Ed25519 signature ─► append to JSONL log
                                                                         │
                                                       every N records   ▼
                                                                witness countersigns head hash
                                                                         │
auditor: verify.cli check  ◄── log + operator public key + witness receipts + witness public key
```

| Layer | What it does | Catches |
|---|---|---|
| Hash chain | Each record includes the previous record's hash; sequence numbers | edits, deletions, reordering, insertions |
| Signatures | Ed25519 signature on each record's hash | records forged by anyone without the operator key |
| Witness checkpoints | An independent witness countersigns the head hash every N records | truncation and whole-chain rewrites by the key holder |
| Content commitments | `SHA-256(salt ‖ value)` replaces prompts, completions, tool arguments and results | (privacy) the auditor verifies integrity without seeing content; one value can be revealed later |

Sensitive attributes committed by default (names from `opentelemetry-semantic-conventions`):
`gen_ai.input.messages`, `gen_ai.output.messages`, `gen_ai.tool.call.arguments`, `gen_ai.tool.call.result`.

### Threat model

- **Adversary:** the operator, who controls log storage and holds the operator signing key. A weaker **outsider** can write to storage but has no key.
- **Goal:** detection, not prevention.
- **Trusted:** the witness and its storage; the auditor's copy of both public keys.
- **Out of scope:** false events logged at write time, a compromised witness, actions the agent takes without passing through the recorder, and theft of the witness key.

## Results

### Detection (results/detection_table.md)

50 random trials per attack on a 210-record log, checkpoint every 25 records.

| Attack | Attacker | Plain logs | Hash chain | + Signatures | + Witness checkpoints |
|---|---|---|---|---|---|
| Edit a field | operator | ✗ 0/50 | ✓ 50/50 | ✓ 50/50 | ✓ 50/50 |
| Edit and re-sign one record | operator | ✗ 0/50 | ✓ 50/50 | ✓ 50/50 | ✓ 50/50 |
| Delete a middle record | operator | ✗ 0/50 | ✓ 50/50 | ✓ 50/50 | ✓ 50/50 |
| Swap two adjacent records | operator | ✗ 0/50 | ✓ 50/50 | ✓ 50/50 | ✓ 50/50 |
| Insert a signed fake record | operator | ✗ 0/50 | ✓ 50/50 | ✓ 50/50 | ✓ 50/50 |
| Append a fake record (no operator key) | outsider | ✗ 0/50 | ✗ 0/50 | ✓ 50/50 | ✓ 50/50 |
| Truncate the tail | operator | ✗ 0/50 | ✗ 0/50 | ✗ 0/50 | ✓ 50/50 |
| Rewrite and re-sign the whole chain | operator | ✗ 0/50 | ✗ 0/50 | ✗ 0/50 | ◐ 49/50 |
| Log a false event at write time | operator | ✗ 0/50 | ✗ 0/50 | ✗ 0/50 | ✗ 0/50 |

The one missed rewrite (and the 9% of missed truncations in the sweep) are
tampering confined to records written after the most recent checkpoint: the
**unprotected window**, at most `checkpoint_every − 1` records.

### Checkpoint interval trade-off (results/checkpoint_sweep.md, results/checkpoint_sweep.png)

More frequent checkpoints shrink the unprotected window at the cost of more
witness calls. Note the observed window in this run depends on where the
210-record run stopped relative to a checkpoint; the worst-case column is the
general bound.

| Checkpoint every | Witness receipts | Worst-case unprotected records | Unprotected this run | Truncation detected | Rewrite detected |
|---|---|---|---|---|---|
| 1 | 210 | 0 | 0 | 100% | 100% |
| 5 | 42 | 4 | 0 | 100% | 100% |
| 10 | 21 | 9 | 0 | 100% | 100% |
| 25 | 8 | 24 | 10 | 91% | 98% |
| 50 | 4 | 49 | 10 | 91% | 98% |
| 100 | 2 | 99 | 10 | 91% | 98% |

### Overhead (results/overhead.md, results/overhead.png)

2,100 spans per run, 15 runs per configuration, wall time through the OTel SDK.

| Configuration | µs per span (median) | Added vs plain | Total bytes / record |
|---|---|---|---|
| plain JSONL logger | 29.9 | — | 509 (1.00×) |
| + hash chain | 64.7 | +34.8 µs | 787 (1.54×) |
| + signatures | 94.8 | +65.0 µs | 926 (1.82×) |
| + content commitments | 104.8 | +75.0 µs | 1229 (2.41×) |
| + witness checkpoints | 111.0 | +81.1 µs | 1248 (2.45×) |

About 81 µs per span with every layer on. For scale, a single LLM call
typically takes hundreds of milliseconds. The witness here is in-process; a
networked witness adds one round trip per checkpoint, amortised over the interval.

### Risk-triggered checkpoints (results/risk_checkpoints.md)

The unprotected window is most dangerous right after a harmful action, when the
operator has the strongest reason to tamper. `TamperEvidentSpanProcessor(writer,
checkpoint_on_tools=("transfer_funds",))` checkpoints immediately after every
high-risk tool call. Scenario: the operator disguises a payment and re-signs the
chain k records after it happened. 5 runs of 210 records, 129 payments, periodic
checkpoint every 25.

| Cover-up delay (records after payment) | Periodic only | Periodic + checkpoint after each payment |
|---|---|---|
| 0 | 9/129 (7%) | 129/129 (100%) |
| 1 | 15/129 (12%) | 129/129 (100%) |
| 2 | 21/127 (17%) | 127/127 (100%) |
| 5 | 33/125 (26%) | 125/125 (100%) |
| 10 | 53/123 (43%) | 123/123 (100%) |
| 20 | 96/113 (85%) | 113/113 (100%) |
| Witness receipts (total) | 40 | 160 |

The cost is one witness call per high-risk action. Other record types in the tail
keep the periodic window.

### Recording what the model read (logs signal)

`TamperEvidentLogProcessor` chains OpenTelemetry log events into the same log as
the spans. The official OpenAI instrumentation emits prompts and completions as
log events, so this puts what the model read and said under the same guarantees
as what it did. Bodies are committed, never stored. In the incident replay, the
auditor can then reveal the poisoned message that preceded the payment (same
trace ID) and so establish the cause as well as the action.

## Run it

```bash
pip install -r requirements.txt

pytest                                  # 19 tests, including the expected detection table
python -m experiment.run_detection      # detection matrix + checkpoint sweep  (~1 min)
python -m bench.overhead                # overhead benchmark                     (~15 s)
python -m experiment.run_risk_checkpoints  # risk-triggered checkpoint experiment (~40 s)
python -m bench.plot                    # charts into results/
```

### Real-LLM validation (local model via Ollama)

`agent/real_agent.py` is a real tool-calling agent: the OpenAI Python SDK pointed at
Ollama's OpenAI-compatible endpoint, chat spans from the official
`opentelemetry-instrumentation-openai-v2`, tool spans from the agent loop, and simulated
tools (no real money or email moves). One invoice (`inv_103.txt`) carries a hidden
prompt injection asking the agent to pay "Offshore Holdings Ltd" 9,800 USD.

```bash
ollama pull qwen2.5:7b                      # any tool-capable model
python -m agent.real_agent --model qwen2.5:7b --tasks 15 --out runs/qwen7b
python -m experiment.run_real_validation --run runs/qwen7b

# with prompt/completion recording and a checkpoint after every payment
python -m agent.real_agent --model qwen2.5:7b --tasks 15 --out runs/qwen7b_full \
    --record-content --risk-checkpoints
python -m experiment.run_real_validation --run runs/qwen7b_full
```

The validation checks the untampered log, completeness (every real action appears in
the log, matched against ground truth kept outside the recorder), the full attack
suite, and an incident replay: find the attacker payment, prove it with a reveal,
attempt two cover-ups (disguise and re-sign; delete, renumber and re-sign) and a
forged reveal. Output: `results/real_validation.md`.

To test the pipeline without a model, run the stand-in server:
`python -m tests.fake_llm_server 8765` and pass `--base-url http://127.0.0.1:8765/v1 --model fake`.

Verify a log as an auditor:

```bash
python -m verify.cli check --log agent_log.jsonl --pubkey operator/public.pem \
    --witness-receipts witness_receipts.jsonl --witness-pubkey witness/public.pem

python -m verify.cli reveal --log agent_log.jsonl --vault vault.jsonl \
    --seq 12 --key gen_ai.tool.call.arguments
```

Use it with your own agent:

```python
from opentelemetry.sdk.trace import TracerProvider
from recorder.chain import ChainWriter
from recorder.otel_processor import TamperEvidentSpanProcessor
from recorder.signer import load_private_key
from witness.witness import Witness

witness = Witness("witness_receipts.jsonl", load_private_key("witness/private.pem"))
writer = ChainWriter("agent_log.jsonl", load_private_key("operator/private.pem"),
                     vault_path="vault.jsonl", witness=witness, checkpoint_every=25)
provider = TracerProvider()
provider.add_span_processor(TamperEvidentSpanProcessor(writer))
```

## Layout

```
recorder/   signer.py (Ed25519), chain.py (hash chain, commitments, checkpoints), otel_processor.py (span + log processors)
witness/    witness.py (independent countersigner, receipt verification)
verify/     verifier.py (hash / signed / witnessed modes, reveal check), cli.py
agent/      toy_agent.py (scripted agent), real_agent.py (real LLM via Ollama, with prompt injection)
attacks/    attacks.py (9 attacks, random targets)
experiment/ common.py, run_detection.py, run_risk_checkpoints.py, run_real_validation.py
bench/      overhead.py, plot.py
tests/      test_recorder.py, test_real_agent.py, fake_llm_server.py (stand-in LLM)
results/    tables (.md, .csv, .json) and charts (.png)
```

## Limitations

- **Write-time lies are undetectable.** The recorder proves the log was not changed after writing, not that it was true when written.
- **Unprotected window.** Up to `checkpoint_every − 1` of the newest records can be truncated or rewritten undetected.
- **Key protection.** The operator key sits in a PEM file. Production use would keep it in an HSM or cloud KMS, ideally in a recorder process separate from the agent. Key theft is out of scope.
- **Witness is simulated** as a separate object with its own key and storage. A real deployment would use an independent party, a Certificate Transparency-style log, or RFC 3161 timestamps.
- **Coverage.** Actions the agent takes outside instrumented code paths are not recorded.
- **Toy agent for the main experiment.** Spans are scripted for reproducibility; the real-LLM run (above) validates the recorder on spans from the official instrumentation, which differ in shape (e.g. `gen_ai.system` rather than `gen_ai.provider.name`, extra `gen_ai.response.*` fields).
- **Log volume with content recording.** The instrumentation re-emits the whole conversation history as log events on every model call, so records grow roughly quadratically with conversation length (127 log events against 43 spans in a 5-task run). Deduplicating by content hash is future work.
- **Overhead** was measured on one machine with an in-process witness; canonical JSON (pure-Python RFC 8785) is the largest single cost.

## Implementation note

RFC 8785 canonical JSON only permits integers within ±2⁵³, and OTel's
nanosecond timestamps exceed that. Timestamps are therefore stored as strings.
Any canonicalisation-based integrity scheme for OTel data needs the same care.
