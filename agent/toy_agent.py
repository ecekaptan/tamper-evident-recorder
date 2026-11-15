"""A scripted 'finance assistant' agent that emits OpenTelemetry GenAI spans.

Scripted (no real LLM calls) so runs are reproducible, free and fast, but the
spans carry the same gen_ai.* attributes a real instrumented agent would emit.

Per task: one invoke_agent span containing 3 steps, each a chat span (the model
deciding) followed by an execute_tool span (the action). 7 spans per task.
"""

import json
import random

from opentelemetry.sdk.trace import TracerProvider

TOOLS = {
    "read_file": lambda r: {"path": f"invoices/inv_{r.randint(100, 999)}.pdf"},
    "search_web": lambda r: {"query": r.choice(["supplier rating ACME", "EUR USD rate", "late payment policy"])},
    "send_email": lambda r: {"to": r.choice(["finance@example.com", "ceo@example.com", "vendor@acme.example"]), "subject": "Invoice update"},
    "transfer_funds": lambda r: {"to": r.choice(["ACME Ltd", "Globex", "Initech"]), "amount": r.choice([500, 1200, 5000, 25000]), "currency": "USD"},
}
MODEL = "toy-model-1"
STEPS_PER_TASK = 3
SPANS_PER_TASK = 1 + 2 * STEPS_PER_TASK


def make_tracer(span_processor):
    provider = TracerProvider(shutdown_on_exit=False)
    provider.add_span_processor(span_processor)
    return provider, provider.get_tracer("toy-finance-agent")


def run_agent(tracer, n_tasks: int, seed: int = 0) -> None:
    rng = random.Random(seed)
    for task_no in range(n_tasks):
        with tracer.start_as_current_span("invoke_agent finance-assistant") as task_span:
            task_span.set_attribute("gen_ai.operation.name", "invoke_agent")
            task_span.set_attribute("gen_ai.agent.name", "finance-assistant")

            for step in range(STEPS_PER_TASK):
                tool = rng.choice(list(TOOLS))
                args = TOOLS[tool](rng)
                call_id = f"call_{task_no:03d}_{step}"

                with tracer.start_as_current_span(f"chat {MODEL}") as chat:
                    chat.set_attribute("gen_ai.operation.name", "chat")
                    chat.set_attribute("gen_ai.provider.name", "toy-provider")
                    chat.set_attribute("gen_ai.request.model", MODEL)
                    chat.set_attribute("gen_ai.usage.input_tokens", rng.randint(200, 1500))
                    chat.set_attribute("gen_ai.usage.output_tokens", rng.randint(20, 300))
                    chat.set_attribute("gen_ai.input.messages", json.dumps([{"role": "user", "content": f"Process task {task_no}"}]))
                    chat.set_attribute("gen_ai.output.messages", json.dumps([{"role": "assistant", "tool_call": {"name": tool, "id": call_id}}]))

                with tracer.start_as_current_span(f"execute_tool {tool}") as tool_span:
                    tool_span.set_attribute("gen_ai.operation.name", "execute_tool")
                    tool_span.set_attribute("gen_ai.tool.name", tool)
                    tool_span.set_attribute("gen_ai.tool.call.id", call_id)
                    tool_span.set_attribute("gen_ai.tool.call.arguments", json.dumps(args))
                    tool_span.set_attribute("gen_ai.tool.call.result", json.dumps({"ok": True}))
