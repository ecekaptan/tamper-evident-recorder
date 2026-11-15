"""OpenTelemetry SpanProcessor that writes finished spans into the tamper-evident chain.

Drop-in: add it to a TracerProvider and every span an agent framework already
emits (including GenAI spans following the OTel semantic conventions) is
chained, signed and optionally witnessed. The agent code does not change.

Attributes that carry content (prompts, completions, tool arguments and
results) are committed rather than stored, so the log itself is safe to hand
to an auditor.
"""

import json

from opentelemetry.sdk._logs import LogRecordProcessor
from opentelemetry.sdk.trace import ReadableSpan, SpanProcessor

from recorder.chain import ChainWriter

# Content-bearing GenAI attributes (names from opentelemetry-semantic-conventions)
DEFAULT_SENSITIVE_ATTRIBUTES = frozenset(
    {
        "gen_ai.input.messages",
        "gen_ai.output.messages",
        "gen_ai.tool.call.arguments",
        "gen_ai.tool.call.result",
    }
)


def _attr_value(value):
    """OTel attribute values may be tuples; make them JSON-friendly."""
    return list(value) if isinstance(value, tuple) else value


class TamperEvidentSpanProcessor(SpanProcessor):
    def __init__(self, writer: ChainWriter, sensitive_attributes=DEFAULT_SENSITIVE_ATTRIBUTES, checkpoint_on_tools=()):
        """checkpoint_on_tools: tool names (gen_ai.tool.name) that are high-risk. A span for one
        of these triggers an immediate witness checkpoint, so the action is never left in the
        unprotected window between periodic checkpoints."""
        self.writer = writer
        self.sensitive_attributes = frozenset(sensitive_attributes)
        self.checkpoint_on_tools = frozenset(checkpoint_on_tools)

    def on_start(self, span, parent_context=None) -> None:
        pass

    def on_end(self, span: ReadableSpan) -> None:
        ctx = span.get_span_context()
        attributes, sensitive = {}, {}
        for key, value in (span.attributes or {}).items():
            target = sensitive if key in self.sensitive_attributes else attributes
            target[key] = _attr_value(value)

        event = {
            "span_name": span.name,
            "trace_id": format(ctx.trace_id, "032x"),
            "span_id": format(ctx.span_id, "016x"),
            "parent_span_id": format(span.parent.span_id, "016x") if span.parent else None,
            # Strings, not ints: nanosecond timestamps exceed the 2^53 integer range
            # that RFC 8785 canonical JSON allows.
            "start_time_unix_nano": str(span.start_time),
            "end_time_unix_nano": str(span.end_time),
            "status": span.status.status_code.name,
            "attributes": attributes,
        }
        high_risk = attributes.get("gen_ai.tool.name") in self.checkpoint_on_tools
        self.writer.append(event, sensitive=sensitive or None, checkpoint=high_risk)

    def shutdown(self) -> None:
        self.writer.checkpoint_now()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True


class TamperEvidentLogProcessor(LogRecordProcessor):
    """Writes OpenTelemetry log events into the same chain as the spans.

    Some instrumentations (e.g. opentelemetry-instrumentation-openai-v2) emit prompt and
    completion content as log events rather than span attributes. Chaining them puts what
    the model read and said under the same integrity guarantees as what it did. The body
    is committed, never stored; trace_id and span_id tie each event to its chat span.
    """

    def __init__(self, writer: ChainWriter):
        self.writer = writer

    def on_emit(self, log_record) -> None:
        lr = log_record.log_record
        event = {
            "signal": "log",
            "event_name": lr.event_name or "",
            "trace_id": format(lr.trace_id, "032x") if lr.trace_id else None,
            "span_id": format(lr.span_id, "016x") if lr.span_id else None,
            "time_unix_nano": str(lr.timestamp or lr.observed_timestamp or ""),
            "attributes": {k: _attr_value(v) for k, v in (lr.attributes or {}).items()},
        }
        body = lr.body
        if body is not None:
            body = json.loads(json.dumps(body, default=str))  # plain JSON types only
        self.writer.append(event, sensitive={"body": body} if body is not None else None)

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True
