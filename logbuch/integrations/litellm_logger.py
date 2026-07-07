"""LiteLLM integration: log every completion as a tamper-evident inference event.

Usage (LiteLLM proxy or SDK):

    import litellm
    from logbuch.integrations.litellm_logger import LogbuchLogger

    litellm.callbacks = [LogbuchLogger("/var/lib/logbuch/prod")]

Only metadata and salted hashes enter the log; prompts/responses are stored
encrypted (per-entry key, crypto-shreddable) when ``store_payload=True``.

Attribute names follow the OpenTelemetry GenAI semantic conventions.
"""

from __future__ import annotations

from ..core import Logbuch

try:
    from litellm.integrations.custom_logger import CustomLogger
except ImportError:  # litellm not installed — allow import for docs/tests
    class CustomLogger:  # type: ignore[no-redef]
        pass


def _text(messages) -> str:
    if isinstance(messages, str):
        return messages
    try:
        return "\n".join(str(m.get("content", "")) for m in messages)
    except Exception:
        return str(messages)


class LogbuchLogger(CustomLogger):
    def __init__(self, log_dir: str, store_payload: bool = False):
        self.lb = Logbuch(log_dir)
        self.store_payload = store_payload

    def _record(self, kwargs, response_obj, start_time, end_time, error: str | None = None):
        usage = getattr(response_obj, "usage", None)
        attrs = {
            "gen_ai.system": kwargs.get("custom_llm_provider") or "unknown",
            "gen_ai.request.model": kwargs.get("model"),
            "gen_ai.usage.input_tokens": getattr(usage, "prompt_tokens", None),
            "gen_ai.usage.output_tokens": getattr(usage, "completion_tokens", None),
            "duration_ms": int((end_time - start_time).total_seconds() * 1000)
            if start_time and end_time else None,
        }
        if error:
            attrs["error"] = error
        attrs = {k: v for k, v in attrs.items() if v is not None}

        out_text = None
        if response_obj is not None:
            try:
                out_text = response_obj.choices[0].message.content
            except Exception:
                out_text = None

        self.lb.append(
            "inference" if not error else "anomaly",
            attrs,
            input_text=_text(kwargs.get("messages", "")) or None,
            output_text=out_text,
            store_payload=self.store_payload,
        )

    def log_success_event(self, kwargs, response_obj, start_time, end_time):
        self._record(kwargs, response_obj, start_time, end_time)

    def log_failure_event(self, kwargs, response_obj, start_time, end_time):
        self._record(kwargs, None, start_time, end_time,
                     error=str(kwargs.get("exception", "unknown error")))
