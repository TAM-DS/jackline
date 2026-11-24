"""SDK-free adapters for model tool-use loops.

Jackline doesn't replace your agent framework or model SDK. Drop these in at
the point where your loop would execute a tool: the model proposes, Jackline
decides, and the model gets back either the result or an explicit denial it
can re-plan around. Works with SDK response objects or plain dicts.
"""

from __future__ import annotations

import json
from typing import Any

from .runtime import Runtime, Session


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


# ---------------------------------------------------------------- Anthropic
def anthropic_tools(runtime: Runtime, tool_schemas: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter the `tools=[...]` list so the model never sees a tool policy can't ever run."""
    return [t for t in tool_schemas if runtime.policy.can_ever_run(_get(t, "name"))]


def anthropic_tool_results(session: Session, response: Any) -> list[dict[str, Any]]:
    """Messages API response → list of `tool_result` blocks for the next user turn.
    Also records token usage against the run's budget."""
    usage = _get(response, "usage")
    if usage is not None:
        session.record_model(str(_get(response, "model", "unknown")),
                             int(_get(usage, "input_tokens", 0) or 0), int(_get(usage, "output_tokens", 0) or 0))
    out = []
    for block in _get(response, "content", []) or []:
        if _get(block, "type") != "tool_use":
            continue
        res = session.call(_get(block, "name"), dict(_get(block, "input", {}) or {}), _get(block, "id"))
        out.append({"type": "tool_result", "tool_use_id": _get(block, "id"),
                    "content": res.message(), "is_error": not res.ok})
    return out


# ------------------------------------------------------------------- OpenAI
def openai_tools(runtime: Runtime, tool_schemas: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def name(t: Any) -> str:
        fn = _get(t, "function")
        return _get(fn, "name") if fn is not None else _get(t, "name")
    return [t for t in tool_schemas if runtime.policy.can_ever_run(name(t))]


def openai_tool_messages(session: Session, response: Any) -> list[dict[str, Any]]:
    """Chat Completions response → list of `{"role": "tool", ...}` messages."""
    usage = _get(response, "usage")
    if usage is not None:
        session.record_model(str(_get(response, "model", "unknown")),
                             int(_get(usage, "prompt_tokens", 0) or 0), int(_get(usage, "completion_tokens", 0) or 0))
    choices = _get(response, "choices", []) or []
    message = _get(choices[0], "message") if choices else None
    out = []
    for tc in (_get(message, "tool_calls", []) or []) if message is not None else []:
        fn = _get(tc, "function")
        raw = _get(fn, "arguments", "{}") or "{}"
        try:
            args = json.loads(raw) if isinstance(raw, str) else dict(raw)
        except json.JSONDecodeError:
            args = {"_unparseable_arguments": raw}
        res = session.call(_get(fn, "name"), args, _get(tc, "id"))
        out.append({"role": "tool", "tool_call_id": _get(tc, "id"), "content": res.message()})
    return out
