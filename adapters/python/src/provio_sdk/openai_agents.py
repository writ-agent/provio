"""OpenAI Agents SDK integration (package ``openai-agents``, import ``agents``).

Integration point: the ``FunctionTool.on_invoke_tool`` invoker, wrapped.

Why this one (checked against ``agents`` 0.22 source):

* ``RunHooks.on_tool_start`` / ``AgentHooks.on_tool_start`` are observers:
  their return value is ignored, and raising aborts the whole run instead of
  refusing one call. They cannot *prevent* a single tool call.
* Tool input guardrails (``ToolGuardrailFunctionOutput.reject_content``) can
  prevent execution, but a redact verdict also needs the tool's output, which
  only an output guardrail sees; the decision ``ref`` would have to be carried
  between two separate callbacks, and a user-supplied guardrail list on the
  same tool changes ordering.
* ``on_invoke_tool`` is what ``Runner`` awaits to execute the tool
  (``_invoke_function_tool_with_metadata``). Wrapping it gives one place that
  decides before the tool body runs, runs it, records ``complete`` and
  substitutes the redacted output. The SDK's own input guardrails and
  approval flow run before it, output guardrails after it (they see the
  redacted text).

A blocked call returns the refusal text as the tool result, so the model sees
provio's reason and the run continues. Tools that are not ``FunctionTool``
(hosted tools that run on OpenAI's side, MCP servers attached to the agent)
cannot be wrapped here; :func:`guard_agent` refuses them unless
``strict=False``.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Callable

from agents import Agent, FunctionTool
from agents.tool_context import ToolContext

from .errors import ProvioError
from .guard import Provio, refusal_text, to_text
from .types import Caller

try:  # pragma: no cover
    from importlib.metadata import version as _pkg_version

    _SDK_VERSION: str | None = _pkg_version("openai-agents")
except Exception:  # pragma: no cover
    _SDK_VERSION = None

_SYNC_MARKER = "__agents_sync_function_tool__"
WITHHELD = "Tool output withheld by provio"

SessionResolver = Callable[[ToolContext[Any]], "str | None"]


def _default_session(ctx: Any) -> str | None:
    rc = getattr(ctx, "run_config", None)
    group = getattr(rc, "group_id", None)
    if group:
        return str(group)
    user_ctx = getattr(ctx, "context", None)
    if isinstance(user_ctx, dict):
        v = user_ctx.get("session_id")
    else:
        v = getattr(user_ctx, "session_id", None)
    return str(v) if v else None


class _Gate:
    def __init__(self, provio: Provio, session_id: str | SessionResolver | None) -> None:
        self.provio = provio
        self.session_id = session_id

    def caller(self) -> Caller:
        c = self.provio.caller
        if c.agent == "provio-sdk":
            return Caller(agent="openai-agents", agent_version=_SDK_VERSION, user=c.user, non_human_id=c.non_human_id)
        return c

    def session(self, ctx: Any) -> str:
        if callable(self.session_id):
            s = self.session_id(ctx)
        else:
            s = self.session_id or _default_session(ctx)
        return s or self.provio.session_id


def guard_function_tool(
    tool: FunctionTool,
    provio: Provio,
    *,
    session_id: str | SessionResolver | None = None,
) -> FunctionTool:
    """Return a copy of ``tool`` whose invocations are gated by provio.

    Session id: ``session_id`` (string or ``ctx -> str``), else
    ``RunConfig.group_id``, else ``context.session_id``, else ``provio.session_id``.
    """
    if getattr(tool.on_invoke_tool, "__provio_guarded__", False):
        return tool
    gate = _Gate(provio, session_id)
    guarded = copy.copy(tool)
    original = guarded.on_invoke_tool
    name = tool.name

    async def on_invoke_tool(ctx: ToolContext[Any], arguments: str) -> Any:
        try:
            parsed = json.loads(arguments) if arguments else {}
        except ValueError:
            parsed = None
        args = parsed if isinstance(parsed, dict) else {"_raw_arguments": arguments}
        call = provio.make_call(
            getattr(ctx, "tool_name", None) or name,
            args,
            session_id=gate.session(ctx),
            call_id=getattr(ctx, "tool_call_id", None) or None,
            caller=gate.caller(),
        )
        try:
            d = await provio.aauthorize(call)
        except ProvioError as e:
            return refusal_text(e)
        try:
            result = await original(ctx, arguments)
        except BaseException as e:
            await provio._arecord_failure(d, e)
            raise
        try:
            redacted = await provio.arecord(d, ok=True, output=to_text(result))
        except ProvioError as e:
            return f"{WITHHELD}: {e}"
        return redacted if d.is_redact else result

    on_invoke_tool.__provio_guarded__ = True  # type: ignore[attr-defined]
    if getattr(original, _SYNC_MARKER, False):
        setattr(on_invoke_tool, _SYNC_MARKER, True)
    guarded.on_invoke_tool = on_invoke_tool
    return guarded


def guard_tools(tools: list[Any], provio: Provio, *, session_id: str | SessionResolver | None = None,
                strict: bool = True) -> list[Any]:
    out = []
    for t in tools:
        if isinstance(t, FunctionTool):
            out.append(guard_function_tool(t, provio, session_id=session_id))
        elif strict:
            raise ProvioError(
                f"tool {getattr(t, 'name', t)!r} ({type(t).__name__}) is not a FunctionTool and "
                "cannot be gated by provio; remove it or pass strict=False to leave it ungated"
            )
        else:
            out.append(t)
    return out


def guard_agent(
    agent: Agent[Any],
    provio: Provio,
    *,
    session_id: str | SessionResolver | None = None,
    strict: bool = True,
) -> Agent[Any]:
    """Clone ``agent`` with every ``FunctionTool`` gated by provio.

    With ``strict=True`` (default) an agent carrying tools provio cannot gate
    (hosted tools, ``mcp_servers``) is refused with :class:`ProvioError`.
    Handoff targets are separate agents: guard each of them too.
    """
    if strict and agent.mcp_servers:
        raise ProvioError(
            "agent has mcp_servers, whose tools the Agents SDK builds at run time and provio cannot "
            "gate here; put the MCP server behind `provio proxy --mcp` or pass strict=False"
        )
    return agent.clone(tools=guard_tools(list(agent.tools), provio, session_id=session_id, strict=strict))


__all__ = ["guard_agent", "guard_function_tool", "guard_tools"]
