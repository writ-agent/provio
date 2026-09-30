"""LangGraph / LangChain integration.

Integration point: ``ToolNode(wrap_tool_call=..., awrap_tool_call=...)``
(langgraph-prebuilt >= 1.0). ToolNode hands every tool call in the graph to
the wrapper together with an ``execute`` callable; the wrapper decides with
provio first and only then calls ``execute``. A blocked call returns a
``ToolMessage(status="error")`` carrying provio's reason, so the model sees the
refusal and the graph keeps running.

* :func:`provio_tool_node` - a ``ToolNode`` with the gate installed (use it as
  the graph's tool node, or pass it as ``tools=`` to ``create_react_agent``).
* :class:`ProvioToolGate` - the wrapper pair, for composing with your own
  ``wrap_tool_call`` or other ``(request, handler)`` interceptors.
* :func:`guard_tool` - wrap a single ``BaseTool`` for code that invokes tools
  outside a ToolNode. Do not combine with ``provio_tool_node`` (each would
  record its own decision).

Session id: ``config["configurable"]["thread_id"]`` when present, else the
``Provio``'s ``session_id``.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Mapping, Sequence

from langchain_core.messages import ToolMessage
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import BaseTool
from langgraph.prebuilt import ToolNode
from langgraph.types import Command

from .errors import ProvioError
from .guard import Provio, refusal_text, to_text
from .types import Caller, Decision, ToolCall

try:  # pragma: no cover - metadata lookup only
    from importlib.metadata import version as _pkg_version

    _LG_VERSION: str | None = _pkg_version("langgraph")
except Exception:  # pragma: no cover
    _LG_VERSION = None

WITHHELD = "Tool output withheld by provio"


def _session_from_config(config: Mapping[str, Any] | None) -> str | None:
    if not config:
        return None
    configurable = config.get("configurable") or {}
    for key in ("thread_id", "session_id"):
        v = configurable.get(key)
        if v:
            return str(v)
    return None


class ProvioToolGate:
    """``wrap_tool_call`` / ``awrap_tool_call`` for LangGraph's ToolNode.

    Args:
        provio: the :class:`~provio_sdk.Provio` gate.
        session_id: fixed session id (default: thread id from config, then
            ``provio.session_id``).
        tool_name: optional ``(langchain tool name) -> provio tool name`` mapping.
    """

    def __init__(
        self,
        provio: Provio,
        *,
        session_id: str | None = None,
        tool_name: Callable[[str], str] | None = None,
    ) -> None:
        self.provio = provio
        self.session_id = session_id
        self.tool_name = tool_name

    # -- helpers -----------------------------------------------------------

    def _caller(self) -> Caller:
        c = self.provio.caller
        if c.agent == "provio-sdk":
            return Caller(agent="langgraph", agent_version=_LG_VERSION, user=c.user, non_human_id=c.non_human_id)
        return c

    def make_call(self, tool_call: Mapping[str, Any], config: Mapping[str, Any] | None) -> ToolCall:
        name = str(tool_call.get("name") or "")
        args = tool_call.get("args")
        if not isinstance(args, Mapping):
            args = {"input": args}
        return self.provio.make_call(
            self.tool_name(name) if self.tool_name else name,
            args,
            session_id=self.session_id or _session_from_config(config) or self.provio.session_id,
            call_id=tool_call.get("id") or None,
            caller=self._caller(),
        )

    @staticmethod
    def _message(tool_call: Mapping[str, Any], content: str) -> ToolMessage:
        return ToolMessage(
            content=content,
            name=tool_call.get("name"),
            tool_call_id=tool_call.get("id") or "",
            status="error",
        )

    @staticmethod
    def _output_of(result: Any) -> tuple[bool, str | None]:
        if isinstance(result, ToolMessage):
            content = result.content
            return result.status != "error", content if isinstance(content, str) else to_text(content)
        if isinstance(result, Command):
            return True, None
        return True, to_text(result)

    @staticmethod
    def _apply(d: Decision, tool_call: Mapping[str, Any], result: Any, ok: bool, redacted: str | None) -> Any:
        if not d.is_redact:
            return result
        if not ok or redacted is None:
            return ProvioToolGate._message(tool_call, f"{WITHHELD}: the tool failed under a redact rule.")
        if isinstance(result, ToolMessage):
            # The artifact may carry the raw result; it must not survive redaction.
            return result.model_copy(update={"content": redacted, "artifact": None})
        if isinstance(result, Command):
            return ProvioToolGate._message(tool_call, f"{WITHHELD}: a Command result cannot be redacted.")
        return redacted

    # -- sync --------------------------------------------------------------

    def gate(self, tool_call: Mapping[str, Any], config: Mapping[str, Any] | None, run: Callable[[], Any]) -> Any:
        """Gate ``run()`` for one LangChain tool call dict. Never raises ProvioError."""
        try:
            d = self.provio.authorize(self.make_call(tool_call, config))
        except ProvioError as e:
            return self._message(tool_call, refusal_text(e))
        try:
            result = run()
        except BaseException as e:
            self.provio._record_failure(d, e)
            raise
        ok, text = self._output_of(result)
        try:
            redacted = self.provio.record(d, ok=ok, output=text)
        except ProvioError as e:
            return self._message(tool_call, f"{WITHHELD}: {e}")
        return self._apply(d, tool_call, result, ok, redacted)

    def wrap_tool_call(self, request: Any, execute: Callable[[Any], Any]) -> Any:
        """``ToolCallWrapper``: ``(ToolCallRequest, execute) -> ToolMessage | Command``."""
        config = getattr(getattr(request, "runtime", None), "config", None)
        return self.gate(request.tool_call, config, lambda: execute(request))

    __call__ = wrap_tool_call

    # -- async -------------------------------------------------------------

    async def agate(
        self, tool_call: Mapping[str, Any], config: Mapping[str, Any] | None, run: Callable[[], Awaitable[Any]]
    ) -> Any:
        try:
            d = await self.provio.aauthorize(self.make_call(tool_call, config))
        except ProvioError as e:
            return self._message(tool_call, refusal_text(e))
        try:
            result = await run()
        except BaseException as e:
            await self.provio._arecord_failure(d, e)
            raise
        ok, text = self._output_of(result)
        try:
            redacted = await self.provio.arecord(d, ok=ok, output=text)
        except ProvioError as e:
            return self._message(tool_call, f"{WITHHELD}: {e}")
        return self._apply(d, tool_call, result, ok, redacted)

    async def awrap_tool_call(self, request: Any, execute: Callable[[Any], Awaitable[Any]]) -> Any:
        """``AsyncToolCallWrapper``."""
        config = getattr(getattr(request, "runtime", None), "config", None)
        return await self.agate(request.tool_call, config, lambda: execute(request))


def provio_tool_node(
    tools: Sequence[BaseTool | Callable[..., Any]],
    provio: Provio,
    *,
    session_id: str | None = None,
    wrap_tool_call: Callable[..., Any] | None = None,
    awrap_tool_call: Callable[..., Any] | None = None,
    **tool_node_kwargs: Any,
) -> ToolNode:
    """A ``ToolNode`` whose every tool call is gated by provio.

    Your own ``wrap_tool_call`` / ``awrap_tool_call`` still run, *outside* the
    gate, so provio decides on the request exactly as it will execute.
    """
    gate = ProvioToolGate(provio, session_id=session_id)

    sync_w: Callable[..., Any] = gate.wrap_tool_call
    async_w: Callable[..., Any] = gate.awrap_tool_call
    if wrap_tool_call is not None:
        user_sync = wrap_tool_call

        def sync_w(request: Any, execute: Callable[[Any], Any]) -> Any:
            return user_sync(request, lambda r: gate.wrap_tool_call(r, execute))

    if awrap_tool_call is not None:
        user_async = awrap_tool_call

        async def async_w(request: Any, execute: Callable[[Any], Awaitable[Any]]) -> Any:
            async def inner(r: Any) -> Any:
                return await gate.awrap_tool_call(r, execute)

            return await user_async(request, inner)

    return ToolNode(list(tools), wrap_tool_call=sync_w, awrap_tool_call=async_w, **tool_node_kwargs)


class ProvioGuardedTool(BaseTool):
    """A ``BaseTool`` that asks provio before delegating to ``inner``."""

    inner: BaseTool
    gate: Any

    def _run(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - invoke is overridden
        raise NotImplementedError("ProvioGuardedTool routes through invoke()")

    @staticmethod
    def _as_tool_call(input: Any) -> tuple[dict[str, Any], bool]:
        if isinstance(input, dict) and input.get("type") == "tool_call" and "args" in input:
            return dict(input), True
        args = input if isinstance(input, dict) else {"input": input}
        return {"name": None, "args": args, "id": None}, False

    def _finish(self, is_call: bool, out: Any) -> Any:
        if isinstance(out, ToolMessage) and out.status == "error" and not is_call:
            raise _tool_exception(str(out.content))
        return out

    def invoke(self, input: Any, config: RunnableConfig | None = None, **kwargs: Any) -> Any:
        tc, is_call = self._as_tool_call(input)
        tc["name"] = tc.get("name") or self.inner.name
        out = self.gate.gate(tc, config, lambda: self.inner.invoke(input, config, **kwargs))
        return self._finish(is_call, out)

    async def ainvoke(self, input: Any, config: RunnableConfig | None = None, **kwargs: Any) -> Any:
        tc, is_call = self._as_tool_call(input)
        tc["name"] = tc.get("name") or self.inner.name

        async def run() -> Any:
            return await self.inner.ainvoke(input, config, **kwargs)

        out = await self.gate.agate(tc, config, run)
        return self._finish(is_call, out)


def _tool_exception(msg: str) -> Exception:
    from langchain_core.tools import ToolException

    return ToolException(msg)


def guard_tool(tool: BaseTool, provio: Provio, *, session_id: str | None = None) -> ProvioGuardedTool:
    """Wrap one LangChain tool. Invoked with a tool-call dict it returns an
    error ``ToolMessage`` when blocked; invoked with plain args it raises
    ``ToolException``. Same name, description and schema as ``tool``."""
    return ProvioGuardedTool(
        name=tool.name,
        description=tool.description,
        args_schema=tool.args_schema,
        return_direct=tool.return_direct,
        response_format=getattr(tool, "response_format", "content"),
        inner=tool,
        gate=ProvioToolGate(provio, session_id=session_id),
    )


__all__ = ["ProvioGuardedTool", "ProvioToolGate", "guard_tool", "refusal_text", "provio_tool_node"]
