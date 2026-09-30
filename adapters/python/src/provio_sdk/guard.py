"""Framework-neutral gate: decide -> (approve) -> run -> complete.

Every framework integration in this package is a thin shell over
:class:`Provio`. The sequence for one tool call:

1. ``decide`` the call. Any provio failure raises and the tool does not run.
2. If provio deferred an ``ask`` (``--ask defer``), call the ``approver``
   (default: reject) and send ``resolve`` with its answer. The final decision
   from ``resolve`` is what counts.
3. If the decision does not dispatch, raise :class:`ProvioBlocked`.
4. Run the tool. If it raises, ``complete(ok=False)`` and re-raise.
5. ``complete(ok=True, output=...)``. For a ``redact`` verdict the redacted
   text provio returns replaces the result; if provio returns none, the output is
   withheld (fail closed). If ``complete`` fails for any reason the output is
   withheld as well.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import threading
import uuid
from typing import Any, Awaitable, Callable, Mapping, TypeVar, Union

from .client import AsyncProvioClient, ProvioClient
from .errors import ProvioApprovalRejected, ProvioBlocked, ProvioDenied, ProvioError, ProvioProtocolError
from .types import Approval, ApprovalRequest, Caller, Decision, Server, ToolCall

T = TypeVar("T")
ApproverResult = Union[bool, Approval]
Approver = Callable[[ApprovalRequest], Union[ApproverResult, Awaitable[ApproverResult]]]

DEFAULT_APPROVAL_TIMEOUT = 300.0


def deny_all(request: ApprovalRequest) -> bool:
    """The default approver: every deferred ask is rejected."""
    return False


def to_text(value: Any) -> str:
    """Render a tool result as the text provio hashes (and redacts)."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def refusal_text(exc: ProvioError) -> str:
    """What the model is told when provio blocks a call (integrations return this)."""
    if isinstance(exc, ProvioBlocked):
        return f"Tool call blocked by provio policy. {exc.decision.describe()}"
    return (
        f"Tool call blocked: provio could not authorize it ({type(exc).__name__}: {exc}). "
        "The tool did not run."
    )


def jsonable(value: Any) -> Any:
    """Coerce tool arguments into plain JSON values (unknown objects -> str)."""
    try:
        return json.loads(json.dumps(value, default=str))
    except (TypeError, ValueError):
        return str(value)


def _add_note(exc: BaseException, note: str) -> None:
    add = getattr(exc, "add_note", None)
    if add is not None:
        add(note)


def _normalize_approval(result: Any, default_id: str) -> Approval:
    if isinstance(result, Approval):
        return Approval(result.approved is True, result.approver or default_id)
    if isinstance(result, bool):
        return Approval(result, default_id)
    # Anything else (None, "yes", 1) is not an approval.
    return Approval(False, default_id)


class Provio:
    """The gate. Owns (or borrows) one gateway process.

    Args:
        client: an existing :class:`ProvioClient`. If omitted, one is created from
            ``client_kwargs`` with ``ask="defer"`` when an ``approver`` is given,
            else ``ask="deny"``.
        session_id: default session id for calls that do not carry one.
        caller: the :class:`Caller` identity sent with every call.
        approver: called for deferred asks; returns ``bool`` or :class:`Approval`
            (may be async on async paths). Default: :func:`deny_all`.
        approver_id: recorded as the approver when the approver does not name one.
        approval_timeout: seconds to wait for the approver (default: the rule's
            ``timeout_ms``, else 300s). Timeout rejects.
        send_output: send tool output to ``complete`` (hashed, never stored)
            for non-redact calls too. Redact calls always send it.
    """

    def __init__(
        self,
        client: ProvioClient | AsyncProvioClient | None = None,
        *,
        session_id: str | None = None,
        caller: Caller | None = None,
        approver: Approver | None = None,
        approver_id: str = "adapter:provio-sdk",
        approval_timeout: float | None = None,
        send_output: bool = True,
        **client_kwargs: Any,
    ) -> None:
        if client is not None and client_kwargs:
            raise TypeError("pass either a client or client kwargs, not both")
        if isinstance(client, AsyncProvioClient):
            sync = client.sync
        elif client is None:
            client_kwargs.setdefault("ask", "defer" if approver is not None else "deny")
            sync = ProvioClient(**client_kwargs)
        else:
            sync = client
        self.client: ProvioClient = sync
        self.aclient: AsyncProvioClient = client if isinstance(client, AsyncProvioClient) else AsyncProvioClient(sync)
        self.session_id = session_id or f"py-{uuid.uuid4().hex[:16]}"
        self.caller = caller or Caller(agent="provio-sdk")
        self.approver: Approver = approver or deny_all
        self.approver_id = approver_id
        self.approval_timeout = approval_timeout
        self.send_output = send_output

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> Provio:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    async def __aenter__(self) -> Provio:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclient.aclose()

    # -- building calls ----------------------------------------------------

    def make_call(
        self,
        tool: str,
        args: Mapping[str, Any] | None,
        *,
        session_id: str | None = None,
        call_id: str | None = None,
        server: Server | None = None,
        trust: str | None = None,
        caller: Caller | None = None,
    ) -> ToolCall:
        a = jsonable(dict(args or {}))
        if not isinstance(a, dict):  # pragma: no cover - dict in, dict out
            a = {"value": a}
        return ToolCall(
            tool=tool,
            args=a,
            session_id=session_id or self.session_id,
            call_id=call_id,
            caller=caller or self.caller,
            server=server,
            trust=trust,
        )

    # -- step 1-3: authorize -----------------------------------------------

    def _approval_timeout(self, d: Decision) -> float:
        if self.approval_timeout is not None:
            return self.approval_timeout
        if d.timeout_ms:
            return d.timeout_ms / 1000.0
        return DEFAULT_APPROVAL_TIMEOUT

    @staticmethod
    def _final(d: Decision) -> Decision:
        if d.dispatch:
            return d
        # `--ask deny` answers an ask as decision "deny" with verdict "ask".
        if d.decision == "ask" or d.approval_required or d.raw.get("verdict") == "ask":
            raise ProvioApprovalRejected(d)
        raise ProvioDenied(d)

    def _ask_sync(self, call: ToolCall, d: Decision) -> Approval:
        box: dict[str, Any] = {}

        def run() -> None:
            try:
                res = self.approver(ApprovalRequest(call, d))
                if inspect.isawaitable(res):
                    close = getattr(res, "close", None)
                    if close:
                        close()
                    box["result"] = False  # async approver on a sync path: reject
                else:
                    box["result"] = res
            except BaseException as e:  # noqa: BLE001 - approver bugs reject
                box["error"] = e

        t = threading.Thread(target=run, name="provio-approver", daemon=True)
        t.start()
        t.join(self._approval_timeout(d))
        if t.is_alive() or "error" in box:
            return Approval(False, self.approver_id)
        return _normalize_approval(box.get("result"), self.approver_id)

    async def _ask_async(self, call: ToolCall, d: Decision) -> Approval:
        async def run() -> Any:
            res = self.approver(ApprovalRequest(call, d))
            if inspect.isawaitable(res):
                res = await res
            return res

        try:
            res = await asyncio.wait_for(run(), timeout=self._approval_timeout(d))
        except asyncio.CancelledError:
            raise
        except BaseException:  # noqa: BLE001 - approver failure or timeout rejects
            return Approval(False, self.approver_id)
        return _normalize_approval(res, self.approver_id)

    def authorize(self, call: ToolCall) -> Decision:
        """decide (+ approve/resolve). Returns a dispatching decision or raises."""
        d = self.client.decide(call)
        if d.approval_required:
            ap = self._ask_sync(call, d)
            assert d.ref is not None  # parse_decision guarantees it
            d = self.client.resolve(d.ref, ap.approved, ap.approver)
            if not ap.approved:
                if d.dispatch:
                    raise ProvioProtocolError("provio dispatched a call the approver rejected")
                raise ProvioApprovalRejected(d)
        return self._final(d)

    async def aauthorize(self, call: ToolCall) -> Decision:
        d = await self.aclient.decide(call)
        if d.approval_required:
            ap = await self._ask_async(call, d)
            assert d.ref is not None
            d = await self.aclient.resolve(d.ref, ap.approved, ap.approver)
            if not ap.approved:
                if d.dispatch:
                    raise ProvioProtocolError("provio dispatched a call the approver rejected")
                raise ProvioApprovalRejected(d)
        return self._final(d)

    # -- step 5: record ----------------------------------------------------

    def _check_completion(self, d: Decision, redacted: str | None) -> str | None:
        if d.is_redact and redacted is None:
            raise ProvioProtocolError("redact verdict but provio returned no redacted output")
        return redacted if d.is_redact else None

    def record(self, d: Decision, *, ok: bool, output: str | None, exit: int | None = None) -> str | None:
        """complete. Returns the redacted text for a redact verdict, else None."""
        assert d.ref is not None
        send = output if (d.is_redact or self.send_output) else None
        if d.is_redact and send is None:
            send = ""
        c = self.client.complete(d.ref, ok, exit=exit if exit is not None else (0 if ok else 1), output=send)
        return self._check_completion(d, c.output) if ok else None

    async def arecord(self, d: Decision, *, ok: bool, output: str | None, exit: int | None = None) -> str | None:
        assert d.ref is not None
        send = output if (d.is_redact or self.send_output) else None
        if d.is_redact and send is None:
            send = ""
        c = await self.aclient.complete(d.ref, ok, exit=exit if exit is not None else (0 if ok else 1), output=send)
        return self._check_completion(d, c.output) if ok else None

    def _record_failure(self, d: Decision, exc: BaseException) -> None:
        try:
            self.record(d, ok=False, output=f"{type(exc).__name__}: {exc}")
        except ProvioError as e:
            _add_note(exc, f"provio: could not record the failed execution: {e}")

    async def _arecord_failure(self, d: Decision, exc: BaseException) -> None:
        try:
            await self.arecord(d, ok=False, output=f"{type(exc).__name__}: {exc}")
        except ProvioError as e:
            _add_note(exc, f"provio: could not record the failed execution: {e}")

    # -- the whole sequence ------------------------------------------------

    def execute(
        self,
        tool: str,
        args: Mapping[str, Any] | None,
        fn: Callable[[], T],
        *,
        session_id: str | None = None,
        call_id: str | None = None,
        server: Server | None = None,
        trust: str | None = None,
        render: Callable[[Any], str] = to_text,
    ) -> T | str:
        """Gate ``fn()`` as tool ``tool`` with ``args``.

        Returns ``fn()``'s result, or the redacted text (``str``) for a redact
        verdict. Raises :class:`ProvioError` whenever the tool must not run or
        its output must not be returned.
        """
        call = self.make_call(tool, args, session_id=session_id, call_id=call_id, server=server, trust=trust)
        d = self.authorize(call)
        try:
            result = fn()
        except BaseException as e:
            self._record_failure(d, e)
            raise
        redacted = self.record(d, ok=True, output=render(result))
        return redacted if d.is_redact else result  # type: ignore[return-value]

    async def aexecute(
        self,
        tool: str,
        args: Mapping[str, Any] | None,
        fn: Callable[[], Awaitable[T]],
        *,
        session_id: str | None = None,
        call_id: str | None = None,
        server: Server | None = None,
        trust: str | None = None,
        render: Callable[[Any], str] = to_text,
    ) -> T | str:
        """Async :meth:`execute`; ``fn()`` returns an awaitable."""
        call = self.make_call(tool, args, session_id=session_id, call_id=call_id, server=server, trust=trust)
        d = await self.aauthorize(call)
        try:
            result = await fn()
        except BaseException as e:
            await self._arecord_failure(d, e)
            raise
        redacted = await self.arecord(d, ok=True, output=render(result))
        return redacted if d.is_redact else result  # type: ignore[return-value]

    # -- wrapping plain callables ------------------------------------------

    def guarded(
        self,
        fn: Callable[..., Any],
        *,
        name: str | None = None,
        session_id: str | None = None,
        server: Server | None = None,
    ) -> Callable[..., Any]:
        """Return ``fn`` gated by provio. Works for sync and ``async def`` functions.

        The call's ``args`` are ``fn``'s bound arguments (defaults applied).
        """
        tool = name or getattr(fn, "__name__", "tool")
        sig = inspect.signature(fn)

        def bind(a: tuple[Any, ...], kw: dict[str, Any]) -> dict[str, Any]:
            try:
                ba = sig.bind(*a, **kw)
            except TypeError:
                return {"args": list(a), **kw}
            ba.apply_defaults()
            out: dict[str, Any] = {}
            for k, v in ba.arguments.items():
                kind = sig.parameters[k].kind
                if kind is inspect.Parameter.VAR_KEYWORD:
                    out.update(v)
                elif kind is inspect.Parameter.VAR_POSITIONAL:
                    out[k] = list(v)
                else:
                    out[k] = v
            return out

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*a: Any, **kw: Any) -> Any:
                return await self.aexecute(
                    tool, bind(a, kw), lambda: fn(*a, **kw), session_id=session_id, server=server
                )

            async_wrapper.__provio_guarded__ = True  # type: ignore[attr-defined]
            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*a: Any, **kw: Any) -> Any:
            return self.execute(tool, bind(a, kw), lambda: fn(*a, **kw), session_id=session_id, server=server)

        wrapper.__provio_guarded__ = True  # type: ignore[attr-defined]
        return wrapper

    def tool(
        self, name: str | None = None, *, session_id: str | None = None, server: Server | None = None
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator form of :meth:`guarded`."""

        def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
            return self.guarded(fn, name=name, session_id=session_id, server=server)

        return deco


# --------------------------------------------------------------------------
# Process-wide default gate for the bare decorator
# --------------------------------------------------------------------------

_default: Provio | None = None
_default_lock = threading.Lock()


def get_default_provio() -> Provio:
    """The shared :class:`Provio` used by :func:`provio_tool` without ``provio=``.

    Built on first use from the environment (``PROVIO_BIN``, and
    ``PROVIO_POLICY`` / ``PROVIO_LEDGER`` when set); asks fail closed.
    """
    global _default
    with _default_lock:
        if _default is None:
            import os

            _default = Provio(policy=os.environ.get("PROVIO_POLICY"), ledger=os.environ.get("PROVIO_LEDGER"))
        return _default


def set_default_provio(provio: Provio | None) -> None:
    """Replace (or clear) the shared default gate."""
    global _default
    with _default_lock:
        _default = provio


def provio_tool(
    name: str | None = None,
    *,
    provio: Provio | None = None,
    session_id: str | None = None,
    server: Server | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator: gate a function through ``provio`` (default: :func:`get_default_provio`).

    The default gate is resolved at call time, so decorating at import time
    does not start provio.
    """

    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        if provio is not None:
            return provio.guarded(fn, name=name, session_id=session_id, server=server)
        cache: dict[int, Callable[..., Any]] = {}

        def current() -> Callable[..., Any]:
            w = get_default_provio()
            g = cache.get(id(w))
            if g is None:
                cache.clear()
                g = cache[id(w)] = w.guarded(fn, name=name, session_id=session_id, server=server)
            return g

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_lazy(*a: Any, **kw: Any) -> Any:
                return await current()(*a, **kw)

            return async_lazy

        @functools.wraps(fn)
        def lazy(*a: Any, **kw: Any) -> Any:
            return current()(*a, **kw)

        return lazy

    return deco
