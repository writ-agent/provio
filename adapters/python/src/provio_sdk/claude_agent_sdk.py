"""Claude Agent SDK integration (package ``claude-agent-sdk``).

Integration point: SDK hook callbacks registered through
``ClaudeAgentOptions(hooks=...)``:

* ``PreToolUse`` -> ``decide`` (+ approver + ``resolve`` for deferred asks).
  Answers ``permissionDecision: "allow"`` or ``"deny"`` with provio's reason.
* ``PostToolUse`` -> ``complete``. For a redact verdict it returns
  ``updatedToolOutput`` with the redacted result.
* ``PostToolUseFailure`` -> ``complete(ok=False)``.

Why hooks and not ``can_use_tool``: the CLI consults ``can_use_tool`` only
when its own permission rules would prompt; tools already allowed by
``allowed_tools`` / ``permission_mode`` never reach it, and it has no
post-execution step for ``complete`` or redaction. A ``PreToolUse`` hook
with no matcher runs for every tool call.

Fail closed: the callbacks never raise (an exception in an SDK hook becomes
an error reply whose handling is up to the CLI). Every failure answers
``deny`` in ``PreToolUse``; in ``PostToolUse`` a redacted call whose
redaction cannot be completed has every string in its output masked.

Tool names and inputs are mapped with :func:`provio_sdk.toolmap.map_claude_tool`,
the same table ``provio check --format claude-code`` uses.
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping

from claude_agent_sdk import HookMatcher

from .errors import ProvioError
from .guard import DEFAULT_APPROVAL_TIMEOUT, Provio, refusal_text, to_text
from .toolmap import map_claude_tool
from .types import Caller, Decision

try:  # pragma: no cover
    from importlib.metadata import version as _pkg_version

    _SDK_VERSION: str | None = _pkg_version("claude-agent-sdk")
except Exception:  # pragma: no cover
    _SDK_VERSION = None

MASK = "[redacted-by-provio]"
_EXIT_RE = re.compile(r"Exit code (\d+)")


def _mask_all(v: Any) -> Any:
    if isinstance(v, str):
        return MASK
    if isinstance(v, list):
        return [_mask_all(x) for x in v]
    if isinstance(v, dict):
        return {k: _mask_all(x) for k, x in v.items()}
    return v


def _same_shape(a: Any, b: Any) -> bool:
    if isinstance(a, dict):
        return isinstance(b, dict) and a.keys() == b.keys() and all(_same_shape(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return isinstance(b, list) and len(a) == len(b) and all(_same_shape(x, y) for x, y in zip(a, b))
    if isinstance(a, str):
        return isinstance(b, str)
    return type(a) is type(b) and a == b


def _pre(decision: str, reason: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"hookEventName": "PreToolUse", "permissionDecision": decision}
    if reason:
        out["permissionDecisionReason"] = reason
    return {"hookSpecificOutput": out}


class ProvioClaudeHooks:
    """provio hooks for ``ClaudeAgentOptions(hooks=ProvioClaudeHooks(provio).hooks())``.

    Args:
        provio: the :class:`~provio_sdk.Provio` gate. Give it an ``approver`` to
            handle ``ask`` verdicts (the client then runs ``--ask defer``);
            without one, asks are rejected.
        session_id: override the SDK's session id.
        mcp_transports: ``{server name: "stdio"|"sse"|"http"|"sdk"}`` for the
            ``server.transport`` provio records (default ``"unknown"``).
        allow_decision: what a provio allow answers in ``PreToolUse``:
            ``"allow"`` (default, as ``provio check --format claude-code`` does)
            skips the SDK's own permission prompt; ``None`` returns no
            decision so the SDK's permission rules still apply on top.
        hook_timeout: seconds the CLI waits for the ``PreToolUse`` hook.
            Default covers the gateway timeout plus the approval timeout.
    """

    def __init__(
        self,
        provio: Provio,
        *,
        session_id: str | None = None,
        mcp_transports: Mapping[str, str] | None = None,
        allow_decision: str | None = "allow",
        hook_timeout: float | None = None,
    ) -> None:
        if allow_decision not in ("allow", None):
            raise ValueError("allow_decision must be 'allow' or None")
        self.provio = provio
        self.session_id = session_id
        self.mcp_transports = dict(mcp_transports or {})
        self.allow_decision = allow_decision
        self.hook_timeout = hook_timeout
        self._pending: dict[tuple[str, str], Decision] = {}

    # -- helpers -----------------------------------------------------------

    def _caller(self, inp: Mapping[str, Any]) -> Caller:
        c = self.provio.caller
        if c.agent == "provio-sdk":
            agent_id = inp.get("agent_id")
            return Caller(
                agent="claude-agent-sdk",
                agent_version=_SDK_VERSION,
                user=c.user,
                non_human_id=str(agent_id) if agent_id else c.non_human_id,
            )
        return c

    def _key(self, inp: Mapping[str, Any], tool_use_id: str | None) -> tuple[str, str]:
        session = self.session_id or str(inp.get("session_id") or self.provio.session_id)
        return session, str(inp.get("tool_use_id") or tool_use_id or "")

    # -- hooks -------------------------------------------------------------

    async def pre_tool_use(self, input: Any, tool_use_id: str | None, context: Any) -> dict[str, Any]:
        try:
            inp: Mapping[str, Any] = input if isinstance(input, Mapping) else {}
            session, use_id = self._key(inp, tool_use_id)
            name = inp.get("tool_name")
            if not isinstance(name, str) or not name:
                return _pre("deny", "provio: hook input has no tool_name (fail closed)")
            tool_input = inp.get("tool_input")
            mapped = map_claude_tool(
                name, tool_input if isinstance(tool_input, Mapping) else {}, mcp_transports=self.mcp_transports
            )
            call = self.provio.make_call(
                mapped.tool,
                mapped.args,
                session_id=session,
                call_id=use_id or None,
                server=mapped.server,
                caller=self._caller(inp),
            )
            d = await self.provio.aauthorize(call)
            if use_id:
                self._pending[(session, use_id)] = d
            if self.allow_decision is None:
                return {}
            return _pre("allow", f"provio {d.decision}" + (f" (rule '{d.rule_id}')" if d.rule_id else ""))
        except ProvioError as e:
            return _pre("deny", refusal_text(e))
        except Exception as e:  # noqa: BLE001 - any adapter bug must deny, not raise
            return _pre("deny", f"provio adapter error ({type(e).__name__}: {e}); the tool did not run")

    async def post_tool_use(self, input: Any, tool_use_id: str | None, context: Any) -> dict[str, Any]:
        inp: Mapping[str, Any] = input if isinstance(input, Mapping) else {}
        d = self._pending.pop(self._key(inp, tool_use_id), None)
        if d is None:
            return {}  # no decision of ours (e.g. PreToolUse denied elsewhere)
        response = inp.get("tool_response")
        try:
            redacted = await self.provio.arecord(d, ok=True, output=to_text(response))
        except ProvioError as e:
            if not d.is_redact:
                return {"systemMessage": f"provio could not record this tool execution: {e}"}
            redacted = None
        except Exception:  # noqa: BLE001
            if not d.is_redact:
                return {}
            redacted = None
        if not d.is_redact:
            return {}
        return {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "updatedToolOutput": self._redacted_output(response, redacted),
            }
        }

    @staticmethod
    def _redacted_output(original: Any, redacted: str | None) -> Any:
        """Shape-preserving redacted tool_response; masks everything on doubt."""
        if redacted is None:
            return _mask_all(original)
        if isinstance(original, str):
            return redacted
        try:
            parsed = json.loads(redacted)
        except ValueError:
            return _mask_all(original)
        # Masking may only change string contents. Anything else means a
        # pattern hit JSON syntax, and the result is not trusted.
        return parsed if _same_shape(original, parsed) else _mask_all(original)

    async def post_tool_use_failure(self, input: Any, tool_use_id: str | None, context: Any) -> dict[str, Any]:
        inp: Mapping[str, Any] = input if isinstance(input, Mapping) else {}
        d = self._pending.pop(self._key(inp, tool_use_id), None)
        if d is None:
            return {}
        err = str(inp.get("error") or "")
        m = _EXIT_RE.search(err)
        try:
            await self.provio.arecord(d, ok=False, output=err, exit=int(m.group(1)) if m else 1)
        except Exception:  # noqa: BLE001 - nothing to withhold; the tool already failed
            pass
        return {}

    # -- wiring ------------------------------------------------------------

    def _pre_timeout(self) -> float:
        if self.hook_timeout is not None:
            return self.hook_timeout
        approval = self.provio.approval_timeout or DEFAULT_APPROVAL_TIMEOUT
        return 2 * self.provio.client.timeout + (approval if self.provio.client.ask == "defer" else 0) + 5

    def hooks(self) -> dict[str, list[HookMatcher]]:
        """The ``hooks=`` mapping for ``ClaudeAgentOptions``; merge with your own if needed."""
        post_timeout = self.provio.client.timeout + 5
        return {
            "PreToolUse": [HookMatcher(matcher=None, hooks=[self.pre_tool_use], timeout=self._pre_timeout())],
            "PostToolUse": [HookMatcher(matcher=None, hooks=[self.post_tool_use], timeout=post_timeout)],
            "PostToolUseFailure": [
                HookMatcher(matcher=None, hooks=[self.post_tool_use_failure], timeout=post_timeout)
            ],
        }


def provio_hooks(provio: Provio, **kwargs: Any) -> dict[str, list[HookMatcher]]:
    """Shorthand: ``ClaudeAgentOptions(hooks=provio_hooks(provio))``."""
    return ProvioClaudeHooks(provio, **kwargs).hooks()


__all__ = ["ProvioClaudeHooks", "provio_hooks"]
