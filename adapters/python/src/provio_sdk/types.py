"""Typed views of the Contract 6 wire format (docs/INTERFACES.md).

Parsing is strict in the fail-closed direction: anything missing, mistyped or
self-contradictory raises :class:`ProvioProtocolError`, never a permissive
default. Unknown fields are ignored (the protocol evolves additively).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Mapping

from .errors import ProvioGatewayError, ProvioProtocolError

PROTOCOL_VERSION = 1

DecisionKind = Literal["allow", "deny", "ask", "redact"]
_DECISIONS = frozenset({"allow", "deny", "ask", "redact"})
_TRUST = frozenset({"verified", "unverified", "malicious"})


@dataclass(frozen=True)
class Caller:
    """`CallerIdentity` (Contract 1)."""

    agent: str = "unknown"
    agent_version: str | None = None
    user: str | None = None
    non_human_id: str | None = None

    def to_wire(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "agent_version": self.agent_version,
            "user": self.user,
            "non_human_id": self.non_human_id,
        }


@dataclass(frozen=True)
class Server:
    """`ServerIdentity` (Contract 1): the MCP server a call targets."""

    name: str
    transport: str = "unknown"
    version: str | None = None

    def to_wire(self) -> dict[str, Any]:
        return {"name": self.name, "transport": self.transport, "version": self.version}


@dataclass(frozen=True)
class ToolCall:
    """The `call` object of a `decide` request (mirrors Contract 1 `ToolCall`).

    provio sets `mode = SdkHook` and `captured_at` itself. Never put credentials
    in `args`.
    """

    tool: str
    args: Mapping[str, Any]
    session_id: str
    call_id: str | None = None
    caller: Caller | None = None
    server: Server | None = None
    trust: str | None = None

    def to_wire(self) -> dict[str, Any]:
        if not isinstance(self.tool, str) or not self.tool:
            raise ValueError("ToolCall.tool must be a non-empty string")
        if not isinstance(self.session_id, str) or not self.session_id:
            raise ValueError("ToolCall.session_id must be a non-empty string")
        if self.trust is not None and self.trust not in _TRUST:
            raise ValueError(f"ToolCall.trust must be one of {sorted(_TRUST)} or None")
        call: dict[str, Any] = {
            "session_id": self.session_id,
            "tool": self.tool,
            "args": dict(self.args),
            "caller": (self.caller or Caller()).to_wire(),
            "server": self.server.to_wire() if self.server else None,
            "trust": self.trust,
        }
        if self.call_id:
            call["call_id"] = self.call_id
        return call


@dataclass(frozen=True)
class Decision:
    """A `decide` or `resolve` response."""

    decision: DecisionKind
    dispatch: bool
    rule_id: str | None = None
    reason: str | None = None
    location: str | None = None
    approval_required: bool = False
    patterns: tuple[str, ...] = ()
    ref: str | None = None
    irreversible: bool = False
    timeout_ms: int | None = None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @property
    def is_redact(self) -> bool:
        return self.decision == "redact"

    def describe(self) -> str:
        """Human text for the model / logs: verdict, rule, reason, location."""
        parts = [f"provio {self.decision}"]
        if self.rule_id:
            parts.append(f"rule '{self.rule_id}'")
        if self.location:
            parts.append(f"at {self.location}")
        head = " ".join(parts)
        if self.approval_required and not self.dispatch:
            head += " (approval required and not granted)"
        return f"{head}: {self.reason}" if self.reason else head


@dataclass(frozen=True)
class Completion:
    """A `complete` response."""

    recorded: bool
    output: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)


@dataclass(frozen=True)
class ApprovalRequest:
    """What an approver sees for a deferred `ask`."""

    call: ToolCall
    decision: Decision

    @property
    def diff(self) -> str | None:
        """The rule's reason / diff text provio sent for the human."""
        return self.decision.reason


@dataclass(frozen=True)
class Approval:
    """An approver's answer. Approvers may also return a plain ``bool``."""

    approved: bool
    approver: str | None = None


# --------------------------------------------------------------------------
# Response parsing
# --------------------------------------------------------------------------


def _opt_str(msg: Mapping[str, Any], key: str) -> str | None:
    v = msg.get(key)
    if v is None:
        return None
    if not isinstance(v, str):
        raise ProvioProtocolError(f"field '{key}' must be a string, got {type(v).__name__}")
    return v


def check_envelope(msg: Any, expected_id: str) -> Mapping[str, Any]:
    """Validate `v` and `id`, and raise on an `error` response."""
    if not isinstance(msg, dict):
        raise ProvioProtocolError("response is not a JSON object")
    if msg.get("v") != PROTOCOL_VERSION:
        raise ProvioProtocolError(f"unsupported protocol version {msg.get('v')!r}")
    if msg.get("id") != expected_id:
        raise ProvioProtocolError(
            f"response id {msg.get('id')!r} does not match request id {expected_id!r}"
        )
    if "error" in msg:
        err = msg["error"]
        if isinstance(err, dict):
            code = str(err.get("code", "unknown"))
            message = str(err.get("message", ""))
        else:
            code, message = "unknown", str(err)
        raise ProvioGatewayError(code, message, raw=msg)
    return msg


def parse_decision(msg: Mapping[str, Any], *, final: bool = False) -> Decision:
    """Parse a decide (``final=False``) or resolve (``final=True``) response."""
    kind = msg.get("decision")
    if kind not in _DECISIONS:
        raise ProvioProtocolError(f"unknown decision {kind!r}")
    dispatch = msg.get("dispatch")
    if not isinstance(dispatch, bool):
        raise ProvioProtocolError("field 'dispatch' must be a boolean")
    approval = msg.get("approval")
    approval_required = approval == "required"
    if approval is not None and not approval_required:
        raise ProvioProtocolError(f"unknown approval value {approval!r}")

    patterns_raw = msg.get("patterns", [])
    if patterns_raw is None:
        patterns_raw = []
    if not isinstance(patterns_raw, list) or not all(isinstance(p, str) for p in patterns_raw):
        raise ProvioProtocolError("field 'patterns' must be a list of strings")

    timeout_ms = msg.get("timeout_ms")
    if timeout_ms is not None and (isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int)):
        raise ProvioProtocolError("field 'timeout_ms' must be an integer")
    irreversible = msg.get("irreversible", False)
    if not isinstance(irreversible, bool):
        raise ProvioProtocolError("field 'irreversible' must be a boolean")

    d = Decision(
        decision=kind,
        dispatch=dispatch,
        rule_id=_opt_str(msg, "rule_id"),
        reason=_opt_str(msg, "reason"),
        location=_opt_str(msg, "location"),
        approval_required=approval_required,
        patterns=tuple(patterns_raw),
        ref=_opt_str(msg, "ref"),
        irreversible=irreversible,
        timeout_ms=timeout_ms,
        raw=dict(msg),
    )

    # Self-consistency. A contradiction is a gateway bug; never dispatch on it.
    if d.dispatch:
        if d.decision not in ("allow", "redact"):
            raise ProvioProtocolError(f"decision '{d.decision}' cannot carry dispatch=true")
        if d.approval_required:
            raise ProvioProtocolError("approval:'required' cannot carry dispatch=true")
        if not d.ref:
            raise ProvioProtocolError("a dispatching decision must carry a 'ref' for complete")
    if d.approval_required:
        if final:
            raise ProvioProtocolError("a resolve response must be final, not approval:'required'")
        if d.decision != "ask":
            raise ProvioProtocolError("approval:'required' is only valid on an 'ask' decision")
        if not d.ref:
            raise ProvioProtocolError("approval:'required' must carry a 'ref' for resolve")
    return d


def parse_completion(msg: Mapping[str, Any]) -> Completion:
    recorded = msg.get("recorded")
    if recorded is not True:
        raise ProvioProtocolError(f"complete was not recorded (recorded={recorded!r})")
    return Completion(recorded=True, output=_opt_str(msg, "output"), raw=dict(msg))
