"""provio-sdk: policy-gated tool calls for Python agent frameworks.

Every tool call is sent to ``provio check --stdio`` (docs/INTERFACES.md,
Contract 6), checked against ``provio.yaml`` (allow / deny / ask / redact) and
recorded to provio's hash-chained ledger before the tool runs. Any failure to
get a clear "dispatch" answer from provio blocks the call.

Framework integrations live in submodules and import their framework only
when imported: ``provio_sdk.langgraph``, ``provio_sdk.openai_agents``,
``provio_sdk.claude_agent_sdk``.
"""

from .client import AsyncProvioClient, ProvioClient, find_provio_binary
from .errors import (
    ProvioApprovalRejected,
    ProvioBlocked,
    ProvioClosed,
    ProvioDenied,
    ProvioError,
    ProvioGatewayCrashed,
    ProvioGatewayError,
    ProvioProtocolError,
    ProvioTimeout,
    ProvioUnavailable,
)
from .guard import Provio, deny_all, get_default_provio, set_default_provio, to_text, provio_tool
from .toolmap import MappedTool, map_claude_tool
from .types import Approval, ApprovalRequest, Caller, Completion, Decision, Server, ToolCall

__version__ = "0.1.4"

__all__ = [
    "Approval",
    "ApprovalRequest",
    "AsyncProvioClient",
    "Caller",
    "Completion",
    "Decision",
    "MappedTool",
    "Server",
    "ToolCall",
    "Provio",
    "ProvioApprovalRejected",
    "ProvioBlocked",
    "ProvioClient",
    "ProvioClosed",
    "ProvioDenied",
    "ProvioError",
    "ProvioGatewayCrashed",
    "ProvioGatewayError",
    "ProvioProtocolError",
    "ProvioTimeout",
    "ProvioUnavailable",
    "deny_all",
    "find_provio_binary",
    "get_default_provio",
    "map_claude_tool",
    "set_default_provio",
    "to_text",
    "provio_tool",
]
