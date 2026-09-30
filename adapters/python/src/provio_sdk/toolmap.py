"""Claude-style tool names -> provio policy vocabulary. The one place this lives.

Claude Code and the Claude Agent SDK expose the same built-in tools. provio
policies are written against a neutral vocabulary (``bash`` + ``command``,
``fs.read`` / ``fs.write`` + ``path``, ``http`` + ``url``, MCP ``server`` +
tool), so every Claude-shaped integration maps names here and nowhere else.
``provio check --format claude-code`` applies the same table
(``map_claude_tool`` in ``crates/provio-cli/src/hook.rs``); change both together.

The original input is kept (so the ledger records what the agent asked for);
the normalized keys are added next to it when the native key differs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .types import Server

_FS_READ = ("Read", "Glob", "Grep", "LS", "NotebookRead")
_FS_WRITE = ("Write", "Edit", "MultiEdit", "NotebookEdit")

MCP_PREFIX = "mcp__"


@dataclass(frozen=True)
class MappedTool:
    tool: str
    args: dict[str, Any]
    server: Server | None = None
    native_name: str = ""


def _first_str(inp: Mapping[str, Any], *keys: str) -> str | None:
    for k in keys:
        v = inp.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def split_mcp_name(name: str) -> tuple[str, str] | None:
    """``mcp__<server>__<tool>`` -> ``(server, tool)``; ``None`` otherwise."""
    if not name.startswith(MCP_PREFIX):
        return None
    rest = name[len(MCP_PREFIX):]
    server, sep, tool = rest.partition("__")
    if not sep or not server or not tool:
        return None
    return server, tool


def map_claude_tool(
    name: str,
    tool_input: Mapping[str, Any] | None,
    *,
    mcp_transports: Mapping[str, str] | None = None,
) -> MappedTool:
    """Map a Claude Code / Claude Agent SDK tool use to provio's vocabulary.

    ==================================  ==============  ======================
    Claude tool                         provio ``tool``   normalized arg
    ==================================  ==============  ======================
    ``Bash``, ``PowerShell``            ``bash``        ``command``
    ``Read``/``Glob``/``Grep``/``LS``   ``fs.read``     ``path``
    ``Write``/``Edit``/``MultiEdit``/   ``fs.write``    ``path``
    ``NotebookEdit``
    ``WebFetch``                        ``http``        ``url``
    ``WebSearch``                       ``web.search``  ``query``
    ``mcp__<server>__<tool>``           ``<tool>``      ``server = <server>``
    anything else                       unchanged       unchanged
    ==================================  ==============  ======================
    """
    inp: dict[str, Any] = dict(tool_input or {})
    if name in ("Bash", "PowerShell"):
        return MappedTool("bash", inp, native_name=name)
    if name in _FS_READ or name in _FS_WRITE:
        if not isinstance(inp.get("path"), str):
            path = _first_str(inp, "file_path", "notebook_path")
            if path is not None:
                inp["path"] = path
        return MappedTool("fs.read" if name in _FS_READ else "fs.write", inp, native_name=name)
    if name == "WebFetch":
        return MappedTool("http", inp, native_name=name)
    if name == "WebSearch":
        return MappedTool("web.search", inp, native_name=name)
    mcp = split_mcp_name(name)
    if mcp is not None:
        server, tool = mcp
        transport = (mcp_transports or {}).get(server, "unknown")
        return MappedTool(tool, inp, server=Server(name=server, transport=transport), native_name=name)
    return MappedTool(name, inp, native_name=name)
