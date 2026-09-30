"""The shared Claude tool mapping; mirrors the cases in crates/provio-cli/src/hook.rs."""

from provio_sdk import map_claude_tool


def m(name, inp):
    return map_claude_tool(name, inp)


def test_mapping_table():
    r = m("Bash", {"command": "ls"})
    assert (r.tool, r.args["command"], r.server) == ("bash", "ls", None)
    assert m("PowerShell", {"command": "dir"}).tool == "bash"
    r = m("Read", {"file_path": "/x/.env"})
    assert (r.tool, r.args["path"], r.args["file_path"]) == ("fs.read", "/x/.env", "/x/.env")
    r = m("NotebookEdit", {"notebook_path": "/n.ipynb"})
    assert (r.tool, r.args["path"]) == ("fs.write", "/n.ipynb")
    for w in ("Write", "Edit", "MultiEdit"):
        assert m(w, {"file_path": "/a"}).tool == "fs.write"
    r = m("Grep", {"pattern": "x", "path": "/src"})
    assert (r.tool, r.args["path"]) == ("fs.read", "/src")
    assert m("WebFetch", {"url": "https://evil.example/x"}).tool == "http"
    assert m("WebSearch", {"query": "q"}).tool == "web.search"
    r = m("mcp__postgres__query", {"sql": "select 1"})
    assert (r.tool, r.server.name, r.server.transport) == ("query", "postgres", "unknown")
    r = m("mcp__plugin_x_db__run__fast", {})
    assert (r.tool, r.server.name) == ("run__fast", "plugin_x_db")
    r = m("mcp__broken", {})
    assert (r.tool, r.server) == ("mcp__broken", None)
    assert m("TodoWrite", {}).tool == "TodoWrite"


def test_input_not_mutated_and_transport_override():
    inp = {"file_path": "/a"}
    m("Read", inp)
    assert inp == {"file_path": "/a"}
    assert map_claude_tool("mcp__gh__x", {}, mcp_transports={"gh": "stdio"}).server.transport == "stdio"


def test_base_package_imports_no_framework():
    import subprocess
    import sys

    code = (
        "import sys, provio_sdk; "
        "bad=[m for m in ('langgraph','langchain_core','agents','claude_agent_sdk') if m in sys.modules]; "
        "sys.exit(1 if bad else 0)"
    )
    assert subprocess.run([sys.executable, "-c", code]).returncode == 0
