"""LangGraph: a real StateGraph + ToolNode driven by a scripted model node."""

from __future__ import annotations

import pytest

pytest.importorskip("langgraph")

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import tools_condition

from provio_sdk import Provio
from provio_sdk.langgraph import guard_tool, provio_tool_node

RAN: list[str] = []


@tool
def allowed(path: str) -> str:
    """Read a file."""
    RAN.append("allowed")
    return f"contents of {path}"


@tool
def denied(target: str) -> str:
    """Delete everything."""
    RAN.append("denied")
    return "deleted"


@tool
def redacty(user: str) -> str:
    """Look up a user."""
    RAN.append("redacty")
    return f"{user} ssn 123-45-6789"


def scripted_graph(node, calls):
    """model node emits one AIMessage with `calls`, then ends after the tools run."""

    def model(state: MessagesState):
        if isinstance(state["messages"][-1], ToolMessage):
            return {"messages": [AIMessage(content="done")]}
        return {
            "messages": [
                AIMessage(content="", tool_calls=[{"name": n, "args": a, "id": f"call_{i}"} for i, (n, a) in enumerate(calls)])
            ]
        }

    g = StateGraph(MessagesState)
    g.add_node("model", model)
    g.add_node("tools", node)
    g.add_edge(START, "model")
    g.add_conditional_edges("model", tools_condition)
    g.add_edge("tools", "model")
    return g.compile()


def tool_messages(result):
    return {m.tool_call_id: m for m in result["messages"] if isinstance(m, ToolMessage)}


@pytest.fixture(autouse=True)
def _reset():
    RAN.clear()


def test_graph_allowed_runs_denied_does_not(fake_bin, fake_log):
    with Provio() as w:
        graph = scripted_graph(
            provio_tool_node([allowed, denied, redacty], w),
            [("allowed", {"path": "a.txt"}), ("denied", {"target": "/"}), ("redacty", {"user": "bob"})],
        )
        out = graph.invoke({"messages": [HumanMessage("go")]}, {"configurable": {"thread_id": "t-42"}})
    msgs = tool_messages(out)
    assert sorted(RAN) == ["allowed", "redacty"]
    assert msgs["call_0"].content == "contents of a.txt" and msgs["call_0"].status == "success"
    assert msgs["call_1"].status == "error" and "no-rm" in msgs["call_1"].content
    assert "provio.yaml:12" in msgs["call_1"].content
    assert msgs["call_2"].content == "bob ssn [redacted-by-provio]"
    assert out["messages"][-1].content == "done"  # graph kept going
    decides = [r for r in fake_log() if r["op"] == "decide"]
    assert {r["call"]["session_id"] for r in decides} == {"t-42"}
    assert {r["call"]["call_id"] for r in decides} == {"call_0", "call_1", "call_2"}
    assert decides[0]["call"]["caller"]["agent"] == "langgraph"


async def test_graph_async_and_gateway_down(monkeypatch, tmp_path):
    monkeypatch.setenv("PROVIO_BIN", str(tmp_path / "missing" / "provio"))
    with Provio() as w:
        graph = scripted_graph(provio_tool_node([allowed], w), [("allowed", {"path": "a"})])
        out = await graph.ainvoke({"messages": [HumanMessage("go")]})
    msg = tool_messages(out)["call_0"]
    assert RAN == [] and msg.status == "error" and "did not run" in msg.content


def test_guard_tool_direct(fake_bin):
    from langchain_core.tools import ToolException

    with Provio() as w:
        g_allowed, g_denied = guard_tool(allowed, w), guard_tool(denied, w)
        assert g_allowed.name == "allowed" and g_allowed.args == allowed.args
        assert g_allowed.invoke({"path": "x"}) == "contents of x"
        with pytest.raises(ToolException):
            g_denied.invoke({"target": "/"})
        msg = g_denied.invoke({"type": "tool_call", "name": "denied", "args": {"target": "/"}, "id": "c9"})
        assert isinstance(msg, ToolMessage) and msg.status == "error"
    assert RAN == ["allowed"]
