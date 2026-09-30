"""OpenAI Agents SDK: a real Runner with the SDK's own ScriptedModel (no network)."""

from __future__ import annotations

import pytest

pytest.importorskip("agents")

from agents import Agent, RunConfig, Runner, WebSearchTool, function_tool
from agents.testing import ScriptedModel, assistant_message, function_call

from provio_sdk import Provio, ProvioError
from provio_sdk.openai_agents import guard_agent, guard_function_tool

RAN: list[str] = []


@function_tool
def allowed(path: str) -> str:
    """Read a file."""
    RAN.append("allowed")
    return f"contents of {path}"


@function_tool
def denied(target: str) -> str:
    """Delete everything."""
    RAN.append("denied")
    return "deleted"


@function_tool
async def redacty(user: str) -> str:
    """Look up a user."""
    RAN.append("redacty")
    return f"{user} ssn 123-45-6789"


@pytest.fixture(autouse=True)
def _reset():
    RAN.clear()


def outputs(result) -> dict[str, str]:
    out = {}
    for item in result.new_items:
        raw = getattr(item, "raw_item", None)
        if getattr(item, "type", "") == "tool_call_output_item":
            cid = raw["call_id"] if isinstance(raw, dict) else raw.call_id
            out[cid] = item.output
    return out


async def test_runner_allowed_runs_denied_does_not(fake_bin, fake_log):
    model = ScriptedModel(
        [
            [
                function_call("allowed", {"path": "a.txt"}, call_id="c1"),
                function_call("denied", {"target": "/"}, call_id="c2"),
                function_call("redacty", {"user": "bob"}, call_id="c3"),
            ],
            [assistant_message("done")],
        ]
    )
    async with Provio() as w:
        agent = guard_agent(Agent(name="a", model=model, tools=[allowed, denied, redacty]), w)
        result = await Runner.run(agent, "go", run_config=RunConfig(group_id="thread-7", tracing_disabled=True))
    out = outputs(result)
    assert sorted(RAN) == ["allowed", "redacty"]
    assert out["c1"] == "contents of a.txt"
    assert "no-rm" in out["c2"] and "provio.yaml:12" in out["c2"]
    assert out["c3"] == "bob ssn [redacted-by-provio]"
    assert result.final_output == "done"
    # the model saw the refusal on its second turn
    assert "no-rm" in str(model.last_call)
    decides = [r for r in fake_log() if r["op"] == "decide"]
    assert {r["call"]["call_id"] for r in decides} == {"c1", "c2", "c3"}
    assert {r["call"]["session_id"] for r in decides} == {"thread-7"}
    assert decides[0]["call"]["caller"]["agent"] == "openai-agents"


async def test_gateway_down_blocks(monkeypatch, tmp_path):
    monkeypatch.setenv("PROVIO_BIN", str(tmp_path / "missing" / "provio"))
    model = ScriptedModel([[function_call("allowed", {"path": "a"}, call_id="c1")], [assistant_message("ok")]])
    async with Provio() as w:
        agent = Agent(name="a", model=model, tools=[guard_function_tool(allowed, w)])
        result = await Runner.run(agent, "go", run_config=RunConfig(tracing_disabled=True))
    assert RAN == [] and "did not run" in outputs(result)["c1"]


def test_strict_refuses_ungateable_tools(fake_bin):
    with Provio() as w:
        with pytest.raises(ProvioError):
            guard_agent(Agent(name="a", tools=[allowed, WebSearchTool()]), w)
        guarded = guard_agent(Agent(name="a", tools=[allowed, WebSearchTool()]), w, strict=False)
        assert len(guarded.tools) == 2
        # guarding is idempotent and leaves the original untouched
        g = guard_function_tool(allowed, w)
        assert guard_function_tool(g, w) is g and allowed.on_invoke_tool is not g.on_invoke_tool
