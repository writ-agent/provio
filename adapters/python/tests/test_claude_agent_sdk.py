"""Claude Agent SDK: the real ClaudeSDKClient + Query control protocol, with a
scripted stand-in for the Claude Code CLI on the other side of the Transport
(no subprocess, no model, no network). The fake CLI "runs" a tool only when the
SDK's PreToolUse hook answers allow, exactly as the CLI does."""

from __future__ import annotations

import asyncio
import json
from typing import Any, AsyncIterator

import pytest

pytest.importorskip("claude_agent_sdk")

from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient, ResultMessage
from claude_agent_sdk._internal.transport import Transport

from provio_sdk import Approval, Provio
from provio_sdk.claude_agent_sdk import ProvioClaudeHooks

MASK = "[redacted-by-provio]"


class FakeClaudeCLI(Transport):
    def __init__(self, script: list[tuple[str, dict, Any]], session_id: str = "sess-cc") -> None:
        self.script = script
        self.session_id = session_id
        self.out: asyncio.Queue[dict | None] = asyncio.Queue()
        self.callbacks: dict[str, list[str]] = {}
        self.waiting: dict[str, asyncio.Future] = {}
        self.ran: list[str] = []
        self.model_saw: dict[str, Any] = {}
        self.n = 0
        self._ready = False

    async def connect(self) -> None:
        self._ready = True

    def is_ready(self) -> bool:
        return self._ready

    async def end_input(self) -> None:
        pass

    async def close(self) -> None:
        self._ready = False
        await self.out.put(None)

    async def read_messages(self) -> AsyncIterator[dict[str, Any]]:
        while True:
            msg = await self.out.get()
            if msg is None:
                return
            yield msg

    async def write(self, data: str) -> None:
        for line in data.splitlines():
            if not line.strip():
                continue
            msg = json.loads(line)
            t = msg.get("type")
            if t == "control_request":
                req = msg["request"]
                if req.get("subtype") == "initialize":
                    for event, matchers in (req.get("hooks") or {}).items():
                        self.callbacks[event] = [cid for m in matchers for cid in m["hookCallbackIds"]]
                await self.out.put(
                    {
                        "type": "control_response",
                        "response": {"subtype": "success", "request_id": msg["request_id"], "response": {}},
                    }
                )
            elif t == "control_response":
                resp = msg["response"]
                fut = self.waiting.pop(resp["request_id"], None)
                if fut is not None:
                    fut.set_result(resp)
            elif t == "user":
                asyncio.get_running_loop().create_task(self.run_turn())

    async def hook(self, event: str, payload: dict, tool_use_id: str) -> dict:
        """Call every SDK callback registered for `event`; return the last response."""
        result: dict = {}
        for cid in self.callbacks.get(event, []):
            self.n += 1
            rid = f"cli_{self.n}"
            fut = asyncio.get_running_loop().create_future()
            self.waiting[rid] = fut
            await self.out.put(
                {
                    "type": "control_request",
                    "request_id": rid,
                    "request": {
                        "subtype": "hook_callback",
                        "callback_id": cid,
                        "tool_use_id": tool_use_id,
                        "input": {
                            "session_id": self.session_id,
                            "transcript_path": "",
                            "cwd": ".",
                            "hook_event_name": event,
                            **payload,
                        },
                    },
                }
            )
            resp = await asyncio.wait_for(fut, 10)
            assert resp["subtype"] == "success", resp
            result = resp["response"]
        return result

    async def run_turn(self) -> None:
        for i, (name, tool_input, output) in enumerate(self.script):
            use_id = f"toolu_{i}"
            base = {"tool_name": name, "tool_input": tool_input, "tool_use_id": use_id}
            pre = (await self.hook("PreToolUse", base, use_id)).get("hookSpecificOutput", {})
            if pre.get("permissionDecision") != "allow":
                self.model_saw[use_id] = ("denied", pre.get("permissionDecisionReason"))
                continue
            self.ran.append(name)
            if isinstance(output, Exception):
                await self.hook("PostToolUseFailure", {**base, "error": f"Exit code 2\n{output}"}, use_id)
                self.model_saw[use_id] = ("error", str(output))
                continue
            post = await self.hook("PostToolUse", {**base, "tool_response": output}, use_id)
            updated = post.get("hookSpecificOutput", {}).get("updatedToolOutput")
            self.model_saw[use_id] = ("ok", updated if updated is not None else output)
        await self.out.put(
            {
                "type": "assistant",
                "message": {"model": "fake", "content": [{"type": "text", "text": "done"}]},
                "parent_tool_use_id": None,
                "session_id": self.session_id,
            }
        )
        await self.out.put(
            {
                "type": "result",
                "subtype": "success",
                "duration_ms": 1,
                "duration_api_ms": 1,
                "is_error": False,
                "num_turns": 1,
                "session_id": self.session_id,
            }
        )


async def run(provio: Provio, script) -> FakeClaudeCLI:
    cli = FakeClaudeCLI(script)
    options = ClaudeAgentOptions(hooks=ProvioClaudeHooks(provio).hooks())
    async with ClaudeSDKClient(options, transport=cli) as client:
        await client.query("go")
        async for msg in client.receive_response():
            if isinstance(msg, ResultMessage):
                break
    return cli


async def test_hooks_gate_claude_tools(fake_bin, fake_log):
    async with Provio() as w:
        cli = await run(
            w,
            [
                ("Read", {"file_path": "/repo/README.md"}, {"type": "text", "file": {"content": "hi"}}),
                ("Bash", {"command": "rm -rf /"}, {"stdout": "", "stderr": "", "interrupted": False}),
                ("mcp__redacty__redacty", {"user": "bob"}, {"stdout": "ssn 123-45-6789", "n": 3}),
                ("Write", {"file_path": "/repo/x"}, RuntimeError("disk full")),
            ],
        )
    assert cli.ran == ["Read", "mcp__redacty__redacty", "Write"]  # Bash rm -rf never ran
    assert cli.model_saw["toolu_1"][0] == "denied" and "no-rm" in cli.model_saw["toolu_1"][1]
    assert cli.model_saw["toolu_2"] == ("ok", {"stdout": f"ssn {MASK}", "n": 3})
    log = fake_log()
    decides = [r["call"] for r in log if r["op"] == "decide"]
    assert [(c["tool"], c["call_id"]) for c in decides] == [
        ("fs.read", "toolu_0"),
        ("bash", "toolu_1"),
        ("redacty", "toolu_2"),
        ("fs.write", "toolu_3"),
    ]
    assert decides[0]["args"]["path"] == "/repo/README.md"
    assert decides[2]["server"] == {"name": "redacty", "transport": "unknown", "version": None}
    assert {c["session_id"] for c in decides} == {"sess-cc"}
    assert decides[0]["caller"]["agent"] == "claude-agent-sdk"
    completes = [r for r in log if r["op"] == "complete"]
    assert [(c["ok"], c["exit"]) for c in completes] == [(True, 0), (True, 0), (False, 2)]


async def test_ask_uses_approver(fake_bin):
    async with Provio(approver=lambda req: Approval(req.call.args.get("ok") is True, "human:bob")) as w:
        cli = await run(w, [("asky", {"ok": True}, "fine"), ("asky", {"ok": False}, "never")])
    assert cli.ran == ["asky"] and cli.model_saw["toolu_1"][0] == "denied"


async def test_gateway_down_denies_everything(monkeypatch, tmp_path):
    monkeypatch.setenv("PROVIO_BIN", str(tmp_path / "missing" / "provio"))
    async with Provio() as w:
        cli = await run(w, [("Read", {"file_path": "/a"}, "x"), ("Bash", {"command": "ls"}, "y")])
    assert cli.ran == []
    assert all(v[0] == "denied" and "did not run" in v[1] for v in cli.model_saw.values())


def test_redact_masks_everything_on_doubt(fake_bin):
    with Provio() as w:
        hooks = ProvioClaudeHooks(w)
        assert hooks._redacted_output({"a": "x", "b": [1, "y"]}, None) == {"a": MASK, "b": [1, MASK]}
        assert hooks._redacted_output({"a": "x"}, "not json") == {"a": MASK}
        assert hooks._redacted_output({"a": "x"}, '{"b": "x"}') == {"a": MASK}
        assert hooks._redacted_output("plain 1", "plain [r]") == "plain [r]"
