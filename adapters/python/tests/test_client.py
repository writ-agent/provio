"""ProvioClient / AsyncProvioClient against the fake gateway: every failure fails closed."""

from __future__ import annotations

import asyncio
import threading

import pytest

from provio_sdk import (
    AsyncProvioClient,
    ToolCall,
    ProvioClient,
    ProvioGatewayCrashed,
    ProvioGatewayError,
    ProvioProtocolError,
    ProvioTimeout,
    ProvioUnavailable,
)


def call(tool: str, **args) -> ToolCall:
    return ToolCall(tool=tool, args=args, session_id="s1", call_id=f"c-{tool}")


def test_allow_decision_and_complete(fake_bin, fake_log):
    with ProvioClient(policy="p.yaml", ledger="l.jsonl") as c:
        d = c.decide(call("allowed", path="x"))
        assert d.decision == "allow" and d.dispatch and d.ref == "ref-1"
        assert d.rule_id == "read-only"
        comp = c.complete(d.ref, True, exit=0, output="hi")
        assert comp.recorded and comp.output is None
    reqs = fake_log()
    assert reqs[0]["argv"] == ["--policy", "p.yaml", "--ledger", "l.jsonl", "check", "--stdio", "--ask", "deny"]
    assert reqs[0]["v"] == 1 and reqs[0]["op"] == "decide"
    assert reqs[0]["call"]["caller"] == {"agent": "unknown", "agent_version": None, "user": None, "non_human_id": None}
    assert reqs[1] == {**reqs[1], "op": "complete", "ref": "ref-1", "ok": True, "exit": 0, "output": "hi"}


def test_deny_carries_rule_reason_location(fake_bin):
    with ProvioClient() as c:
        d = c.decide(call("bash", command="rm -rf /"))
    assert (d.decision, d.dispatch, d.rule_id, d.location) == ("deny", False, "no-rm", "provio.yaml:12")
    assert "Destructive" in d.describe() and "provio.yaml:12" in d.describe()


def test_ask_defer_then_resolve(fake_bin, fake_log):
    with ProvioClient(ask="defer") as c:
        d = c.decide(call("asky"))
        assert d.approval_required and not d.dispatch and d.irreversible and d.timeout_ms == 5000
        final = c.resolve(d.ref, True, "human:alice")
        assert final.dispatch
        d2 = c.decide(call("asky"))
        assert not c.resolve(d2.ref, False).dispatch
    resolves = [r for r in fake_log() if r["op"] == "resolve"]
    assert resolves[0]["approved"] is True and resolves[0]["approver"] == "human:alice"


def test_redact_returns_redacted_output(fake_bin):
    with ProvioClient() as c:
        d = c.decide(call("redacty"))
        assert d.is_redact and d.patterns == (r"\d{3}-\d{2}-\d{4}",)
        assert c.complete(d.ref, True, output="ssn 123-45-6789").output == "ssn [redacted-by-provio]"


def test_missing_binary_env(monkeypatch, tmp_path):
    monkeypatch.setenv("PROVIO_BIN", str(tmp_path / "nope" / "provio.exe"))
    with pytest.raises(ProvioUnavailable):
        ProvioClient().decide(call("allowed"))


def test_missing_binary_path(monkeypatch):
    import provio_sdk.client as client_mod

    monkeypatch.delenv("PROVIO_BIN", raising=False)
    monkeypatch.setenv("PATH", "")
    monkeypatch.setattr(client_mod, "bundled_provio_binary", lambda: None)
    with pytest.raises(ProvioUnavailable):
        ProvioClient().decide(call("allowed"))


def test_bundled_binary_is_preferred_over_path(monkeypatch, tmp_path):
    import provio_sdk.client as client_mod

    bundled = tmp_path / "bundled" / "provio.exe"
    bundled.parent.mkdir()
    bundled.write_bytes(b"")
    on_path = tmp_path / "onpath"
    on_path.mkdir()
    (on_path / "provio.exe").write_bytes(b"")
    (on_path / "provio").write_bytes(b"")
    monkeypatch.delenv("PROVIO_BIN", raising=False)
    monkeypatch.setenv("PATH", str(on_path))
    monkeypatch.setattr(client_mod, "bundled_provio_binary", lambda: str(bundled))
    assert client_mod.find_provio_binary() == [str(bundled)]


def test_provio_bin_overrides_bundled(monkeypatch, fake_bin):
    import provio_sdk.client as client_mod

    monkeypatch.setattr(client_mod, "bundled_provio_binary", lambda: "/should/not/be/used")
    assert client_mod.find_provio_binary()[-1].endswith("fake_provio.py")


def test_bundled_lookup_without_provio_cli_is_none(monkeypatch):
    from importlib import metadata

    import provio_sdk.client as client_mod

    def missing(name):
        raise metadata.PackageNotFoundError(name)

    monkeypatch.setattr(metadata, "distribution", missing)
    assert client_mod.bundled_provio_binary() is None


def test_binary_exits_immediately_like_stub(fake_bin, monkeypatch):
    monkeypatch.setenv("FAKE_PROVIO_FAIL", "1")
    with ProvioClient(timeout=10) as c, pytest.raises(ProvioGatewayCrashed) as ei:
        c.decide(call("allowed"))
    assert "exited (code 1)" in str(ei.value) and "fail closed" in str(ei.value)


def test_malformed_line(fake_bin):
    with ProvioClient() as c:
        with pytest.raises(ProvioProtocolError):
            c.decide(call("malformed"))
        # gateway was killed; the next call gets a fresh one
        assert c.decide(call("allowed")).dispatch


def test_wrong_id(fake_bin):
    with ProvioClient() as c, pytest.raises(ProvioProtocolError):
        c.decide(call("wrongid"))


def test_contradictory_response(fake_bin):
    with ProvioClient() as c, pytest.raises(ProvioProtocolError):
        c.decide(call("liar"))


def test_error_response(fake_bin):
    with ProvioClient() as c, pytest.raises(ProvioGatewayError) as ei:
        c.decide(call("error"))
    assert ei.value.code == "bad_request"


def test_timeout_kills_and_recovers(fake_bin):
    with ProvioClient(timeout=0.5) as c:
        with pytest.raises(ProvioTimeout):
            c.decide(call("hang"))
        assert c.decide(call("allowed"), timeout=10).dispatch


def test_crash_then_restart_budget(fake_bin):
    with ProvioClient(max_restarts=2, restart_window=60) as c:
        for _ in range(3):
            with pytest.raises(ProvioGatewayCrashed):
                c.decide(call("crash"))
        with pytest.raises(ProvioUnavailable):
            c.decide(call("allowed"))


def test_closed_client_refuses(fake_bin):
    c = ProvioClient()
    c.close()
    with pytest.raises(Exception) as ei:
        c.decide(call("allowed"))
    from provio_sdk import ProvioError

    assert isinstance(ei.value, ProvioError)


def test_spawn_override_command(fake_command, fake_log):
    with ProvioClient(command=fake_command, ask="defer") as c:
        assert c.decide(call("allowed")).dispatch
    assert fake_log()[0]["argv"][-2:] == ["--ask", "defer"]


def test_thread_safety(fake_bin):
    errors: list[BaseException] = []
    with ProvioClient() as c:

        def worker(i: int) -> None:
            try:
                for j in range(20):
                    d = c.decide(ToolCall(tool="allowed", args={"i": i, "j": j}, session_id="s"))
                    assert d.dispatch
                    c.complete(d.ref, True)
            except BaseException as e:  # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    assert not errors


async def test_async_client_allow_and_timeout(fake_bin):
    async with AsyncProvioClient(timeout=0.5) as ac:
        results = await asyncio.gather(*(ac.decide(call("allowed")) for _ in range(10)))
        assert all(d.dispatch for d in results)
        with pytest.raises(ProvioTimeout):
            await ac.decide(call("hang"))
        d = await ac.decide(call("redacty"), timeout=10)
        assert (await ac.complete(d.ref, True, output="123-45-6789")).output == "[redacted-by-provio]"


def test_ask_ui_is_accepted_with_a_longer_default_timeout():
    from provio_sdk.client import UI_ASK_TIMEOUT

    assert ProvioClient(ask="ui").timeout == UI_ASK_TIMEOUT
    assert ProvioClient(ask="ui", timeout=5).timeout == 5
    assert ProvioClient().timeout == 30.0
    with pytest.raises(ValueError):
        ProvioClient(ask="maybe")
