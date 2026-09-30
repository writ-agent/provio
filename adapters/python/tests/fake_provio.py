"""A tiny Contract 6 gateway for tests: ``fake_provio.py [--policy P] [--ledger L] check --stdio --ask deny|defer``.

The verdict is chosen by tool name (no real policy):

    allowed / anything else  -> allow
    denied / bash + "rm -rf" -> deny (rule no-rm, provio.yaml:12)
    asky                     -> ask (approval required under --ask defer)
    redacty                  -> redact, pattern \\d{3}-\\d{2}-\\d{4}
    malformed                -> writes a non-JSON line
    hang                     -> never answers
    crash                    -> exits with code 3
    error                    -> {"error": {...}}
    wrongid                  -> answers with a different id
    liar                     -> deny with dispatch=true (contradiction)
    redact_noout             -> redact, but complete omits output

Every request is appended as a JSON line to ``$FAKE_PROVIO_LOG`` when set.
Set ``FAKE_PROVIO_FAIL=1`` to exit 1 immediately, like the stub binary.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time

SSN = r"\d{3}-\d{2}-\d{4}"


def main() -> int:
    argv = sys.argv[1:]
    if os.environ.get("FAKE_PROVIO_FAIL") == "1":
        sys.stderr.write("provio check is not implemented in this build (fail closed)\n")
        return 1
    ask_mode = "deny"
    if "--ask" in argv:
        ask_mode = argv[argv.index("--ask") + 1]
    if "check" not in argv or "--stdio" not in argv:
        sys.stderr.write(f"fake_provio: unexpected argv {argv}\n")
        return 1
    log_path = os.environ.get("FAKE_PROVIO_LOG")
    refs: dict[str, dict] = {}
    n = 0
    out = sys.stdout

    def send(obj: dict) -> None:
        out.write(json.dumps(obj) + "\n")
        out.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        if log_path:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({"argv": argv, **req}) + "\n")
        rid = req.get("id")
        base = {"v": 1, "id": rid}
        op = req.get("op")
        if op == "decide":
            call = req["call"]
            tool = call.get("tool")
            n += 1
            ref = f"ref-{n}"
            refs[ref] = {"tool": tool, "call": call}
            cmd = (call.get("args") or {}).get("command", "")
            if tool == "malformed":
                out.write("this is not json\n")
                out.flush()
                continue
            if tool == "hang":
                time.sleep(3600)
            if tool == "crash":
                return 3
            if tool == "error":
                send({**base, "error": {"code": "bad_request", "message": "fake failure"}})
                continue
            if tool == "wrongid":
                send({**base, "id": "nope", "decision": "allow", "dispatch": True, "ref": ref})
                continue
            if tool == "liar":
                send({**base, "decision": "deny", "dispatch": True, "rule_id": "x", "ref": ref})
                continue
            if tool == "denied" or (tool == "bash" and "rm -rf" in cmd):
                send({**base, "decision": "deny", "dispatch": False, "rule_id": "no-rm",
                      "reason": "Destructive command.", "location": "provio.yaml:12", "ref": ref})
                continue
            if tool == "asky":
                if ask_mode == "defer":
                    send({**base, "decision": "ask", "dispatch": False, "approval": "required",
                          "rule_id": "prod", "reason": "--- diff ---", "irreversible": True,
                          "timeout_ms": 5000, "ref": ref})
                else:  # what the real gateway sends for an ask under --ask deny
                    send({**base, "decision": "deny", "verdict": "ask", "dispatch": False,
                          "rule_id": "prod", "reason": "requires human approval (fail closed)",
                          "location": "provio.yaml:20", "ref": ref})
                continue
            if tool in ("redacty", "redact_noout"):
                send({**base, "decision": "redact", "dispatch": True, "rule_id": "pii",
                      "patterns": [SSN], "ref": ref})
                continue
            send({**base, "decision": "allow", "dispatch": True, "rule_id": "read-only", "ref": ref})
        elif op == "resolve":
            ref = req.get("ref")
            if ref not in refs:
                send({**base, "error": {"code": "bad_ref", "message": "unknown ref"}})
                continue
            if req.get("approved") is True:
                new_ref = f"{ref}.approved"  # like provio: an approval mints a new ref
                refs[new_ref] = {**refs[ref], "approved": True}
                send({**base, "decision": "allow", "dispatch": True, "rule_id": "prod", "ref": new_ref})
            else:
                send({**base, "decision": "deny", "dispatch": False, "rule_id": "prod",
                      "reason": "rejected by approver", "ref": ref})
        elif op == "complete":
            ref = req.get("ref")
            if ref not in refs:
                send({**base, "error": {"code": "bad_ref", "message": "unknown ref"}})
                continue
            tool = refs[ref]["tool"]
            if tool == "asky" and not refs[ref].get("approved"):
                send({**base, "error": {"code": "state", "message": "complete for an ask that was not approved"}})
                continue
            resp = {**base, "recorded": True}
            if tool == "redacty":
                resp["output"] = re.sub(SSN, "[redacted-by-provio]", req.get("output") or "")
            send(resp)
        else:
            send({**base, "error": {"code": "bad_request", "message": f"unknown op {op!r}"}})
    return 0


if __name__ == "__main__":
    sys.exit(main())
