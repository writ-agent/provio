#!/usr/bin/env python3
"""Compile every policy pack and example policy, and run each pack's fixtures.

Pack files carry only `rules`, so each is wrapped in a minimal policy header
(`version: 1`, `default: ask`) before compiling with `provio doctor`. A pack
that ships a `fixtures/` directory is then tested with
`provio policy test --fixtures packs/<id>/fixtures` against the same wrapped
policy, so unmatched cases expect `verdict: ask, rule_id: default`.

A pack may also ship `redact-samples.yaml`: each sample is driven through
the real gateway (`provio check` decide, then complete with a tool output) and
the masked result is checked for strings that must disappear or survive.

Every pack must also carry a README.md and a fixtures/ directory.
Exits 1 if any file fails to compile, any fixture fails, or a pack is
missing its README or fixtures.

Usage: python3 scripts/validate_packs.py [--provio PATH]
Builds `provio` with cargo first unless --provio points at an existing binary.
Requires PyYAML.
"""

import json
import pathlib
import subprocess
import sys
import tempfile
import time

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent


def provio_binary(argv):
    if "--provio" in argv:
        return pathlib.Path(argv[argv.index("--provio") + 1])
    subprocess.run(["cargo", "build", "-q", "-p", "provio-cli"], cwd=ROOT, check=True)
    exe = ROOT / "target" / "debug" / "provio"
    return exe.with_suffix(".exe") if sys.platform == "win32" else exe


def run(cmd, **kwargs):
    """Run `cmd`; retry when Windows Application Control transiently blocks
    a freshly built binary (os error 4551)."""
    for attempt in range(10):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, **kwargs)
        except OSError as e:
            if getattr(e, "winerror", None) != 4551 or attempt == 9:
                raise
            time.sleep(0.5)
    raise AssertionError("unreachable")


def check_redact_samples(exe, policy_text, samples_path, tmp):
    """Drive each redact sample through the real gateway (`provio check`
    decide, then complete with the sample output) and assert the masking.
    Returns a list of failure strings (empty = all good)."""
    project = tmp / f"redact-{samples_path.parent.name}"
    project.mkdir(exist_ok=True)
    (project / "provio.yaml").write_text(policy_text, encoding="utf-8")
    samples = yaml.safe_load(samples_path.read_text(encoding="utf-8")) or []
    failures = []

    def gateway(req):
        res = run([str(exe), "check"], input=json.dumps(req), cwd=project)
        lines = [l for l in res.stdout.splitlines() if l.strip()]
        return json.loads(lines[-1]) if lines else {"error": res.stderr.strip()}

    for n, s in enumerate(samples):
        call = s["call"]
        decided = gateway({
            "v": 1, "id": f"d{n}", "op": "decide",
            "call": {"call_id": f"sample-{n}", "session_id": "validate-packs",
                     "tool": call["tool"], "args": call.get("args", {}),
                     "caller": {"agent": "validate-packs"}},
        })
        if decided.get("decision") != "redact":
            failures.append(f"{s['name']}: expected a redact decision, got {decided}")
            continue
        done = gateway({"v": 1, "id": f"c{n}", "op": "complete", "ref": decided["ref"],
                        "ok": True, "exit": 0, "output": s["output"]})
        seen = done.get("output")
        if not isinstance(seen, str):
            failures.append(f"{s['name']}: no masked output returned: {done}")
            continue
        for secret in s.get("masked", []):
            if secret in seen:
                failures.append(f"{s['name']}: {secret!r} was not masked")
        for keep in s.get("kept", []):
            if keep not in seen:
                failures.append(f"{s['name']}: {keep!r} was masked but should survive")
    return len(samples), failures


def main(argv):
    exe = provio_binary(argv)
    targets = sorted(ROOT.glob("packs/*/pack.yaml")) + sorted(ROOT.glob("examples/*.yaml"))
    ok = True
    with tempfile.TemporaryDirectory(prefix="provio-packval-") as tmp:
        tmp = pathlib.Path(tmp)
        for path in targets:
            rel = path.relative_to(ROOT).as_posix()
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            is_pack = "default" not in doc
            if is_pack:  # pack file -> wrap into a policy
                doc = {"version": 1, "default": "ask", "rules": doc["rules"]}
            probe = tmp / f"{path.parent.name}_{path.name}"
            probe.write_text(yaml.safe_dump(doc), encoding="utf-8")
            out = run(
                [str(exe), "doctor", "--policy", str(probe), "--ledger", str(tmp / "none.jsonl")]
            ).stdout
            line = next((l for l in out.splitlines() if l.startswith("policy")), "")
            good = bool(line) and "FAILED" not in line
            ok &= good
            print("PASS" if good else "FAIL", rel, "->", line.strip()[:90] or "(no policy line)")
            if not is_pack:
                continue

            pack_dir = path.parent
            for required in ("README.md", "fixtures"):
                if not (pack_dir / required).exists():
                    ok = False
                    print("FAIL", rel, "-> missing", f"{pack_dir.name}/{required}")
            fixtures = pack_dir / "fixtures"
            if not fixtures.is_dir():
                continue
            res = run([str(exe), "policy", "test", "--policy", str(probe), "--fixtures", str(fixtures)])
            passed = res.returncode == 0
            ok &= passed
            summary = (res.stdout or res.stderr).strip()
            first = summary.splitlines()[0] if summary else "(no output)"
            print("PASS" if passed else "FAIL", f"{fixtures.relative_to(ROOT).as_posix()}/", "->", first)
            if not passed:
                for extra in summary.splitlines()[1:]:
                    print("    ", extra)

            samples = pack_dir / "redact-samples.yaml"
            if samples.exists():
                total, failures = check_redact_samples(exe, probe.read_text(encoding="utf-8"), samples, tmp)
                ok &= not failures
                print("PASS" if not failures else "FAIL",
                      samples.relative_to(ROOT).as_posix(), "->",
                      f"{total - len({f.split(':')[0] for f in failures})}/{total} redact samples masked as expected")
                for f in failures:
                    print("    ", f)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
