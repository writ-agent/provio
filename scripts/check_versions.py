#!/usr/bin/env python3
"""Fail unless every released artifact carries the same version.

Checks the Rust workspace (provio-cli wheel and binaries), the provio-sdk Python
package and its provio-cli pin, the provio-sdk npm package and its
provio pin, and provio with its platform-package pins.

Usage: python3 scripts/check_versions.py [vX.Y.Z]   (tag optional)
"""

import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main(argv):
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    rust = cargo["workspace"]["package"]["version"]
    py = tomllib.loads((ROOT / "adapters/python/pyproject.toml").read_text(encoding="utf-8"))
    sdk = json.loads((ROOT / "adapters/typescript/package.json").read_text(encoding="utf-8"))
    cli = json.loads((ROOT / "packaging/npm/cli/package.json").read_text(encoding="utf-8"))
    plugin = json.loads((ROOT / "plugins/claude-code/.claude-plugin/plugin.json").read_text(encoding="utf-8"))
    market = json.loads((ROOT / ".claude-plugin/marketplace.json").read_text(encoding="utf-8"))

    found = {
        "Cargo.toml workspace.package.version": rust,
        "provio-sdk (PyPI) version": py["project"]["version"],
        "provio-sdk (npm) version": sdk["version"],
        "provio version": cli["version"],
        "Claude Code plugin version": plugin["version"],
        "marketplace version": market["metadata"]["version"],
        "marketplace plugin entry version": market["plugins"][0]["version"],
    }
    for dep in py["project"].get("dependencies", []):
        m = re.fullmatch(r"provio==(\S+)", dep.replace(" ", ""))
        if m:
            found["provio-sdk (PyPI) -> provio pin"] = m.group(1)
    found["provio-sdk (npm) -> provio pin"] = sdk.get("optionalDependencies", {}).get("provio")
    for name, ver in cli.get("optionalDependencies", {}).items():
        found[f"provio -> {name} pin"] = ver
    if len(argv) > 0:
        found["git tag"] = argv[0].removeprefix("refs/tags/").removeprefix("v")

    expected = rust
    bad = {k: v for k, v in found.items() if v != expected}
    for k, v in found.items():
        print(f"{'ok ' if v == expected else 'BAD'} {k}: {v}")
    if bad:
        print(f"\nversion mismatch: expected {expected} everywhere", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
