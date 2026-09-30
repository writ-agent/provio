#!/usr/bin/env python3
"""Generate docs/assets/demo-88462.svg: the animated cast of
examples/incident-88462 (claude-code#88462 replayed).

Reuses the self-contained SVG renderer in gen_demo_svg.py (no script, no
external refs, no web fonts). Every verdict, rule id, reason and OS error
below is copied from the REAL output of examples/incident-88462/run.sh; the
only trims are line wrapping, the "provio denied this: " prefix and the tail
of long reasons (marked …). Re-run the demo and update these lines if provio's
output changes.

    python scripts/gen_88462_svg.py
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from gen_demo_svg import (  # noqa: E402  (path set above)
    DIM,
    GREEN,
    MUTED,
    RED,
    TEXT,
    YELLOW,
    prompt,
    svg,
)

SEP = "─" * 78

CAST = [
    (0.0, prompt("./examples/incident-88462/run.sh")),
    (0.6, [("claude-code#88462, replayed", TEXT, True),
           ("  ·  the agent's cleanup script ran rm -rf \"$HOME\"", DIM, False)]),
    (0.9, [(SEP, DIM, False)]),
    (1.3, [("Act 1. ", TEXT, True), ("The agent writes cleanup.sh", TEXT, False)]),
    (1.6, [("    trap 'rm -rf \"$HOME\"' EXIT", MUTED, False)]),
    (2.2, [("  ✗ DENY ", RED, True),
           ("floor-rm-home-or-root-denied — the file being written (cleanup.sh) line 3", TEXT, False)]),
    (2.4, [("          runs `trap 'rm -rf \"$HOME\"' EXIT`. Recursive delete of your home directory…", TEXT, False)]),
    (3.0, [(SEP, DIM, False)]),
    (3.4, [("Act 2. ", TEXT, True), ("The script exists anyway, and the agent runs it:", TEXT, False)]),
    (3.7, [("    $ bash cleanup.sh", MUTED, False),
           ("        # all a command-string check ever sees", MUTED, False)]),
    (4.3, [("  ✗ DENY ", RED, True),
           ("floor-rm-home-or-root-denied — script cleanup.sh line 3 runs", TEXT, False)]),
    (4.5, [("          `trap 'rm -rf \"$HOME\"' EXIT`. …", TEXT, False)]),
    (5.1, [(SEP, DIM, False)]),
    (5.5, [("Act 3. ", TEXT, True), ("The same delete, obfuscated so no text rule can read it:", TEXT, False)]),
    (5.8, [("    $ eval \"$(echo cm0gLXJmICIkSE9NRSI= | base64 -d)\"", MUTED, False)]),
    (6.4, [("  ✓ ALLOW", GREEN, True), (" provio: allowed by rule \"default\"", TEXT, False),
           ("   # the rules miss it, honestly", YELLOW, False)]),
    (7.1, [("    run it the way provio run runs an agent: inside the kernel write boundary", TEXT, False)]),
    (7.6, [("    filesystem : enforced — writes outside the writable paths are denied by the kernel", DIM, False)]),
    (8.1, [("    rm: cannot remove '…/home/.ssh/id_ed25519': Permission denied", RED, False)]),
    (8.3, [("    rm: cannot remove '…/home/Documents/thesis.md': Permission denied", RED, False)]),
    (8.9, [("  ✓ Home directory intact", GREEN, True),
           ("  — the kernel refused every write outside the workspace", TEXT, False)]),
    (9.5, [(SEP, DIM, False)]),
    (9.9, [("  chain intact · 5 records · no gaps", GREEN, False),
           ("   (provio log, provio verify)", DIM, False)]),
    (10.6, prompt("")),
]


def main() -> None:
    out = pathlib.Path(__file__).resolve().parent.parent / "docs" / "assets"
    out.mkdir(parents=True, exist_ok=True)
    (out / "demo-88462.svg").write_text(
        svg("incident88462", "claude-code#88462, replayed against provio", CAST, width=980),
        encoding="utf-8",
    )
    print(f"wrote {out}/demo-88462.svg")


if __name__ == "__main__":
    main()
