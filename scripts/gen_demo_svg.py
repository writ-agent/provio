#!/usr/bin/env python3
"""Generate the animated terminal casts used in the README.

The casts are self-contained SVG (no script, no external refs, no web fonts)
so GitHub's image proxy renders and animates them. Every line of output is
copied from the real CLI renderers -- provio_tui::render_call_line,
provio_tui::gate, provio_cli::cmds::{log,verify,doctor} -- so the README never
shows a screen the binary cannot produce.

    python scripts/gen_demo_svg.py

Writes docs/assets/*.svg. Re-run after changing CLI output.
"""

from __future__ import annotations

import html
import pathlib

# Terminal palette. Dark chrome reads correctly on both GitHub themes.
BG = "#0b0f14"
CHROME = "#11161d"
EDGE = "#1f2731"
DIM = "#7d8590"
TEXT = "#d7e0ea"
GREEN = "#3fb950"
YELLOW = "#d29922"
RED = "#f85149"
CYAN = "#39c5cf"
BLUE = "#79b8ff"
MUTED = "#79838f"

FONT = ("ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,"
        "'Liberation Mono','Courier New',monospace")

CHAR_W = 8.42          # only used to park the cursor; text itself flows
LINE_H = 23
PAD_X = 26
TOP = 70               # first baseline, below the title bar


def svg(name: str, title: str, lines: list, width: int = 900) -> str:
    """lines: (delay_seconds, spans) or (delay, spans, row).

    spans is a list of (text, color, bold). Only the first span of a line is
    positioned; the rest flow after it, so column alignment comes from literal
    spaces in the text and holds in whatever monospace font the viewer has.
    `row` reuses an earlier text row, which is how a keypress lands on the
    prompt line it answers.
    """
    rows = []
    nxt = 0
    for entry in lines:
        if len(entry) == 3:
            rows.append(entry[2])
        else:
            rows.append(nxt)
            nxt = max(nxt, rows[-1]) + 1
    total = max(d for d, *_ in lines) + 2.4
    height = TOP + LINE_H * (max(rows) + 1) + 26

    css = [
        f"  .t{{font-family:{FONT};font-size:14px;white-space:pre}}",
        "  .r{opacity:0}",
        "  @media (prefers-reduced-motion:reduce){.r{opacity:1;animation:none!important}"
        ".cur{animation:none!important;opacity:1}}",
        "  @keyframes blink{0%,49%{opacity:1}50%,100%{opacity:0}}",
        f"  .cur{{animation:blink 1.06s step-end infinite}}",
    ]
    body = []

    for i, entry in enumerate(lines):
        delay, spans = entry[0], entry[1]
        pct = delay / total * 100
        if pct <= 0:
            css.append(f"  @keyframes k{i}{{0%,100%{{opacity:1}}}}")
        else:
            css.append(
                f"  @keyframes k{i}{{0%,{pct - 0.01:.3f}%{{opacity:0}}"
                f"{pct:.3f}%,100%{{opacity:1}}}}"
            )
        css.append(f"  .l{i}{{animation:k{i} {total:.2f}s infinite}}")
        y = TOP + LINE_H * rows[i]
        parts = []
        for n, (text, color, bold) in enumerate(spans):
            weight = ' font-weight="600"' if bold else ""
            place = f' x="{PAD_X}" y="{y}"' if n == 0 else ""
            parts.append(
                f"<tspan{place} fill=\"{color}\"{weight}>"
                f"{html.escape(text)}</tspan>"
            )
        body.append(f'  <text class="t r l{i}">' + "".join(parts) + "</text>")

    cursor_y = TOP + LINE_H * rows[-1] - 12
    cursor_x = PAD_X + sum(len(t) for t, _, _ in lines[-1][1]) * CHAR_W + 2

    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" \
width="{width}" height="{height}" role="img" aria-label="{html.escape(title)}">
  <style>
{chr(10).join(css)}
  </style>
  <rect width="{width}" height="{height}" rx="10" fill="{BG}" stroke="{EDGE}"/>
  <rect width="{width}" height="38" rx="10" fill="{CHROME}"/>
  <rect y="28" width="{width}" height="10" fill="{CHROME}"/>
  <line x1="0" y1="38" x2="{width}" y2="38" stroke="{EDGE}"/>
  <circle cx="22" cy="19" r="5.5" fill="#ff5f56"/>
  <circle cx="42" cy="19" r="5.5" fill="#ffbd2e"/>
  <circle cx="62" cy="19" r="5.5" fill="#27c93f"/>
  <text class="t" x="86" y="24" fill="{DIM}" font-size="12.5">{html.escape(title)}</text>
{chr(10).join(body)}
  <rect class="cur" x="{cursor_x:.1f}" y="{cursor_y}" width="8" height="16" fill="{TEXT}"/>
</svg>
"""


def prompt(cmd: str):
    return [("$ ", GREEN, True), (cmd, TEXT, False)]


GATE_PROMPT = "  [a]llow  [d]eny  [e]dit  [!] always allow > "

GATE = [
    (0.0, prompt("provio run -- claude")),
    (0.7, [("  provio · 5 rules loaded from provio.yaml · ledger: .provio/ledger.jsonl", DIM, False)]),
    (1.0, [("  mode: process wrap · backend: local-os · coverage: run `provio doctor`", DIM, False)]),
    (1.3, [("", TEXT, False)]),
    (1.9, [("✓ ", GREEN, True), ("read    ", TEXT, False), ("src/api/handlers.rs", BLUE, False)]),
    (2.6, [("✓ ", GREEN, True), ("bash    ", TEXT, False), ("cargo test --lib", BLUE, False)]),
    (3.4, [("◆ ", CYAN, True), ("postgres", TEXT, False),
           ("  SELECT email, ssn FROM users LIMIT 20", BLUE, False), ("  [redact]", CYAN, False)]),
    (3.7, [("  rule: mask-pii (provio.yaml:24) — 2 fields masked before the model sees them",
            MUTED, False)]),
    (4.4, [("", TEXT, False)]),
    (4.9, [("⚠ provio asks: ", YELLOW, True), ("bash rm -rf ./build/../../", TEXT, False),
           ("  [ask]", YELLOW, False)]),
    (5.2, [("  rule: block-destructive-shell (provio.yaml:6)", MUTED, False)]),
    (5.5, [("  → path resolves outside the workspace root", MUTED, False)]),
    (6.1, [(GATE_PROMPT, TEXT, False)]),
    (7.9, [(GATE_PROMPT, TEXT, False), ("d", YELLOW, True)], 12),
    (8.4, [("✗ ", RED, True), ("bash    ", TEXT, False), ("rm -rf ./build/../../", TEXT, False),
           ("  [denied]", RED, False)]),
    (9.1, [("", TEXT, False)]),
    (9.6, [("✗ ", RED, True), ("http    ", TEXT, False),
           ("POST https://paste.ee/api", TEXT, False), ("  [denied]", RED, False)]),
    (9.9, [("  rule: egress-allowlist (provio.yaml:18)", MUTED, False)]),
    (10.2, [("  → host not in hosts.allowed — the refusal goes back to the agent, with the reason",
             MUTED, False)]),
    (11.0, [("", TEXT, False)]),
    (11.4, prompt("")),
]

VERIFY = [
    (0.0, prompt("provio log")),
    (0.6, [("3 sessions · 47 records · 2 denied · 1 sessions with your approvals", TEXT, False)]),
    (0.9, [("session                            records   denied  approved", DIM, False)]),
    (1.1, [("run-4821-1758543012                     31        2  yes", TEXT, False)]),
    (1.3, [("proxy-github-1758546640                 11        0  -", TEXT, False)]),
    (1.5, [("ci-pr-2291                               5        0  -", TEXT, False)]),
    (2.1, [("", TEXT, False)]),
    (2.5, prompt("provio verify")),
    (3.1, [("chain intact · 47 records · no gaps", GREEN, False)]),
    (3.8, [("", TEXT, False)]),
    (4.3, prompt("sed -i '12s/rm -rf/ls/' .provio/ledger.jsonl") +
          [("   # someone edits the evidence", MUTED, False)]),
    (5.3, prompt("provio verify")),
    (5.9, [("chain BROKEN at record 12 · 11 records verified before the break", RED, False)]),
    (6.2, [("exit 1", MUTED, False)]),
    (7.0, prompt("")),
]


def main() -> None:
    out = pathlib.Path(__file__).resolve().parent.parent / "docs" / "assets"
    out.mkdir(parents=True, exist_ok=True)
    (out / "demo-gate.svg").write_text(
        svg("gate", "provio run -- claude", GATE), encoding="utf-8")
    (out / "demo-verify.svg").write_text(
        svg("verify", "provio log · provio verify", VERIFY), encoding="utf-8")
    print(f"wrote {out}/demo-gate.svg and {out}/demo-verify.svg")


if __name__ == "__main__":
    main()
