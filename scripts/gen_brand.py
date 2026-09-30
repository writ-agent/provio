#!/usr/bin/env python3
"""Generate the provio brand SVGs in docs/assets/brand/ (wordmarks, icon,
README hero). Monoline letterforms: stroke 13 on a 120-unit x-height grid,
round caps and joins, the teal dot as the full stop.

    python scripts/gen_brand.py

PNGs (icon-*.png, social-preview.png) are rendered from these SVGs; see
docs/BRAND.md.
"""

from __future__ import annotations

import pathlib

OUT = pathlib.Path(__file__).resolve().parent.parent / "docs" / "assets" / "brand"
TEAL = "#4ec9a5"
INK_ON_DARK = "#dbe4ec"
INK_ON_LIGHT = "#0b0f14"


def letters(ink: str) -> str:
    """`provio.` on a baseline at y=98, x-height 42..98, descender to 116."""
    return f"""  <g fill="none" stroke="{ink}" stroke-width="13" stroke-linecap="round" stroke-linejoin="round">
    <path d="M12 42 V116"/>
    <circle cx="40" cy="70" r="28"/>
    <path d="M92 98 V42 M92 66 C92 50 104 42 122 42"/>
    <circle cx="162" cy="70" r="28"/>
    <path d="M208 42 L230 98 L252 42"/>
    <path d="M276 98 V42"/>
    <circle cx="324" cy="70" r="28"/>
  </g>
  <circle cx="276" cy="18" r="7.5" fill="{ink}"/>
  <circle cx="374" cy="91" r="10" fill="{TEAL}"/>"""


def wordmark(ink: str) -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 396 124" role="img" aria-label="provio">\n'
        + letters(ink)
        + "\n</svg>\n"
    )


ICON = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" role="img" aria-label="provio">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#131b23"/>
      <stop offset="1" stop-color="#0b0f14"/>
    </linearGradient>
  </defs>
  <rect x="8" y="8" width="496" height="496" rx="116" fill="url(#bg)"/>
  <rect x="8" y="8" width="496" height="496" rx="116" fill="none" stroke="#1e2933" stroke-width="4"/>
  <g fill="none" stroke="{INK_ON_DARK}" stroke-width="46" stroke-linecap="round" stroke-linejoin="round">
    <path d="M168 150 V410"/>
    <circle cx="252" cy="232" r="84"/>
  </g>
  <circle cx="386" cy="360" r="36" fill="{TEAL}"/>
</svg>
"""


def hero() -> str:
    src = (OUT / "hero.svg").read_text(encoding="utf-8")
    head = src[: src.index("  <!-- wordmark -->")]
    tail = src[src.index("  <!-- agent -->"):]
    head = head.replace(
        head[head.index('aria-label="'): head.index('">', head.index('aria-label="')) + 1],
        'aria-label="provio: a safety floor your AI agents can\'t get under. A tool call passes a policy gate (allow, deny, ask, redact) and is recorded in a hash-chained ledger."',
    )
    tail = tail.replace(">writ.yaml<", ">provio.yaml<")
    body = f"""  <!-- wordmark -->
  <g transform="translate(72 64) scale(0.56)">
{letters(INK_ON_DARK)}
  </g>
  <text x="72" y="204" class="sans" font-size="42" font-weight="700" fill="#dbe4ec">A safety floor</text>
  <text x="72" y="252" class="sans" font-size="42" font-weight="700" fill="#dbe4ec">your AI agents</text>
  <text x="72" y="300" class="sans" font-size="42" font-weight="700" fill="#dbe4ec">can't get under<tspan fill="{TEAL}">.</tspan></text>
  <text x="72" y="342" class="sans" font-size="18" fill="#8a99a8">One policy for every agent, checked before every call.</text>
  <text x="72" y="366" class="sans" font-size="18" fill="#8a99a8">Kernel backstop. Signed, tamper-evident ledger.</text>
  <text x="72" y="404" class="mono" font-size="15" fill="#5c6b7a">$ pip install provio &amp;&amp; provio scan</text>

"""
    return head + body + tail


def main() -> None:
    (OUT / "wordmark-light.svg").write_text(wordmark(INK_ON_DARK), encoding="utf-8")
    (OUT / "wordmark-dark.svg").write_text(wordmark(INK_ON_LIGHT), encoding="utf-8")
    (OUT / "icon.svg").write_text(ICON, encoding="utf-8")
    (OUT / "hero.svg").write_text(hero(), encoding="utf-8")
    print("wrote", ", ".join(p.name for p in sorted(OUT.glob("*.svg"))))


if __name__ == "__main__":
    main()
