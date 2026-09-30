#!/usr/bin/env python3
"""Claim-discipline lint (plan section 8, "Claim discipline" quality gate).

Scans repository text files for unearned-assurance phrases. Every hit is
reported as file:line and the script exits 1; a clean repo exits 0.

Discipline (mirrors the grep job in .github/workflows/ci.yml, extended with
the Wave-4 phrases "military grade", "zero latency" and "unbreakable"):

- Absolute bans - no wording saves them:
    "bank grade", "military grade", "SOC 2 certified/compliant",
    "prevents prompt injection", "sub-millisecond", "zero latency",
    "unbreakable"
- Qualified ban: "tamper-proof" is banned UNLESS the same line also states
  the distinction (evident / not / never / only / without / require / no /
  until). The docs-honesty gate requires the "tamper-evident, not
  tamper-proof" statement verbatim, so the qualified form must stay
  expressible. Run with --strict to ban unqualified-free tamper-proof
  everywhere (then the honesty statements must be rephrased).

Meta files that define the discipline itself are excluded, matching ci.yml's
EXCLUDE list (docs/internal/BUILD_PLAN.md quotes the phrases; ci.yml and the PR
template enforce or describe them), plus this script (it contains the
patterns).

Performance numbers are not checked here: only bench output carries numbers,
and prose must carry none at all.
"""

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Text file extensions scanned (everything the repo authors write by hand).
TEXT_EXTENSIONS = {
    ".css",
    ".html",
    ".js",
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".rs",
    ".sh",
    ".toml",
    ".ts",
    ".txt",
    ".yml",
    ".yaml",
}

# Extensionless text files worth scanning.
TEXT_FILE_NAMES = {"Dockerfile", "LICENSE"}

# Directories never scanned: VCS/ignore targets, fuzz output, runtime state.
EXCLUDED_DIRS = {".git", "target", "node_modules", ".venv", "venv", "dist", "__pycache__", "corpus", "artifacts", "coverage", ".provio"}

# Meta files that define or describe the discipline itself (mirrors ci.yml's
# EXCLUDE list), plus this script, which holds the patterns as data.
EXCLUDED_FILES = {
    "docs/internal/BUILD_PLAN.md",
    ".github/workflows/ci.yml",
    ".github/workflows/fuzz.yml",
    ".github/PULL_REQUEST_TEMPLATE.md",
    "scripts/claim_lint.py",
}

# (pattern, label) pairs; matching is case-insensitive on each line.
ABSOLUTE_BANS = [
    (r"bank[\s-]?grade", "bank grade"),
    (r"military[\s-]?grade", "military grade"),
    (r"SOC[\s-]?2\s+(certified|compliant)", "SOC 2 certified/compliant"),
    (r"prevents?\s+prompt\s+injection", "prevents prompt injection"),
    (r"sub[\s-]?millisecond", "sub-millisecond"),
    (r"zero[\s-]?latency", "zero latency"),
    (r"unbreakable", "unbreakable"),
]

# "tamper-proof" needs a same-line qualifier (see module docstring).
QUALIFIED_BANS = [(r"tamper[\s-]?proof", "tamper-proof")]

QUALIFIER = re.compile(
    r"evident|\bnot\b|\bnever\b|\bonly\b|\bwithout\b|\brequire|\bno\b|\buntil\b",
    re.IGNORECASE,
)


def iter_text_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel.split("/")[0] in EXCLUDED_DIRS:
            continue
        if any(part in EXCLUDED_DIRS for part in rel.split("/")):
            continue
        if rel in EXCLUDED_FILES:
            continue
        if path.suffix.lower() in TEXT_EXTENSIONS or path.name in TEXT_FILE_NAMES:
            yield path


def scan_line(line: str, strict: bool):
    """Yield labels of forbidden phrases found on one line."""
    for pattern, label in ABSOLUTE_BANS:
        if re.search(pattern, line, re.IGNORECASE):
            yield label
    for pattern, label in QUALIFIED_BANS:
        if re.search(pattern, line, re.IGNORECASE):
            if strict or not QUALIFIER.search(line):
                yield label + ("" if strict else " (unqualified)")


def main(argv):
    strict = "--strict" in argv
    hits = []
    for path in iter_text_files(REPO_ROOT):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"warning: could not read {path}: {exc}")
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for label in scan_line(line, strict):
                hits.append((path.relative_to(REPO_ROOT).as_posix(), lineno, label, line.strip()))

    for rel, lineno, label, snippet in hits:
        print(f"{rel}:{lineno}: {label}: {snippet[:120]}")

    if hits:
        print(f"\n{len(hits)} claim-discipline violation(s). Rephrase the wording.")
        return 1
    scope = "strict" if strict else "ci.yml-consistent"
    print(f"claim-discipline lint ({scope}): clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))