# Launch-day checklist

In order. Don't skip ahead: a broken install on day one costs more than a
day's delay.

## T-3 days: blockers

- [x] **Ship a release that matches the README.** Done: **0.1.2** is on
      PyPI (`provio`, `provio-sdk`), npm (`provio`,
      `provio-sdk`) and GitHub Releases, with every feature the posts
      describe. Verified from clean installs on Windows and Linux (pip and
      npm): `provio ui`, `provio receipt` round trip, all five
      `provio integrate` targets, bundled `provio policy add`.
- [ ] In a clean VM for each OS (Linux, macOS, Windows), from the published
      packages only:
      `pip install provio` → `provio --version` → `provio integrate claude-code`
      → one Claude Code session → `provio log` → `provio verify` → `provio ui`.
- [x] Run `examples/attack-demo/run.sh` (Linux/macOS) and `run.ps1`
      (Windows) against the **published** binary. The expected output is in
      `examples/attack-demo/README.md`. If provio's output changed, update
      the lines in `scripts/gen_attack_svg.py`, re-run it, and re-render
      `docs/launch/demo-attack.png`.
- [x] `python scripts/claim_lint.py` is clean; CI is green on `main`.
- [ ] The repo is public; the README renders `demo-attack.svg` (check it on
      GitHub, in light and dark themes); the site and playground load.
- [x] Name collision: renamed writ → provio (2026-09-30); the name is free
      on GitHub, PyPI, npm and crates.io.
- [ ] `SECURITY.md` has a working private reporting channel (GitHub private
      vulnerability reporting turned on). Launch day brings bypass reports.

## T-2 days: assets

- [ ] Record the video (`video-script.md`) in a throwaway environment with
      no real SSH key. Caption any shot that uses the scripted replay.
- [ ] Export: MP4 (1080p, captions burned in, under 90 s) for X and
      LinkedIn; the PNG `docs/launch/demo-attack.png` as a fallback.
- [ ] Publish the blog post (`blog-post.md`), filling in `<VERSION>`. Check
      every link.
- [ ] Set the GitHub social preview (`docs/assets/brand/social-preview.png`),
      the description and the topics (`ai-agents`, `mcp`, `claude-code`,
      `security`, `policy`, `audit-log`, `rust`).

## Launch day

Pick a weekday. Post the Show HN in the US morning (Pacific time); be at
your keyboard for the six hours after that.

1. [ ] **Show HN** (`show-hn.md`). Link the repo, then post the body as the
       first comment straight away. Don't share the HN link asking for
       upvotes.
2. [ ] Answer every HN comment. Concede valid criticism and link the
       threat model; don't argue.
3. [ ] **X thread** (`x-thread.md`) with the video, 1–2 hours after HN.
4. [ ] **LinkedIn** (`linkedin.md`), the same day.
5. [ ] **r/ClaudeAI** (`reddit.md`), with showcase flair.
6. [ ] Watch the issues. Label and answer install problems first; they
       decide whether someone stays.

## Days 2–7

- [ ] **r/LocalLLaMA** (day 2), **r/netsec** (link to the blog post, day 3
      or later, author comment with the threat model).
- [ ] **Communities** (`communities.md`), one or two a day, each with the
      intro written for that venue. Codex, Gemini, Cursor and Windsurf only
      once the release that includes them is live.
- [ ] **Awesome lists** (`awesome-lists.md`): the owner is submitting these;
      mark in that file which ones went in, and when. awesome-claude-code is
      form-only; awesome-rust needs more than 50 stars first.
- [ ] Collect every "doesn't work with X" and every bypass report into
      issues, and triage them publicly.
- [ ] Write a short follow-up (what people asked, what changed), with no
      invented numbers. If you quote stars or installs, quote them exactly
      and with a date.

## Never, anywhere

- "prevents" or "stops" prompt injection. Say: it limits what an injected
  agent can do.
- "tamper-proof". Say: tamper-evident, and receipts make a rewrite
  detectable.
- Any phrase on the ban list in `scripts/claim_lint.py` (assurance labels,
  certification claims, latency superlatives), and any performance number
  that isn't from a published, reproducible benchmark.
- Testimonials, logos or user counts you can't point to.
- Presenting the scripted replay as a live model session.
