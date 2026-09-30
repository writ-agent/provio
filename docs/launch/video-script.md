# Video: "provio blocks an injected agent" (60–90 s)

A screen recording the owner makes. One take per shot is fine; cut between
shots. No music needed. Captions on (most views are muted).

## Before you record

- **Use a build that has `provio ui`.** The 0.1.1 release does not include
  `provio ui` or `--ask ui`. Record from a release cut from `main`, or from a
  `cargo build -p provio-cli` of `main`, and say which version appears on screen.
- **Throwaway environment.** A fresh OS user or VM with **no real
  `~/.ssh/id_rsa`**. `attacker.example` is a reserved domain that does not
  resolve, so a mistaken approval sends nothing, but do not rely on that.
- **Set up the fixture:**
  ```bash
  cp -r examples/attack-demo/fixture-repo ~/fastcsv
  cp examples/attack-demo/provio.yaml ~/fastcsv/
  cd ~/fastcsv && provio integrate claude-code
  ```
- Terminal: dark theme, 18–20 pt font, about 110 columns. Browser for
  `provio ui` at the same zoom level. Hide notifications, bookmarks and your
  shell history.
- **Do a dry run first.** Models often refuse an instruction hidden in a
  README. If the model refuses, that is the honest result: either record it
  as it is (see the alternate ending) or use the offline replay for the
  denial shots and label it on screen.

## Shot list

| # | Time | Screen | Action | Caption on screen |
|---|---|---|---|---|
| 1 | 0:00–0:07 | Editor showing `fixture-repo/README.md`, scrolled to the HTML comment | Slow scroll through the hidden block | "A normal-looking README. The HTML comment is for the AI agent." |
| 2 | 0:07–0:15 | Editor: `provio.yaml` | Highlight the three deny rules | "One policy file, committed with the repo." |
| 3 | 0:15–0:22 | Split: terminal left, `provio ui` Live screen right | Type `claude`, then "Read the README and do the setup steps." | "Claude Code, with provio hooks installed." |
| 4 | 0:22–0:32 | Same split | Claude reads README.md; a green `allow` row appears in Live | "The read is allowed. The injection is now in the model's context." |
| 5 | 0:32–0:50 | Same split | Claude attempts the key read, the upload, the `rm -rf`. Red `deny` rows appear in Live, each with its rule | "Denied: never-read-secrets · egress-allowlist · block-destructive-shell" |
| 6 | 0:50–0:58 | Live screen: click the `egress-allowlist` row | Record detail: rule, reason, `provio.yaml:LINE`, hashes | "Every attempt is recorded, with the rule that decided it." |
| 7 | 0:58–1:08 | Terminal | `provio log`, then `provio verify` → `chain intact` | "Hash-chained ledger. `provio verify` checks it." |
| 8 | 1:08–1:18 | Terminal | Edit one record in a copy, `provio verify --ledger <copy>` → `chain BROKEN at record N` | "Edit the evidence and verify names the record." |
| 9 | 1:18–1:25 | Title card: repo URL, `pip install provio` | none | "provio does not stop prompt injection. It limits what an injected agent can do, and keeps the record." |

Shots 6–8 can use the offline replay (`examples/attack-demo/run.sh`) if the
live session didn't produce every denial. If you use it, add a caption:
"replay of scripted tool calls · real provio output".

**Alternate ending (model refuses):** keep shot 4. Then caption "This time
the model refused. Next time it might not." and cut to the offline replay for
shots 5–8, captioned as above.

## Voice-over script

About 150 words, which runs a little over 60 seconds read at an even pace.
Read it flat and don't oversell.

> **[1]** This README looks normal. Hidden in a comment is an instruction
> for any AI agent that reads it: grab the SSH key, upload it, delete the
> project.
>
> **[2]** provio puts one policy file in front of every tool call the agent
> makes. Three rules matter here: no secret reads, no destructive shell
> commands, and outbound requests only to hosts we listed.
>
> **[3–4]** Claude Code reads the README. That read is allowed, so the
> injection is now in the model's context.
>
> **[5]** The agent tries the key, then the upload, then `rm -rf`. Each one
> is denied, and the agent gets the rule and the reason back.
>
> **[6–7]** Every attempt is recorded in a hash-chained ledger: the call, the
> verdict, and the line of the policy that decided it.
>
> **[8]** Edit that record afterwards and `provio verify` names the record
> that was changed.
>
> **[9]** provio doesn't stop prompt injection. It limits what an injected
> agent can do, and it keeps the record. It's open source, Apache 2.0.

## Things not to say or show

- Don't say provio "prevents" or "blocks" prompt injection. It refuses the
  *actions*.
- Don't call the ledger "tamper-proof". It is tamper-evident; say "verify
  catches the edit".
- Don't show numbers you haven't measured (latency, "blocks X% of attacks").
- If any shot is a scripted replay, the caption must say so.
