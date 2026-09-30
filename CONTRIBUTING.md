# Contributing to Provio

Thanks for helping build the authorization and provenance layer for AI agents.

## Where to start

- The [roadmap](https://github.com/writ-agent/provio/issues/9) is pinned in Issues.
- Issues labelled [`good first issue`](https://github.com/writ-agent/provio/labels/good%20first%20issue) are scoped for a first PR; [`help wanted`](https://github.com/writ-agent/provio/labels/help%20wanted) ones are bigger.
- A new **policy pack** is the most valuable small contribution (see below).
- Questions and ideas go to [Discussions](https://github.com/writ-agent/provio/discussions), not issues.
- `main` is protected: open a PR; CI must pass, and changes under the security
  paths in `.github/CODEOWNERS` need a code-owner review.

## Ground rules

1. **DCO, not CLA.** Sign off every commit: `git commit -s`
   (`Signed-off-by: Your Name <you@example.org>`). This certifies you wrote
   or have the right to submit the change (Developer Certificate of Origin 1.1).
2. **Claim discipline is CI-enforced.** No unearned assurance labels, no
   certification claims about the binary, no performance numbers outside
   published, reproducible benchmarks. See `docs/THREAT_MODEL.md`.
3. **Honesty over hype.** Provio is a governance tool; its docs state what it
   does NOT do as clearly as what it does. Match that standard.

## Build & test

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Crate ownership

Every crate has an owning agent role (see `docs/internal/BUILD_PLAN.md` §5.2).
Changes to the frozen contracts in `provio-core` or `docs/INTERFACES.md`
require an ADR in `docs/DECISIONS.md` and maintainer review.

## Contribute a policy pack

Packs are the flywheel — small, high-value, and each one is a reason for a
new user to arrive. One PR per pack:

1. Add `packs/<your-pack>/pack.yaml` (schema: `id`, `version`, `description`,
   `rules` — see `packs/terraform-safety` for the shape).
2. Rules must compile: `cargo run -p provio-cli -- doctor --policy <file>` after
   wrapping with a `version`/`default` header, or add a fixture under
   `crates/provio-policy/fixtures/`.
3. Every `deny`/`ask` needs a human-readable `reason`.
4. Describe the threat your pack addresses in the PR body.

## Security

Never file security issues publicly. See `docs/SECURITY.md` (72h ack SLA).
