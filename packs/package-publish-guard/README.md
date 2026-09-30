# package-publish-guard

Human gates on publishing packages and container images, and hard blocks on
unpublishing, deprecating and changing package ownership. A published
version is effectively permanent: registries refuse to reuse a version
number, mirrors and caches keep copies, and downstream installs pick it up
within minutes. `--dry-run` publishes are allowed.

| Rule | Verdict | Covers |
|---|---|---|
| `publish-dry-run-allowed` | allow | anchored `npm/pnpm/yarn/bun/cargo/poetry/uv … publish --dry-run` with no shell chaining |
| `publish-npm-unpublish-denied` | deny | `npm/pnpm/yarn/bun unpublish`, `deprecate`, `undeprecate` |
| `publish-registry-ownership-denied` | deny | `npm owner add/rm`, `npm access …`, `npm team add/rm`, `gem owner --add/--remove`, `cargo owner --add/--remove` |
| `publish-npm-asks` | ask, irreversible | `npm/pnpm/bun publish`, `yarn [npm] publish`, `lerna publish`, `changeset publish`, `nx release publish`, `semantic-release`, `npm dist-tag add/rm` |
| `publish-python-asks` | ask, irreversible | `twine upload` (also `python -m twine`), `poetry/uv/flit/hatch/pdm/maturin publish` |
| `publish-cargo-asks` | ask, irreversible | `cargo publish` |
| `publish-yank-asks` | ask | `cargo yank`, `gem yank` |
| `publish-gem-asks` | ask, irreversible | `gem push`, `rake release` |
| `publish-image-push-asks` | ask, irreversible | `docker/podman/buildah/nerdctl push`, `docker compose push`, `image/manifest push`, `buildx build/bake --push`, `crane`, `skopeo copy … docker://`, `oras push`, `ko`, `jib`, `kaniko` |
| `publish-helm-push-asks` | ask, irreversible | `helm push`, `helm cm-push` |
| `publish-other-registries-asks` | ask, irreversible | `dotnet nuget push`, `nuget push`, `choco push`, `mvn deploy`, `gradle publish*`, `Publish-Module/Script/PSResource`, `vsce/ovsx publish`, `dart/flutter pub publish`, `mix hex.publish`, `pod trunk push` |

`publish(\s|$)` is matched as a whole word, so `npm run publish-docs` is not
treated as a publish. `npm run publish` (a script named `publish`) is, which
is usually right.

## What it deliberately does not cover

- **CI pipelines that publish on tag.** `git push --tags` or
  `gh release create` can trigger a release workflow; this pack does not
  guess that. `github-safety` and your branch/tag protection cover the push
  side.
- **Registry targets.** A push to a private or test registry asks just like
  a push to npmjs.org or Docker Hub. Add an earlier allow rule for your
  internal registry host if you want that to pass.
- **Custom scripts** (`make release`, `./scripts/release.sh`) get your
  policy default.
- **Tokens on the command line** (`--token $PYPI_TOKEN`) are not masked
  here; see `secrets-guard`.

## Use it

Packs are rules you merge into your own `provio.yaml`; provio does not load
`.provio/packs/` automatically.

```bash
provio policy add package-publish-guard   # bundled with provio (a local ./packs/<id> wins); prints the sha256
```

Paste the `rules:` entries into your `provio.yaml` above any broad allow of
your own (for example "allow npm in CI"). Ids are prefixed `publish-`.

```bash
provio doctor --policy provio.yaml
provio policy test --policy provio.yaml --fixtures packs/package-publish-guard/fixtures
```

Fixtures: `fixtures/package-publish-guard.yaml` (38 cases, with near misses
such as `npm run publish-docs`, `npm pack`, `docker pull`,
`docker buildx build --load`, `twine check` and
`npm publish --dry-run && npm publish`).
