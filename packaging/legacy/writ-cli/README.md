# writ-cli → provio

**writ is now provio.** Same tool, new name:

```bash
pip install provio
provio scan      # what would provio have caught in your agents' last 30 days?
provio init
```

This final `writ-cli` release installs `provio` and keeps a `writ` command
that runs `provio` with the same arguments (and prints a rename notice;
`PROVIO_QUIET_RENAME=1` silences it). Existing `writ.yaml` and `.writ/`
files are still found. Details: the
[0.1.3 changelog](https://github.com/writ-agent/provio/blob/main/CHANGELOG.md).
