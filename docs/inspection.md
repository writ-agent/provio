# Judged by what it runs

A policy rule reads the tool call: the command line, the path, the query.
The damage is often one step further away. In
[claude-code#88462](https://github.com/anthropics/claude-code/issues/88462)
the command was `bash cleanup.sh`; line 3 of the script the agent had
written was `trap 'rm -rf "$HOME"' EXIT`. A rule that reads the command
string cannot see that.

So before provio records a decision (in `provio check`, for every agent hook
format and the SDKs, and in `provio test` and `provio scan`), it also finds the commands **hidden behind the
call** and judges each one as a `bash` call against the same policy:

| The call | What else is judged |
|---|---|
| `bash x.sh`, `sh -e x.sh`, `source x`, `. x`, `./x` (shell shebang), `pwsh -File x.ps1` | every logical line of the script (continuations joined, comments skipped), and scripts those lines run, up to 3 deep |
| `npm run <name>`, `npm test`, `yarn <name>`, `pnpm <name>`, `bun run <name>` | the `package.json` script, and what it runs |
| `python x.py`, `node x.js` (also `deno`, `bun`, `ruby`, `perl`, `php`) | shell commands in the program's source (below) |
| A file write or edit of a shell script (by extension or shebang) | the lines being written: a dangerous script is refused when it is **written**, before anything runs it |
| A write or edit of `package.json` | its `scripts` values (also in an edit fragment) |
| A write of a Makefile | its recipe lines |
| A Codex `apply_patch` | the added lines of each script file in the patch |
| A heredoc fed to a shell: `bash <<EOF`, `ssh host <<EOF`, `cat <<EOF \| sh` | each line of the heredoc |
| A heredoc written to a script (`cat > x.sh <<EOF`), or to a file the same command then runs (`cat > /tmp/job <<EOF … sh /tmp/job`) | the heredoc, as a script being written |
| A heredoc fed to a database client (`psql <<SQL`) | the SQL, attached to the client's command |
| A heredoc fed to Python, Node, … (`python - <<EOF`) | shell commands in the program (below) |

**Shell commands inside code** are string literals passed to `os.system`,
`os.popen`, `subprocess.run/call/check_call/check_output/Popen`,
`execSync`, `spawnSync`, `child_process.exec`, `execa`, `system`, `exec`,
`shell_exec`, `%x()`, including the `["bash", "-c", "…"]` form; plus
recursive deletes of the home directory or `/` spelled in the language
(`shutil.rmtree(Path.home())`, `fs.rmSync(os.homedir(), { recursive: true })`),
which are judged as `rm -rf ~`.

## Two rules keep this precise

1. **Only an explicit deny or ask counts.** A hidden line that matches no
   rule does not fall to the policy default, so a script full of ordinary
   commands does not become an `ask` under `default: ask`. And a hidden
   command only matters when it is stricter than the call's own verdict.
2. **Heredoc bodies are not command lines.** The command-line rules see the
   command with heredoc bodies taken out; each body is judged by what
   consumes it (the table above). A Markdown file written with
   `cat > notes.md <<EOF`, or a Python program that mentions `rm -rf ~` in a
   string it prints, is text, not shell. `provio scan` over a month of real
   Claude Code sessions (16,000 tool calls) found that heredoc text was the
   largest single source of false positives before this rule.

The verdict names where the command was found, so the agent (and you) can
see why:

```text
DENY  floor-rm-home-or-root-denied  (pack:floor@0.1.0)
      script cleanup.sh line 3 runs `trap 'rm -rf "$HOME"' EXIT`. Recursive delete
      of your home directory, a top-level home folder, or a system root. …
```

The ledger records the call as the agent sent it, with that verdict.

The MCP proxy (`provio proxy`) does not inspect: MCP tools take structured
arguments, not shell.

## What it does not see

Inspection reads files and text; it does not execute anything. It misses:

- **Obfuscation and indirection**: `eval "$(echo cm0gLXJmIH4= | base64 -d)"`,
  commands assembled from variables at run time, `curl … | sh`
  (the floor asks before those instead), downloaded or generated scripts.
- **Changes between the check and the run**: a script is read when the call
  is decided; if something rewrites it before it executes, the new content
  was never judged.
- **Most of what programs do**: only literal shell strings and the home/root
  deletes above are recognised in code. `shutil.rmtree(some_variable)` is
  not.
- **Files it cannot read**: over 1 MiB, unreadable, or not on this machine.
  The call is then decided by its own verdict alone.

This is why provio also has a second, independent layer. An agent launched
with `provio run` sits inside a **kernel write boundary** (Landlock + seccomp,
Seatbelt, a Windows low-integrity token): whatever a script does, it cannot
write outside the workspace and its own state directories. Inspection makes
the policy smarter; the kernel boundary does not depend on it. See
[THREAT_MODEL.md](THREAT_MODEL.md).
