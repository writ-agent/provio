# Turnloom

[Turnloom](https://github.com/bhaskargurram-ai/turnloom) is a local coding
workbench with its own agent loop. provio decides every tool call that loop
makes: shell commands, workspace reads and MCP tool calls. It uses the Python
SDK (`provio-sdk`), so the decision point is the same `provio check --stdio`
gateway as every other SDK integration ([Contract 6](../INTERFACES.md)).

## Setup

```sh
pip install "turnloom[guard]"   # brings provio-sdk and the provio binary
provio init                     # or create provio.yaml in Turnloom Studio's Policy view
turnloom run "Fix the failing test"
```

Turnloom turns the gate on whenever the workspace has a `provio.yaml`. It
prints `Provio policy gate on` at start. `--no-gate` skips it for one run.

## Mapping

| Turnloom tool | provio `tool` | args |
|---|---|---|
| `shell` | `bash` | `command` |
| `workspace` (list, read, search) | `fs.read` | `path` (absolute), `action` |
| `mcp_call` | the MCP tool's own name, with `server` | the tool's arguments |
| `mcp_search`, `recall` | not sent | read Turnloom's own catalog and archive |

The caller is recorded as `agent: turnloom` with Turnloom's version, and the
session id is the id of the Turnloom transcript, so a ledger session lines up
with one `.turnloom/<id>.jsonl` trace.

## Verdicts

| Verdict | Terminal, interactive | Terminal with `--yes` | Studio |
|---|---|---|---|
| `deny` | not run; the model reads the rule and reason | same | same; the call is marked blocked in the activity log |
| `ask` | the operator is asked, seeing the command | refused (nobody to ask) | the approval card shows the rule and reason |
| `allow` | the operator still confirms | runs | depends on the mode below |
| `redact` | the model receives the redacted text | same | same |

Studio has three modes, chosen in its Policy view: **Confirm every call**
(provio refuses what it denies and the operator approves everything else),
**Let the policy decide** (allowed calls run without a prompt; only `ask`
verdicts reach the operator), and **Gate off**.

## Residual risks

- Turnloom's shell tool runs with the operator's permissions and is not inside
  provio's kernel boundary. Launch Turnloom with `provio run -- turnloom ...`
  for that boundary.
- Studio's own panels (the editor, document verification, the undo ledger) act
  for the operator and are not agent tool calls, so they are not sent to provio.
- The gate fails closed: when provio is missing or does not answer, the tool
  does not run. A workspace with a `provio.yaml` and no provio installed stops
  with an install hint instead of running ungoverned.
