# provio-sdk

Python integrations for [provio](https://github.com/writ-agent/provio/blob/main/README.md). Every tool call an agent makes
is checked against `provio.yaml` (allow / deny / ask / redact) before the tool
runs, and recorded to provio's hash-chained ledger.

The package has no runtime dependencies. It starts `provio check --stdio` as a
long-lived child process and speaks the hook-gateway protocol
([`docs/INTERFACES.md`, Contract 6](https://github.com/writ-agent/provio/blob/main/docs/INTERFACES.md)). Framework
integrations import their framework only when you import them.

## Install

> The `provio` binary comes with it: `provio-sdk` depends on
> [`provio`](https://pypi.org/project/provio/), whose platform wheels carry
> the prebuilt binary. No Rust toolchain or repository checkout is needed.

```bash
pip install provio-sdk                     # core: ProvioClient, Provio, @provio_tool
pip install "provio-sdk[langgraph]"        # + LangGraph / LangChain
pip install "provio-sdk[openai-agents]"    # + OpenAI Agents SDK
pip install "provio-sdk[claude-agent-sdk]" # + Claude Agent SDK
```

You also need the `provio` binary. The client looks for it in this order: the
`binary=` argument, the `PROVIO_BIN` environment variable, then `provio` on `PATH`.
`policy=` / `ledger=` become `--policy` / `--ledger`; otherwise provio uses
`./provio.yaml` and `./.provio/ledger.jsonl` relative to the child's `cwd`.

## Fail closed

The tool does not run unless provio answers `dispatch: true`. Every failure
raises a `ProvioError` subclass, and each framework integration turns that into
a refusal the model can read:

| Situation                                        | Result                          |
|--------------------------------------------------|---------------------------------|
| `deny` verdict                                   | `ProvioDenied` (rule, reason, `provio.yaml:LINE`) |
| `ask`, approver rejects / times out / raises     | `ProvioApprovalRejected`          |
| `ask` with `--ask deny` (the default)            | `ProvioApprovalRejected`          |
| provio binary missing or cannot start              | `ProvioUnavailable`               |
| `provio check` exits while a request is waiting    | `ProvioGatewayCrashed`            |
| no answer within `timeout` (child is killed)     | `ProvioTimeout`                   |
| non-JSON line, wrong id, contradictory response  | `ProvioProtocolError`             |
| `{"error": ...}` response                        | `ProvioGatewayError`              |
| `complete` fails after the tool ran              | output withheld from the model  |
| `redact` verdict but no redacted output returned | output withheld from the model  |

A request is never retried: a retried `decide` could write a second Decision
record for one call. A crashed gateway is restarted on the next request, up to
`max_restarts` (default 3) per `restart_window` (60 s); past that the client
refuses to start provio again.

## Core API

```python
from provio_sdk import Provio, provio_tool

provio = Provio(policy="provio.yaml", session_id="run-42")   # one provio check process

@provio.tool("fs.read")                 # the tool name your policy matches on
def read_file(path: str) -> str:
    return open(path).read()

read_file("README.md")                # decide -> run -> complete; ProvioDenied if refused
safe = provio.guarded(lambda command: ..., name="bash")
provio.execute("postgres.query", {"query": sql}, lambda: db.run(sql))  # redact -> redacted text
```

The sequence is always: `decide`; for a deferred ask, the `approver` plus
`resolve`; run; `complete`. For a `redact` verdict the value returned is the
redacted **text** provio sends back, not the original object.

`ProvioClient` / `AsyncProvioClient` expose the raw protocol (`decide`, `resolve`,
`complete`) with typed `Decision` / `Completion` results. Both are thread-safe
and share one child process; `close()` (or `with`) closes its stdin and waits
for it to exit, and an `atexit` hook closes anything left open.

### Approvals

With no approver, `Provio` runs `--ask deny`: every `ask` fails closed. Give it
an approver and it runs `--ask defer`; the approver sees the call and the
rule's diff, and its answer goes to provio with `resolve`:

```python
from provio_sdk import Approval, Provio

def approve(req):                      # sync or async
    print(req.decision.rule_id, req.diff, req.call.args)
    return Approval(input("run it? [y/N] ") == "y", approver="human:alice")

provio = Provio(approver=approve, approval_timeout=120)   # timeout -> rejected
```

Anything other than `True` / `Approval(True, ...)` rejects, as do exceptions
and timeouts (default: the rule's `timeout_ms`, else 300 s).

## LangGraph / LangChain

Integration point: `ToolNode(wrap_tool_call=..., awrap_tool_call=...)`.
ToolNode hands every tool call to the wrapper with an `execute` callable; the
wrapper asks provio first. A blocked call becomes a `ToolMessage(status="error")`
with provio's reason, so the model sees the refusal and the graph keeps going.
The session id is the graph's `thread_id`.

```python
from langchain_core.tools import tool
from langgraph.prebuilt import tools_condition
from provio_sdk import Provio
from provio_sdk.langgraph import provio_tool_node

@tool
def read_file(path: str) -> str:
    """Read a file."""
    return open(path).read()

provio = Provio()
graph.add_node("tools", provio_tool_node([read_file], provio))   # instead of ToolNode([...])
graph.add_conditional_edges("model", tools_condition)
app = graph.compile(); app.invoke(inputs, {"configurable": {"thread_id": "t-1"}})
```

`provio_tool_node` accepts every `ToolNode` argument; your own `wrap_tool_call`
runs outside provio's, so provio decides on the request as it will execute. It
can also be passed as `tools=` to `create_react_agent`. For tools invoked
outside a ToolNode, `guard_tool(tool, provio)` wraps a single `BaseTool` (use
one or the other, not both: each records its own decision). For a redact
verdict the `ToolMessage` content is replaced and its `artifact` dropped; a
`Command` result under a redact rule is withheld.

## OpenAI Agents SDK

Integration point: each `FunctionTool`'s `on_invoke_tool`, wrapped. That is
the call `Runner` awaits to execute a tool, so the wrapper can decide before
the tool body runs, record `complete`, and substitute the redacted output.
`RunHooks.on_tool_start` cannot refuse a single call (its return value is
ignored; raising aborts the run), and tool input guardrails see no output, so
they cannot carry a redact verdict.

```python
from agents import Agent, RunConfig, Runner, function_tool
from provio_sdk import Provio
from provio_sdk.openai_agents import guard_agent

@function_tool
def read_file(path: str) -> str:
    """Read a file."""
    return open(path).read()

provio = Provio()
agent = guard_agent(Agent(name="coder", tools=[read_file]), provio)
result = await Runner.run(agent, "read README.md", run_config=RunConfig(group_id="t-1"))
```

A blocked call returns provio's refusal as the tool result. Session id:
`session_id=` (string or `ctx -> str`), else `RunConfig.group_id`, else a
`session_id` on your run context, else the `Provio`'s. `guard_agent` refuses
agents with tools it cannot gate (hosted tools, `mcp_servers`) unless you pass
`strict=False`; put MCP servers behind `provio proxy --mcp` instead. Handoff
targets are separate agents: guard each one. `guard_function_tool` wraps a
single tool.

## Claude Agent SDK

Integration point: SDK hooks. `PreToolUse` decides (allow / deny with provio's
reason), `PostToolUse` records `complete` and, for a redact verdict, returns
`updatedToolOutput` with the redacted result, `PostToolUseFailure` records the
failure. `can_use_tool` is not used: the CLI only consults it when its own
permission rules would prompt, and it has no post-execution step.

```python
from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
from provio_sdk import Provio
from provio_sdk.claude_agent_sdk import provio_hooks

provio = Provio()
options = ClaudeAgentOptions(hooks=provio_hooks(provio))
async with ClaudeSDKClient(options) as client:
    await client.query("list the repo and summarize README.md")
    async for message in client.receive_response():
        print(message)
```

Tool names are mapped exactly as `provio check --format claude-code` maps them
([`toolmap.py`](https://github.com/writ-agent/provio/blob/main/adapters/python/src/provio_sdk/toolmap.py)), so one `provio.yaml` covers Claude
Code and the SDK:

| Claude tool                                   | provio `tool`  | policy field           |
|-----------------------------------------------|--------------|------------------------|
| `Bash`, `PowerShell`                          | `bash`       | `command`              |
| `Read`, `Glob`, `Grep`, `LS`, `NotebookRead`  | `fs.read`    | `path` (from `file_path`) |
| `Write`, `Edit`, `MultiEdit`, `NotebookEdit`  | `fs.write`   | `path` (from `file_path` / `notebook_path`) |
| `WebFetch`                                    | `http`       | `url` (`url.host`)     |
| `WebSearch`                                   | `web.search` | `query`                |
| `mcp__<server>__<tool>`                       | `<tool>`     | `server = <server>`    |
| anything else                                 | unchanged    | unchanged              |

Redacted output keeps the tool's output shape (Claude Code rejects a
mismatched `updatedToolOutput` for built-in tools); if the redacted result
cannot be parsed back into the same shape, every string in the output is
masked. The hooks never raise; any adapter failure answers `deny`.

## Development

```bash
python -m venv .venv && .venv/Scripts/python -m pip install -e ".[dev]"   # bin/ on POSIX
.venv/Scripts/python -m pytest
PROVIO_E2E=1 PROVIO_BIN=/path/to/provio .venv/Scripts/python -m pytest tests/test_e2e_provio.py
```

Unit tests run against `tests/fake_provio.py`, a small Contract 6 gateway that
picks verdicts by tool name and can misbehave on request (malformed lines,
hangs, crashes, contradictions). Framework tests use each framework's real
runtime with a scripted model: a LangGraph `StateGraph`, the Agents SDK's
`agents.testing.ScriptedModel`, and a scripted stand-in for the Claude Code
CLI behind the SDK's `Transport`. No network, no API keys. The e2e module is
skipped unless `PROVIO_E2E=1`; it builds nothing and uses `PROVIO_BIN`.

Tested with Python 3.14, langgraph 1.2.12 / langchain-core 1.6.4,
openai-agents 0.22.3, claude-agent-sdk 0.2.157. Requires Python >= 3.10.

## License

Apache-2.0. See [LICENSE](https://github.com/writ-agent/provio/blob/main/adapters/python/LICENSE).
