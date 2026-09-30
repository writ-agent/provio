# provio-sdk

TypeScript / Node client for the [provio](https://github.com/writ-agent/provio/blob/main/README.md) hook gateway. Before an
agent's tool call runs, provio checks it against `provio.yaml` (allow / deny / ask /
redact) and records it to provio's hash-chained, tamper-evident ledger.

This package talks to provio over its gateway protocol (`provio check --stdio`,
[INTERFACES.md Contract 6](https://github.com/writ-agent/provio/blob/main/docs/INTERFACES.md)). It spawns one long-lived
`provio check` child process per `ProvioClient`, so there is no daemon to run.

- ESM and CommonJS builds, TypeScript types, Node >= 18, no runtime dependencies.
- `guard()` / `guardTools()`: wrap any tool function or `{ description, parameters, execute }` tool object.
- `provio-sdk/claude-agent-sdk`: `hooks` and `canUseTool` for the Claude Agent SDK.
- **Fails closed.** A missing binary, gateway crash, timeout, malformed line or
  `error` response rejects with a `ProvioError`, and the tool does not run.

## Install

> The `provio` binary comes with it: `provio-sdk` pulls in
> [`provio`](https://www.npmjs.com/package/provio), and npm
> installs only the prebuilt binary for your platform. No Rust toolchain or
> repository checkout is needed.

```sh
npm install provio-sdk
# optional, for the Claude Agent SDK integration
npm install @anthropic-ai/claude-agent-sdk
```

You also need the `provio` binary. The client looks for it in this order:

1. the `bin` option (a path; `.js`/`.mjs`/`.cjs` paths run under Node),
2. the `PROVIO_BIN` environment variable,
3. `provio` on `PATH` (`provio.exe` / `provio.com` on Windows; `.cmd` shims are not accepted).

Or pass `command` / `args` to spawn something else entirely (a wrapper, a test gateway).

## Wrap a tool

```ts
import { ProvioBlockedError, ProvioClient, guard } from "provio-sdk";

const provio = new ProvioClient({ policy: "provio.yaml", caller: { agent: "my-agent" } });

const runQuery = guard(async (input: { query: string }) => db.query(input.query), {
  client: provio,
  tool: "postgres.query", // the name your provio.yaml rules match on
});

try {
  const rows = await runQuery({ query: "select email from users" });
  // With a redact rule, `rows` is provio's redacted output, not the raw result.
} catch (err) {
  if (err instanceof ProvioBlockedError) console.error(err.message); // names rule_id and provio.yaml:LINE
  else throw err;
} finally {
  await provio.close(); // or: await using provio = new ProvioClient(...)
}
```

`guard` runs **decide, then (for a deferred ask) your approver, then the tool,
then complete**:

| provio verdict | what `guard` does |
| --- | --- |
| allow | runs the tool, records it, returns the result |
| deny | throws `ProvioBlockedError`; the tool never runs |
| ask (`ask: "deny"`, default) | throws `ProvioBlockedError` |
| ask (`ask: "defer"`) | calls `approver`; only an explicit `true` / `{ approved: true }` runs the tool. No approver, a throw, or no answer within the ask's `timeout_ms` is a rejection, and the rejection is sent to provio (`resolve`) |
| redact | runs the tool, sends the output to provio, returns provio's redacted output (structured results are re-parsed from the redacted JSON) |

If the gateway fails after the tool ran (the `complete` call), `guard` throws
instead of returning the result, so an unrecorded or unredacted result never
reaches the model.

### Tool objects (Vercel AI SDK and similar)

```ts
import { guardTools } from "provio-sdk";

const tools = guardTools(myTools, { client: provio, toolName: (key) => key });
// each tool's execute is wrapped; the AI SDK's toolCallId becomes provio's call_id
```

## Claude Agent SDK

```ts
import { query } from "@anthropic-ai/claude-agent-sdk";
import { ProvioClient } from "provio-sdk";
import { createProvioIntegration } from "provio-sdk/claude-agent-sdk";

await using provio = new ProvioClient({ ask: "defer" });
const { hooks, canUseTool } = createProvioIntegration({
  client: provio,
  approver: async ({ call, decision }) => askAHuman(call, decision), // optional
});

for await (const msg of query({ prompt: "...", options: { hooks, canUseTool } })) {
  // ...
}
```

What the integration registers (checked against `@anthropic-ai/claude-agent-sdk` 0.3.280 types):

- **`PreToolUse`** sends `decide` and returns
  `hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision, permissionDecisionReason }`:
  `allow` for allow / redact, `deny` for deny (the reason names the rule and
  `provio.yaml:LINE`). Any provio failure also returns `deny`: the hook never throws.
- **Deferred asks** (`ask: "defer"`): with `approver`, the hook asks it inline
  and returns `allow` or `deny`. Without `approver` but with your own
  `canUseTool`, the hook returns `permissionDecision: "ask"`; the SDK then calls
  the returned `canUseTool`, which asks yours and sends the answer to provio.
  An approval that edits the tool input is treated as a rejection, and
  `updatedPermissions` are dropped so an SDK "always allow" rule cannot
  bypass later provio asks. With neither, deferred asks are denied.
- **`PostToolUse`** sends `complete` with the tool response. For redact it
  returns `hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput }`
  with provio's redacted output. If redaction cannot be applied the output is
  replaced with a withheld notice.
- **`PostToolUseFailure`** records the failed execution (`ok: false`).

Use `mergeHooks(hooks, yourHooks)` to combine with your own hooks, and
`onAllow: "passthrough"` if the SDK's own permission rules should still apply
after provio allows a call.

Tool names and inputs are mapped to provio's policy vocabulary, the same way as
`provio check --format claude-code`:

| Claude tool | provio `tool` | policy fields |
| --- | --- | --- |
| `Bash`, `PowerShell` | `bash` | `command` |
| `Read`, `Glob`, `Grep`, `LS`, `NotebookRead` | `fs.read` | `path` (kept, or from `file_path`) |
| `Write`, `Edit`, `MultiEdit`, `NotebookEdit` | `fs.write` | `path` (from `file_path` / `notebook_path`) |
| `WebFetch` | `http` | `url` (so `url.host`) |
| `WebSearch` | `web.search` | `query` |
| `mcp__<server>__<tool>` | `<tool>` | `server` = `<server>` (`mcp_server.name` if sent) |
| anything else | unchanged | |

The original input fields are kept alongside the normalized ones. For
subagent calls the SDK's `agent_id` becomes `caller.non_human_id`. Pass
`mapTool` to change the mapping.

## Client API

```ts
const provio = new ProvioClient({
  policy, ledger,        // forwarded as --policy / --ledger
  ask: "deny",           // or "defer"
  timeoutMs: 30_000,     // per request; a timeout kills the gateway (fail closed)
  caller, sessionId,     // defaults for calls that do not set them
  respawn: true,         // start a fresh gateway after a crash (in-flight calls still fail)
  bin, command, args, cwd, env, onStderr,
});

await provio.decide(call);                  // -> Decision
await provio.resolve(ref, approved, who);   // -> final Decision
await provio.complete(ref, { ok, exit, output }); // -> { recorded, output? }
await provio.authorize(call, { approver }); // decide + approver + resolve
await provio.close();
```

Only `shouldDispatch(decision)` (`dispatch === true` and not `deny`) means the
tool may run. Responses that contradict themselves (for example `deny` with
`dispatch: true`, or a dispatching decision without `ref`) are rejected as
`ProvioProtocolError`.

Never put credentials in tool `args`: args are recorded in the ledger and
visible to policy.

## Development

```sh
npm install
npm run build      # dist/esm + dist/cjs
npm run typecheck
npm run lint
npm test           # unit tests against a fake gateway (test/fixtures/fake-provio.mjs)
PROVIO_E2E=1 PROVIO_BIN=/path/to/provio npm test   # also runs the e2e suite against the real binary
```

## License

Apache-2.0
