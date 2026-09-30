# MCP over HTTP: `provio proxy --transport http`

`provio proxy` can sit in front of a remote MCP server that speaks HTTP. The
agent connects to provio at a loopback MCP endpoint, and provio connects to the
real server. Every `tools/call` goes through the same decision pipeline as
the stdio proxy.

```sh
provio proxy --mcp --server github \
  --transport http --listen 127.0.0.1:8931 \
  --upstream https://mcp.example.com/mcp
#   listening: http://127.0.0.1:8931/mcp   <- give this URL to the agent
```

With `--listen 127.0.0.1:0`, provio picks a free port and prints it on the
`listening:` line on stderr.

## Spec versions implemented

Checked against the official specification at
<https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http>
(latest revision, 2026-07-28), and against the earlier session-based revisions
<https://modelcontextprotocol.io/specification/2025-11-25/basic/transports>
(2025-03-26 through 2025-11-25) that most deployed clients and servers speak
today.

provio is a relay: it does not negotiate a protocol version. It forwards what the
agent sends and relays what the server returns, so either revision works end
to end.

| Feature | Behaviour |
|---|---|
| Single MCP endpoint, `POST` of one JSON-RPC message | Yes (default path `/mcp`) |
| Reply as `application/json` or `text/event-stream` | Both, in both directions. SSE events are re-emitted one by one and flushed immediately. Event `id`s, `retry` hints, priming events and keep-alive comments are preserved |
| Notifications and client responses → `202 Accepted` | Relayed from upstream |
| `Mcp-Session-Id` (2025-03-26 … 2025-11-25) | Relayed as-is in both directions. provio does not mint its own session ids |
| `MCP-Protocol-Version` | Forwarded upstream. Also relayed back to the agent if the server sends it |
| `GET` server stream (session era) | Relayed, including server-initiated requests such as `roots/list` and `sampling/createMessage`. The agent's answers are forwarded upstream. A 2026-07-28 server's `405` is relayed |
| `DELETE` (end session) | Relayed. Any `405` from the server is relayed as well |
| Resumability, `Last-Event-ID` (session era) | Header forwarded and event ids preserved. A `tools/call` response replayed on a resumed stream is recognised by (session, id) and goes through the same record and redact path |
| `Mcp-Method` / `Mcp-Name` / `Mcp-Param-*` (2026-07-28) | Forwarded. If `Mcp-Method` or `Mcp-Name` (base64 sentinel decoded) does not match the body, the request is refused with `400` and `-32020 HeaderMismatch` before any decision. Policy decides on the body, so a header/body split is never forwarded |
| `subscriptions/listen` and MRTR `InputRequiredResult` (2026-07-28) | Relayed. A retried `tools/call` carrying `inputResponses` is a new call and gets its own decision |
| Cancellation by closing the response stream (2026-07-28) | When the agent disconnects, provio drops the upstream stream |
| JSON-RPC batches | Accepted only when `MCP-Protocol-Version` is absent or `2025-03-26`, the only revision that allowed them. Batches are refused with `400` otherwise. Each element is decided and forwarded as its own POST, and the responses come back to the agent as one JSON array |
| Legacy HTTP+SSE upstream (2024-11-05) | `--upstream-transport auto` (the default) first POSTs to the URL. If that returns `400`/`404`/`405` without a JSON-RPC error body, provio opens `GET <url>` and waits for the `endpoint` event, as the spec's backward-compatibility section describes. `--upstream-transport sse` forces legacy. The agent still talks Streamable HTTP to provio |
| Legacy HTTP+SSE towards the agent | Not supported. Agents must use Streamable HTTP |

### Legacy upstream limits

- The proxy shares one upstream SSE connection, so one upstream session. If
  the connection drops, provio reconnects on the next request, and the agent
  must initialize again.
- Server-initiated messages are delivered on the agent's `GET` stream. Only
  one `GET` stream is allowed at a time (`409` otherwise). Up to 1024
  messages are buffered while no stream is open.
- `DELETE` answers `405`.
- The `endpoint` event must point at the same origin as the SSE URL. Any other
  origin is refused, because it would receive the injected credentials.

## Governance: identical to stdio

The stdio and HTTP proxies drive the same `provio_mcp::Interceptor`, built by
`cmds::mcp_interceptor`. For each `tools/call`:

1. Policy is evaluated, and `ask` fails closed because the proxy is headless.
   Exactly one decision record is written, before any dispatch.
2. A refusal returns a JSON-RPC error with code `-32043`. It names the rule
   and the reason, and carries `data.provio_refusal = true`. The request is
   never forwarded.
3. On `allow` or `redact`, the body that policy evaluated is re-serialized and
   forwarded. The agent's raw bytes are never forwarded, so JSON parser
   differences cannot split the decision from the execution.
4. The response is read from the JSON body or from the matching SSE event.
   The execution record hashes the **original** result. Redact patterns are
   applied before anything reaches the agent, and that includes
   request-scoped notifications (progress, log messages) on the same stream.
   If a pattern is invalid, the result is withheld.
5. For a `tools/call`, a reply provio cannot parse is withheld and replaced by
   JSON-RPC error `-32044` (fail closed).

If the upstream is unreachable, or a connect, TLS or timeout error occurs, the
agent gets a JSON-RPC error `-32044` (`"… unavailable (fail closed) …"`) with
the request id. Notifications get `502`. The decision record stays in the
ledger. No execution record is written.

Tool calls are recorded with `server.transport` = `streamable-http` or
`http+sse`, and with call ids of the form `<proxy-session>:<seq>:<jsonrpc-id>`.
The HTTP proxy can carry several agent sessions at once, so the JSON-RPC id
alone would not be unique.

## Credentials

Credentials are loaded from the environment, using the same naming as the
stdio proxy: `PROVIO_CRED_<SERVER>_<KEY>`, with the server name uppercased and
dashes turned into underscores. They are injected into **every** upstream
request as headers, at dispatch:

| Variable | Header sent upstream |
|---|---|
| `PROVIO_CRED_GITHUB_BEARER_TOKEN=tok` | `Authorization: Bearer tok` |
| `PROVIO_CRED_GITHUB_HEADER_X_API_KEY=k` | `X-Api-Key: k` (underscores in the name become dashes) |
| any other `PROVIO_CRED_GITHUB_*` | not sent over HTTP (stdio servers receive these as environment variables) |

- The agent's own `Authorization` and `Cookie` headers are **not** forwarded.
  To forward the agent's `Authorization`, pass `--forward-agent-auth`. A
  configured credential header still takes precedence over it.
- Only MCP headers are forwarded upstream: `Mcp-Session-Id`,
  `MCP-Protocol-Version`, `Last-Event-ID`, `Mcp-Method`, `Mcp-Name` and
  `Mcp-Param-*`. Only `Mcp-Session-Id` and `MCP-Protocol-Version` are relayed
  back to the agent.
- Secret values live in `SecretString` and are marked sensitive in the HTTP
  client. They never appear in logs, the ledger or anything returned to the
  agent. The startup banner prints header **names** only.
- Redirects are not followed, so a `3xx` cannot carry credentials to another
  host.
- provio warns when credentials would go over plain `http://` to a
  non-loopback host.
- OAuth discovery through the proxy (`401` → protected-resource metadata) is
  not proxied. Configure the token with `PROVIO_CRED_*` instead.

## Security of the listening side

- **Loopback by default.** A non-loopback `--listen` address is refused
  unless you pass `--allow-remote`. `--allow-remote` in turn requires
  `PROVIO_PROXY_TOKEN`: agents must then send
  `Authorization: Bearer <token>`. The token is compared in constant time and
  is never forwarded upstream. You can also set `PROVIO_PROXY_TOKEN` on
  loopback.
- **DNS rebinding.** Following the MCP spec, a request whose `Origin` is
  present but not allowed gets `403`, with a JSON-RPC error body that has no
  `id`. Loopback origins (`http(s)://localhost|127.x|[::1]`, any port) are
  allowed. Add others with `--allow-origin <origin>` (repeatable).
  Unless `--allow-remote` is set, the `Host` header must also be a loopback
  name. A rebound page's same-origin `GET` carries no `Origin` header, so
  checking `Origin` alone would not catch it.
- **Bounds:**
  - Request header block: 64 KiB.
  - Request body: 4 MiB. Larger bodies get `413`.
  - `Content-Length` and `chunked` sent together are refused.
  - At most 128 concurrent connections (`503` beyond that).
  - Socket read and write timeouts: 30 s.
  - Upstream: connect timeout 10 s; response-headers timeout 300 s
    (`--upstream-timeout`).
  - Upstream JSON bodies: 16 MiB; single SSE events: 16 MiB.
  - Batches: at most 64 elements.
- Requests go only to the configured path (`/mcp`). Other paths get `404`;
  methods other than `GET`/`POST`/`DELETE` get `405`. POST bodies must be
  `application/json` (`415` otherwise).

## Residual risks

- A malicious upstream server can put data anywhere it likes: in tool
  descriptions, in list results, in notifications on the `GET` stream (which
  belong to no call). Redaction masks known patterns in tool results and in
  request-scoped notifications. It is not a boundary against a hostile
  server.
- If the agent can reach the upstream URL directly, it can bypass provio, just
  as it can in stdio proxy mode. See `docs/THREAT_MODEL.md` ("Agent bypasses
  Provio entirely").
- `Mcp-Param-*` headers are forwarded but not validated against the body.
  The 2026-07-28 spec requires the upstream to validate them.

## Implementation

- `crates/provio-mcp/src/http/server.rs`: a small blocking HTTP/1.1 server (a
  thread per connection, with `httparse`) that flushes each SSE event as it
  is written.
- `crates/provio-mcp/src/http/upstream.rs`: `ureq` 3 (rustls + ring,
  webpki-roots; no OpenSSL). Provides the Streamable, legacy SSE and auto
  clients.
- `crates/provio-mcp/src/http/gateway.rs`: the proxy. The `Interceptor` runs
  on a single thread and is fed by a job channel, so decisions and ledger
  writes are serialized exactly as in the stdio proxy.
- `crates/provio-mcp/src/http/sse.rs`: the SSE codec.
