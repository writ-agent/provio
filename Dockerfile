# provio as an MCP server: `provio mcp serve` on stdio, with read-only tools
# to check a tool call against the policy, list recent decisions and
# sessions, verify the ledger, and show the policy in force.
#
#   docker build -t provio .
#   docker run -i --rm -v "$PWD:/work" provio
#
# Mount a project at /work to use its provio.yaml and .provio/ledger.jsonl;
# without one, calls are judged by the starter packs (floor, secrets-guard).
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p provio-cli --bin provio

FROM debian:bookworm-slim
COPY --from=build /src/target/release/provio /usr/local/bin/provio
WORKDIR /work
ENTRYPOINT ["provio", "mcp", "serve"]
