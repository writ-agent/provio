//! writ-mcp — the MCP proxy (interception mode A, spec §6A/§11).
//!
//! Writ is an MCP *server* to the agent and an MCP *client* to the real
//! servers: every `tools/call` is checked against policy before dispatch,
//! tool schemas are auto-discovered, and credentials are injected at spawn
//! so the agent never holds a token.
//!
//! Transports: stdio ([`McpProxy`]) and Streamable HTTP with legacy
//! HTTP+SSE upstream fallback ([`http::HttpProxy`]); both drive the same
//! [`Interceptor`].

#![forbid(unsafe_code)]

pub mod credentials;
pub mod http;
pub mod jsonrpc;
pub mod pins;
pub mod proxy;
pub mod transport;

pub use credentials::{spawn_stdio_server, CredentialStore, StdioServer};
pub use jsonrpc::{
    JsonRpcError, JsonRpcMessage, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, RequestId,
};
pub use proxy::{
    Interception, Interceptor, McpProxy, ProxyConfig, ProxyDecision, WRIT_REFUSAL_CODE,
};
pub use transport::{stdio_transport, MemoryTransport, StreamTransport, Transport};
