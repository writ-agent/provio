//! MCP over HTTP: the Streamable HTTP proxy (agent-facing server and
//! upstream client) plus the building blocks it is made of.
//!
//! * [`server`] — a small blocking HTTP/1.1 server that can flush SSE
//!   events one by one.
//! * [`sse`] — the SSE codec.
//! * [`upstream`] — Streamable HTTP / legacy HTTP+SSE clients.
//! * [`gateway`] — [`HttpProxy`]: the proxy itself. Every `tools/call` goes
//!   through the same [`crate::Interceptor`] as the stdio proxy.

pub mod gateway;
pub mod server;
pub mod sse;
pub mod upstream;

pub use gateway::{HttpProxy, HttpProxyOptions, HEADER_MISMATCH_CODE, PROVIO_UPSTREAM_ERROR_CODE};
pub use server::{Limits, ShutdownHandle};
pub use upstream::{
    AutoUpstream, LegacySseUpstream, Reply, StreamableUpstream, Upstream, UpstreamError,
    UpstreamOptions,
};
