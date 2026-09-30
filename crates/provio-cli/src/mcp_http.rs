//! `provio proxy --mcp --transport http`: the MCP proxy over Streamable HTTP.
//!
//! Provio listens for the agent on a loopback MCP endpoint and forwards to an
//! upstream MCP server over Streamable HTTP (falling back to the legacy
//! 2024-11-05 HTTP+SSE transport when the upstream speaks only that). Every
//! `tools/call` goes through the same interceptor as the stdio proxy
//! (`cmds::mcp_interceptor`). See docs/mcp-http.md.

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use provio_core::SecretString;
use provio_mcp::http::{
    AutoUpstream, HttpProxy, HttpProxyOptions, LegacySseUpstream, StreamableUpstream, Upstream,
    UpstreamOptions,
};
use provio_mcp::CredentialStore;

use crate::cmds;

/// MCP transport between the agent and provio.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum Transport {
    /// Spawn the downstream server and speak JSON-RPC over its stdio.
    #[default]
    Stdio,
    /// Listen for the agent over Streamable HTTP and forward to an upstream
    /// HTTP MCP server.
    Http,
}

/// How provio talks to the upstream (http transport).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum UpstreamTransport {
    /// Streamable HTTP; fall back to legacy HTTP+SSE per the MCP spec's
    /// detection rule.
    #[default]
    Auto,
    /// Streamable HTTP only.
    Streamable,
    /// Legacy HTTP+SSE (protocol 2024-11-05): `--upstream` is the SSE URL.
    Sse,
}

/// Flags for the HTTP transport (flattened into `provio proxy`).
#[derive(Clone, Debug, Default, clap::Args)]
pub struct HttpArgs {
    /// Transport the agent uses to reach provio.
    #[arg(long, value_enum, default_value_t = Transport::Stdio)]
    pub transport: Transport,
    /// Address to listen on for the agent (http transport). Loopback only
    /// unless --allow-remote.
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:0")]
    pub listen: String,
    /// Upstream MCP server URL (http transport).
    #[arg(long, value_name = "URL")]
    pub upstream: Option<String>,
    /// Allow a non-loopback --listen address. Requires PROVIO_PROXY_TOKEN
    /// (agents must then send `Authorization: Bearer <token>`).
    #[arg(long)]
    pub allow_remote: bool,
    /// Additional browser Origin to accept (loopback origins always are).
    /// Repeatable.
    #[arg(long, value_name = "ORIGIN")]
    pub allow_origin: Vec<String>,
    /// Upstream transport.
    #[arg(long, value_enum, default_value_t = UpstreamTransport::Auto)]
    pub upstream_transport: UpstreamTransport,
    /// Forward the agent's own Authorization header upstream (off by
    /// default; configured credential headers still take precedence).
    #[arg(long)]
    pub forward_agent_auth: bool,
    /// Seconds to wait for the upstream to start answering a request.
    #[arg(long, value_name = "SECS", default_value_t = 300)]
    pub upstream_timeout: u64,
}

impl HttpArgs {
    pub fn is_http(&self) -> bool {
        self.transport == Transport::Http
    }
}

/// Resolve `--listen` and enforce the loopback rule.
fn listen_addr(args: &HttpArgs) -> Result<SocketAddr> {
    let addr = args
        .listen
        .to_socket_addrs()
        .with_context(|| format!("--listen {}", args.listen))?
        .next()
        .ok_or_else(|| anyhow!("--listen {} resolves to no address", args.listen))?;
    if !addr.ip().is_loopback() && !args.allow_remote {
        bail!(
            "--listen {addr} is not a loopback address; pass --allow-remote (with PROVIO_PROXY_TOKEN set) to expose the proxy beyond this machine"
        );
    }
    Ok(addr)
}

/// `scheme://host[:port]/path` without query or userinfo (for display).
fn display_url(url: &str) -> String {
    let no_query = url.split(['?', '#']).next().unwrap_or(url);
    match no_query.split_once("://") {
        Some((scheme, rest)) => {
            let rest = rest.rsplit_once('@').map(|(_, h)| h).unwrap_or(rest);
            format!("{scheme}://{rest}")
        }
        None => no_query.to_string(),
    }
}

fn upstream_host(url: &str) -> &str {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    authority
        .strip_prefix('[')
        .and_then(|a| a.split(']').next())
        .unwrap_or_else(|| authority.split(':').next().unwrap_or(authority))
}

pub fn proxy_http(
    policy: &Path,
    ledger: &Path,
    yolo: bool,
    mcp: bool,
    server: &str,
    args: &HttpArgs,
    pin: bool,
) -> Result<()> {
    if !mcp {
        bail!("only --mcp is supported by provio proxy");
    }
    let upstream_url = args.upstream.as_deref().ok_or_else(|| {
        anyhow!("--transport http needs --upstream <URL> (the upstream MCP endpoint)")
    })?;
    let lower = upstream_url.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        bail!("--upstream must be an http:// or https:// URL");
    }
    let addr = listen_addr(args)?;
    let token = std::env::var("PROVIO_PROXY_TOKEN")
        .ok()
        .filter(|t| !t.trim().is_empty());
    if args.allow_remote && token.is_none() {
        bail!("--allow-remote requires PROVIO_PROXY_TOKEN: a proxy holding injected credentials must not be open to the network");
    }
    if args.forward_agent_auth && token.is_some() {
        bail!("--forward-agent-auth cannot be combined with PROVIO_PROXY_TOKEN (the agent's Authorization header is the proxy token)");
    }

    let engine = cmds::load_engine(policy, yolo)?;
    cmds::banner(&engine, policy, ledger);

    let mut creds = CredentialStore::new();
    creds.load_from_env(server);
    let names = creds.http_header_names(server);
    if !names.is_empty() {
        // Header names only: values never reach a log line.
        eprintln!(
            "  credentials: injecting {} into upstream requests for '{server}' (agent never sees them)",
            names.join(", ")
        );
        let host = upstream_host(upstream_url);
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false);
        if lower.starts_with("http://") && !loopback {
            eprintln!("  \x1b[33mwarning: credentials will cross the network unencrypted (http:// upstream)\x1b[0m");
        }
    }
    let creds = Arc::new(creds);
    let uopts = UpstreamOptions {
        response_timeout: Duration::from_secs(args.upstream_timeout.max(1)),
        ..UpstreamOptions::default()
    };
    let upstream: Arc<dyn Upstream> = match args.upstream_transport {
        UpstreamTransport::Auto => Arc::new(AutoUpstream::new(upstream_url, server, creds, uopts)),
        UpstreamTransport::Streamable => {
            Arc::new(StreamableUpstream::new(upstream_url, server, creds, uopts))
        }
        UpstreamTransport::Sse => {
            Arc::new(LegacySseUpstream::new(upstream_url, server, creds, uopts))
        }
    };

    let core = cmds::mcp_interceptor(engine, ledger, server, upstream.kind(), pin)?;
    let opts = HttpProxyOptions {
        allow_remote: args.allow_remote,
        allowed_origins: args.allow_origin.clone(),
        agent_token: token.map(SecretString::new),
        forward_agent_auth: args.forward_agent_auth,
        ..HttpProxyOptions::default()
    };
    let proxy = HttpProxy::bind(&addr.to_string(), opts, upstream)
        .with_context(|| format!("listen on {addr}"))?;
    eprintln!(
        "  mode: mcp proxy (streamable http) · server: {server} · upstream: {}",
        display_url(upstream_url)
    );
    eprintln!("  listening: {}", proxy.url());
    proxy.run(core);
    eprintln!(
        "  provio · proxy stopped · ledger: {}",
        crate::cmds::show_ledger(ledger)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_url_drops_query_and_userinfo() {
        assert_eq!(
            display_url("https://user:pw@mcp.example.com/mcp?key=secret"),
            "https://mcp.example.com/mcp"
        );
        assert_eq!(
            upstream_host("https://u@mcp.example.com:8443/x"),
            "mcp.example.com"
        );
        assert_eq!(upstream_host("http://[::1]:9/x"), "::1");
    }

    #[test]
    fn non_loopback_listen_needs_allow_remote() {
        let mut a = HttpArgs {
            listen: "0.0.0.0:0".into(),
            ..Default::default()
        };
        assert!(listen_addr(&a).is_err());
        a.allow_remote = true;
        assert!(listen_addr(&a).is_ok());
        a.listen = "127.0.0.1:0".into();
        a.allow_remote = false;
        assert!(listen_addr(&a).is_ok());
    }
}
