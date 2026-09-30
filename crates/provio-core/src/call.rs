//! Contract 1: the `ToolCall` envelope (interceptors → core) and the derived
//! `ToolCallContext` consumed by policy engines.
//!
//! Every interception mode (MCP proxy, process wrap, SDK hook) must normalise
//! what it sees into a `ToolCall`. Blind-spot metadata is carried explicitly so
//! `provio doctor` can report coverage honestly (spec §6).

use crate::time::Timestamp;
use serde::{Deserialize, Serialize};

/// How the call was captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum InterceptMode {
    /// Mode A: MCP proxy.
    #[default]
    Mcp,
    /// Mode B: OS process wrap (Landlock/seccomp, Seatbelt, restricted tokens).
    ProcessWrap,
    /// Mode C: SDK hook inside the agent framework.
    SdkHook,
}

/// Who is making the call. `non_human_id` is the per-agent identity used in
/// cluster mode (spec §20: per-agent non-human identity).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallerIdentity {
    /// Agent product, e.g. "claude-code", "codex", "langgraph".
    pub agent: String,
    pub agent_version: Option<String>,
    /// Local user or SSO subject.
    pub user: Option<String>,
    pub non_human_id: Option<String>,
}

/// Identity of the MCP server a call targets (mode A only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerIdentity {
    pub name: String,
    /// "stdio" | "sse" | "http"
    pub transport: String,
    pub version: Option<String>,
}

/// External scanner verdict, surfaced as a policy input (spec §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustVerdict {
    Verified,
    Unverified,
    Malicious,
}

/// The intercepted tool call. Credentials must NEVER appear in `args`:
/// provio-mcp injects them at dispatch, after the ledger record is written.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub call_id: String,
    pub session_id: String,
    pub caller: CallerIdentity,
    pub mode: InterceptMode,
    /// Tool name as the agent sees it, e.g. "bash", "postgres.query".
    pub tool: String,
    pub args: serde_json::Value,
    pub server: Option<ServerIdentity>,
    pub trust: Option<TrustVerdict>,
    pub captured_at: Timestamp,
}

/// Flattened, evaluation-ready view of a `ToolCall`. This is the vocabulary
/// of the policy DSL (`tool`, `command`, `path`, `url.host`, `query`,
/// `server`, `server.trust`). Policy engines receive this, not raw args.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ToolCallContext {
    pub tool: String,
    pub command: Option<String>,
    pub path: Option<String>,
    pub url_host: Option<String>,
    pub query: Option<String>,
    pub server: Option<String>,
    pub trust: Option<String>,
    pub mode: InterceptMode,
    pub agent: String,
}

impl ToolCallContext {
    /// Extract well-known fields from tool arguments. Conservative: unknown
    /// argument shapes simply leave fields `None`; rules referencing them
    /// do not match (fail-closed is handled by the policy default, not here).
    pub fn from_call(call: &ToolCall) -> Self {
        let get_str = |keys: &[&str]| -> Option<String> {
            keys.iter().find_map(|k| {
                call.args
                    .get(*k)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
        };
        let url_host = get_str(&["url", "uri"]).and_then(|u| extract_host(&u));
        ToolCallContext {
            tool: call.tool.clone(),
            command: get_str(&["command", "cmd"]),
            path: get_str(&["path", "file_path", "file"]),
            url_host,
            query: get_str(&["query", "sql"]),
            server: call.server.as_ref().map(|s| s.name.clone()),
            trust: call
                .trust
                .and_then(|t| serde_json::to_value(t).ok())
                .and_then(|v| v.as_str().map(|s| s.to_string())),
            mode: call.mode,
            agent: call.caller.agent.clone(),
        }
    }
}

/// Minimal scheme/host split; avoids a URL crate dependency in the contract crate.
fn extract_host(url: &str) -> Option<String> {
    let no_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let host = no_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");
    // Reject empties and anything that plainly isn't a host (spaces, etc.).
    if host.is_empty()
        || host
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '<' | '>' | '"' | '\''))
    {
        None
    } else {
        Some(host.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_host_from_url() {
        assert_eq!(
            extract_host("https://api.github.com/x"),
            Some("api.github.com".into())
        );
        assert_eq!(
            extract_host("http://a.internal:8080/p?q=1"),
            Some("a.internal".into())
        );
        assert_eq!(extract_host("not a url"), None);
    }

    #[test]
    fn context_extracts_wellknown_args() {
        let call = ToolCall {
            call_id: "c1".into(),
            session_id: "s1".into(),
            caller: CallerIdentity {
                agent: "claude-code".into(),
                agent_version: None,
                user: None,
                non_human_id: None,
            },
            mode: InterceptMode::Mcp,
            tool: "bash".into(),
            args: serde_json::json!({"command": "rm -rf /"}),
            server: None,
            trust: None,
            captured_at: Timestamp::now(),
        };
        let ctx = ToolCallContext::from_call(&call);
        assert_eq!(ctx.tool, "bash");
        assert_eq!(ctx.command.as_deref(), Some("rm -rf /"));
    }
}
