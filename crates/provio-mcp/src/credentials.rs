//! Per-server credential isolation (spec §11): the agent never holds the
//! token — Provio injects it into the downstream server's environment at
//! dispatch. Secrets live in `SecretString`, which cannot be serialized,
//! cloned, or Debug-printed, so they can never reach a ToolCall, a ledger
//! record, or a log line (plan §4.3 invariant).

use std::collections::{BTreeMap, HashMap};
use std::io::BufReader;
use std::process::{Child, Command, Stdio};

use provio_core::{ProvioError, Result, SecretString};

use crate::transport::StreamTransport;

/// server name → (env key → secret value)
#[derive(Default)]
pub struct CredentialStore {
    secrets: HashMap<String, BTreeMap<String, SecretString>>,
}

impl CredentialStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, server: &str, env_key: &str, value: SecretString) {
        self.secrets
            .entry(server.to_string())
            .or_default()
            .insert(env_key.to_string(), value);
    }

    /// Load credentials for `server` from process env vars named
    /// `PROVIO_CRED_<SERVER>_<KEY>` (server uppercased, dashes→underscores).
    pub fn load_from_env(&mut self, server: &str) {
        let prefix = format!("PROVIO_CRED_{}_", server.to_uppercase().replace('-', "_"));
        for (k, v) in std::env::vars() {
            if let Some(key) = k.strip_prefix(&prefix) {
                self.add(server, key, SecretString::new(v));
            }
        }
    }

    pub fn has_any(&self, server: &str) -> bool {
        self.secrets
            .get(server)
            .map(|m| !m.is_empty())
            .unwrap_or(false)
    }

    /// Inject this server's secrets into an environment map about to be used
    /// for a downstream spawn. This is the ONLY path secrets take out of the
    /// store, and it targets a child-process environment — never a message.
    pub fn inject_env(&self, server: &str, env: &mut BTreeMap<String, String>) {
        if let Some(map) = self.secrets.get(server) {
            for (k, v) in map {
                env.insert(k.clone(), v.expose().to_string());
            }
        }
    }
}

impl CredentialStore {
    /// Inject this server's secrets as HTTP request headers for an upstream
    /// (Streamable HTTP / SSE) server. Naming follows `load_from_env`:
    ///
    /// * `PROVIO_CRED_<SERVER>_BEARER_TOKEN=tok` → `Authorization: Bearer tok`
    /// * `PROVIO_CRED_<SERVER>_HEADER_<NAME>=v` → `<Name>: v`, underscores in
    ///   `<NAME>` becoming dashes (`HEADER_X_API_KEY` → `X-Api-Key`).
    ///
    /// Other keys are environment credentials for stdio servers and are not
    /// sent over HTTP. Values containing CR/LF (header injection) and names
    /// that are not HTTP tokens are skipped with a warning naming the key —
    /// never the value. `set` receives the header name and the exposed value
    /// and must write it straight into the outgoing request.
    pub fn inject_http_headers(&self, server: &str, set: &mut dyn FnMut(&str, &str)) {
        let Some(map) = self.secrets.get(server) else {
            return;
        };
        for (key, value) in map {
            let (name, val) = if key == "BEARER_TOKEN" {
                (
                    "Authorization".to_string(),
                    format!("Bearer {}", value.expose()),
                )
            } else if let Some(h) = key.strip_prefix("HEADER_") {
                (header_name_from_env(h), value.expose().to_string())
            } else {
                continue;
            };
            let name_ok = !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
            let val_ok = !val.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0);
            if !name_ok || !val_ok {
                tracing::warn!(server, key = %key, "skipping credential header: invalid name or value");
                continue;
            }
            set(&name, &val);
        }
    }

    /// Header names this server's credentials will set (for banners/logs;
    /// contains no secret material).
    pub fn http_header_names(&self, server: &str) -> Vec<String> {
        let mut names = Vec::new();
        self.inject_http_headers(server, &mut |n, _| names.push(n.to_string()));
        names
    }
}

/// `X_API_KEY` → `X-Api-Key`.
fn header_name_from_env(key: &str) -> String {
    key.split('_')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let lower = p.to_ascii_lowercase();
            let mut c = lower.chars();
            match c.next() {
                Some(f) => f.to_ascii_uppercase().to_string() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// A spawned downstream MCP server: child handle + framed transport.
pub struct StdioServer {
    pub child: Child,
    pub transport: StreamTransport<BufReader<std::process::ChildStdout>, std::process::ChildStdin>,
}

/// Spawn a downstream stdio MCP server with its credentials injected.
/// The child environment is clean (PATH + declared env + injected secrets).
pub fn spawn_stdio_server(
    program: &str,
    args: &[String],
    server_name: &str,
    creds: &CredentialStore,
    extra_env: &BTreeMap<String, String>,
) -> Result<StdioServer> {
    let mut env = extra_env.clone();
    creds.inject_env(server_name, &mut env);

    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .envs(&env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| {
            ProvioError::Intercept(format!("spawn MCP server {server_name} ({program}): {e}"))
        })?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ProvioError::Intercept("child stdout not piped".into()))?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| ProvioError::Intercept("child stdin not piped".into()))?;
    Ok(StdioServer {
        child,
        transport: StreamTransport::new(BufReader::new(stdout), stdin),
    })
}
