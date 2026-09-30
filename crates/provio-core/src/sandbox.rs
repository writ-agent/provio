//! Contract 4: the `SandboxBackend` trait (spec §8).
//!
//! Narrow by design: prepare / exec / collect / teardown. Provio's opinion is
//! about *which* call runs, not *how* it is contained. Adapters (local-os,
//! docker, microsandbox, firecracker/e2b, k8s) ship separately from core and
//! are detected if present (spec §12 correction).

use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// What the sandbox must enforce for one wrapped run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxSpec {
    /// Filesystem root the agent may write inside.
    pub workspace: PathBuf,
    /// Egress allow-list (kernel-enforced where the backend supports it).
    pub allowed_hosts: Vec<String>,
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SandboxId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env: BTreeMap<String, String>,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
    pub duration_ms: u64,
}

/// Best-effort post-execution diff (feeds the ledger's output hash and the
/// approval-gate "what changed" view on replay).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Artifacts {
    pub files_changed: Vec<PathBuf>,
}

pub trait SandboxBackend {
    /// "local-os" | "docker" | "microsandbox" | "firecracker" | "k8s"
    fn name(&self) -> &'static str;

    /// True when this backend's prerequisites exist on this machine
    /// (e.g. docker daemon reachable). Used by `provio doctor`.
    fn available(&self) -> bool {
        true
    }

    fn prepare(&mut self, spec: &SandboxSpec) -> Result<SandboxId>;
    fn exec(&mut self, id: &SandboxId, req: &ExecRequest) -> Result<ExecOutput>;
    fn collect(&mut self, id: &SandboxId) -> Result<Artifacts>;
    fn teardown(&mut self, id: SandboxId) -> Result<()>;
}
