//! provio-sandbox-docker — the Docker `SandboxBackend` adapter (spec §8).
//!
//! Runs approved calls inside a user-supplied container image: cgroups v2 +
//! namespaces via the docker daemon (Linux containers; on Windows hosts this
//! goes through Docker Desktop's Linux engine — Windows containers are not
//! supported by this adapter). Provio's opinion is about *which* call runs, not
//! *how* it is contained, so this adapter overclaims nothing (see
//! docs/THREAT_MODEL.md and the honesty notes below):
//!
//! - **Egress.** An empty `allowed_hosts` runs the container with network
//!   mode `none` — that *is* container-level deny-all egress and may be
//!   described as such. A non-empty `allowed_hosts` cannot be honored:
//!   docker provides no hostname-level egress filtering out of the box, so
//!   `prepare` fails closed with a precise error instead of silently allowing
//!   full network. Per-host enforcement needs a docker network + iptables
//!   setup that this adapter does not build (follow-up, not a hidden default).
//! - **Env.** The exec environment is the image's own environment plus the
//!   run-declared vars ([`SandboxSpec::env`] then [`ExecRequest::env`], req
//!   wins). The host environment is never forwarded — that is the isolation
//!   property this backend provides where `local-os` only clears to a
//!   baseline.
//! - **Container lifecycle.** `prepare` creates the container with the
//!   image's `CMD` overridden by a keep-alive ([`KEEPALIVE_CMD`]) so exec
//!   sessions have a running container to attach to (a plain `docker run -d
//!   alpine` exits immediately); programs the agent runs go through docker
//!   exec, not the container main process. `exec` timeouts are enforced by
//!   killing the CLI client and *stopping the container*: the docker API
//!   offers no way to kill a single exec'd process, so a timed-out sandbox
//!   must be prepared again. `teardown` stops and force-removes the
//!   container, idempotent on an already-removed one.
//! - **Mechanism.** This backend drives the `docker` CLI (found on `PATH`,
//!   honoring the CLI's own `DOCKER_HOST`/context configuration) rather than
//!   a library client. Bollard — the natural async client — does not build
//!   in the reference environment: its tokio → windows-sys 0.61 chain needs
//!   raw-dylib import libraries and this GNU toolchain's dlltool cannot
//!   spawn an assembler (`dlltool.exe: CreateProcess`, ADR-007), and the
//!   `icu_normalizer_data` build script it pulls in via url → idna is
//!   blocked by a Windows Application Control policy (os error 4551). The
//!   CLI path has zero FFI/build-script surface; migrating to bollard is a
//!   follow-up for environments without those constraints.
//! - **Not applied (honest gaps).** Capabilities are not dropped (docker
//!   `--cap-drop ALL` would harden further); the rootfs stays writable
//!   outside the workspace bind mount (writes there are still diffed by
//!   `collect`).

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use provio_core::error::{ProvioError, Result};
use provio_core::sandbox::{
    Artifacts, ExecOutput, ExecRequest, SandboxBackend, SandboxId, SandboxSpec,
};

/// Where the workspace bind mount lives inside the container.
pub const CONTAINER_WORKSPACE: &str = "/workspace";

/// `SandboxSpec::env` key that overrides the image for one prepared sandbox,
/// taking precedence over the image configured via
/// [`DockerSandboxBackend::with_image`].
pub const IMAGE_ENV_KEY: &str = "PROVIO_DOCKER_IMAGE";

/// Image used when neither the backend nor the sandbox spec names one.
pub const DEFAULT_IMAGE: &str = "alpine:3.20";

/// The image `CMD` is overridden with this so the container stays up for exec
/// sessions. Every entrypoint-less base image ships `sleep`; images whose
/// `ENTRYPOINT` semantics matter for the main process are not suited to this
/// backend as-is.
const KEEPALIVE_CMD: [&str; 2] = ["sleep", "infinity"];

/// The CLI binary this backend drives.
const DOCKER_BIN: &str = "docker";

/// Parity with the local-os backend: 10 minutes when the request says nothing.
const DEFAULT_EXEC_TIMEOUT_MS: u64 = 600_000;

/// Bound on `available()` so `provio doctor` cannot hang on a half-dead daemon.
const PING_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound for quick daemon round-trips (start/stop/remove/diff).
const DAEMON_CALL_TIMEOUT: Duration = Duration::from_secs(60);

/// Bound for `docker create`/`pull`: a first pull of the image happens inside
/// the create call, so this must fit a full image download.
const PULL_TIMEOUT: Duration = Duration::from_secs(600);

/// Resource limits applied to every sandbox container. Docker enforces these
/// via cgroups (memory, pids controllers) and the scheduler (`--cpus`).
/// Unset fields pass through to docker's own defaults; the modest
/// `pids_limit` default is the one limit that never breaks ordinary agent
/// workloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Max processes/threads in the container (`--pids-limit`).
    pub pids_limit: Option<i64>,
    /// Memory limit in bytes (`--memory`).
    pub memory_bytes: Option<i64>,
    /// CPU quota as CPU cores (`--cpus`; docker's `NanoCpus` divided by 1e9).
    pub nano_cpus: Option<i64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        ResourceLimits {
            pids_limit: Some(512),
            memory_bytes: None,
            nano_cpus: None,
        }
    }
}

/// What a prepared sandbox remembers between calls. `SandboxId` *is* the
/// docker container id, so exec/collect/teardown all key off the daemon
/// directly; the record only carries what the daemon cannot tell us back.
#[derive(Debug, Clone)]
struct ContainerRecord {
    /// Canonicalized host path of the workspace (the bind mount source).
    workspace: PathBuf,
    /// Spec-declared env forwarded to every exec (under request env).
    env: BTreeMap<String, String>,
}

/// The Docker backend (`name() == "docker"`). Detected, never required
/// (spec §12): `available()` reports whether a daemon is actually reachable.
#[derive(Debug, Clone)]
pub struct DockerSandboxBackend {
    image: String,
    limits: ResourceLimits,
    containers: HashMap<SandboxId, ContainerRecord>,
    next_seq: u64,
}

impl DockerSandboxBackend {
    /// Backend with the default image ([`DEFAULT_IMAGE`]), overridable per-run
    /// via the `PROVIO_DOCKER_IMAGE` key in the sandbox spec's env.
    pub fn new() -> Self {
        DockerSandboxBackend::with_image(DEFAULT_IMAGE)
    }

    /// Backend pinned to a specific image (e.g. `"rust:1-slim"`); the sandbox
    /// spec's `PROVIO_DOCKER_IMAGE` env key still wins over this.
    pub fn with_image(image: impl Into<String>) -> Self {
        DockerSandboxBackend {
            image: image.into(),
            limits: ResourceLimits::default(),
            containers: HashMap::new(),
            // Seed from the clock so two backend instances in one process
            // cannot collide on the generated container name.
            next_seq: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos() as u64)
                .unwrap_or(0),
        }
    }

    /// Consuming builder for [`ResourceLimits`] (docker applies these via
    /// cgroups — see the struct docs).
    pub fn with_limits(mut self, limits: ResourceLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Image precedence: spec env `PROVIO_DOCKER_IMAGE` > backend image >
    /// [`DEFAULT_IMAGE`]. An empty override counts as unset.
    fn image_for(&self, spec: &SandboxSpec) -> String {
        spec.env
            .get(IMAGE_ENV_KEY)
            .filter(|image| !image.is_empty())
            .cloned()
            .unwrap_or_else(|| self.image.clone())
    }

    fn record(&self, id: &SandboxId) -> Result<ContainerRecord> {
        self.containers
            .get(id)
            .cloned()
            .ok_or_else(|| ProvioError::Sandbox(format!("unknown sandbox {id:?}")))
    }
}

impl Default for DockerSandboxBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxBackend for DockerSandboxBackend {
    fn name(&self) -> &'static str {
        "docker"
    }

    /// True when the docker daemon is reachable (bounded `docker version`
    /// probe; used by `provio doctor`).
    fn available(&self) -> bool {
        matches!(
            run_captured(&["version", "--format", "{{.Server.Version}}"], PING_TIMEOUT),
            Ok(Captured::Done(out)) if out.code == 0
        )
    }

    /// Create and start a sandbox container: workspace bind-mounted at
    /// [`CONTAINER_WORKSPACE`], network `none` unless the spec demands an
    /// allow-list we cannot honor (then: fail closed — see module docs),
    /// resource limits per [`ResourceLimits`], `no-new-privileges` on.
    fn prepare(&mut self, spec: &SandboxSpec) -> Result<SandboxId> {
        // Checked before any filesystem or daemon contact: deterministic
        // fail-closed regardless of machine state.
        if !spec.allowed_hosts.is_empty() {
            let shown: Vec<String> = spec.allowed_hosts.iter().take(5).cloned().collect();
            let more = if spec.allowed_hosts.len() > 5 {
                ", ..."
            } else {
                ""
            };
            return Err(ProvioError::Sandbox(format!(
                "docker backend cannot enforce the per-host egress allow-list [{}{}] \
                 (docker provides no hostname-level egress filtering out of the box; \
                 failing closed instead of silently allowing full network). \
                 Set allowed_hosts to empty (network fully disabled) or use a \
                 backend that can enforce it",
                shown.join(", "),
                more
            )));
        }

        std::fs::create_dir_all(&spec.workspace)?;
        let workspace = spec.workspace.canonicalize().map_err(|e| {
            ProvioError::Sandbox(format!(
                "workspace {} not canonicalizable (fail closed): {e}",
                spec.workspace.display()
            ))
        })?;

        let image = self.image_for(spec);
        self.next_seq += 1;
        let name = format!("provio-sandbox-{}-{}", std::process::id(), self.next_seq);
        let bind = format!(
            "{}:{CONTAINER_WORKSPACE}",
            normalize_windows_path(&workspace)
        );
        let create = create_args(&name, &bind, &image, self.limits);

        // `docker create` pulls a missing image itself; the explicit pull is
        // the retry path for the daemon reporting the reference unknown.
        let mut out = run_ok(&create, PULL_TIMEOUT, "create container")?;
        if out.code != 0 && is_no_such_image(&out.stderr) {
            let pull = vec!["pull".to_string(), image.clone()];
            run_ok(&pull, PULL_TIMEOUT, "pull image")?.require("pull image", &image)?;
            out = run_ok(&create, PULL_TIMEOUT, "create container")?;
        }
        let out = out.require("create container", &name)?;
        let container_id = lossy(&out.stdout).trim().to_string();
        if container_id.is_empty() {
            return Err(ProvioError::Sandbox(
                "docker create returned no container id".to_string(),
            ));
        }
        let id = SandboxId(container_id.clone());
        self.containers.insert(
            id.clone(),
            ContainerRecord {
                workspace,
                env: spec.env.clone(),
            },
        );

        let start = run_ok(
            &["start", &container_id],
            DAEMON_CALL_TIMEOUT,
            "start container",
        );
        if start.as_ref().map(|out| out.code != 0).unwrap_or(true) {
            self.containers.remove(&id);
            // The exec target never came up; do not leak the container.
            let _ = run_ok(
                &["rm", "-f", &container_id],
                DAEMON_CALL_TIMEOUT,
                "remove container",
            );
            return Err(start.err().unwrap_or_else(|| {
                ProvioError::Sandbox("docker start container timed out".to_string())
            }));
        }
        Ok(id)
    }

    /// `docker exec` the request's program/args/env/cwd with a deadline.
    /// On timeout the CLI client is killed and the container is stopped
    /// (docker cannot kill a single exec'd process), so the sandbox is
    /// unusable afterwards and must be re-prepared.
    fn exec(&mut self, id: &SandboxId, req: &ExecRequest) -> Result<ExecOutput> {
        let record = self.record(id)?;
        let cwd = map_cwd(&record.workspace, req.cwd.as_deref())?;
        let env_pairs = merged_exec_env(&record.env, &req.env);
        let args = exec_args(&id.0, &cwd, &env_pairs, &req.program, &req.args);
        let timeout_ms = req.timeout_ms.unwrap_or(DEFAULT_EXEC_TIMEOUT_MS);

        let start = Instant::now();
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        match run_captured(&arg_refs, Duration::from_millis(timeout_ms))? {
            Captured::Done(out) => {
                // Docker's own failure (container gone, not running) surfaces
                // as exit 125 + a daemon error text; a program's own 125 is
                // passed through untouched.
                if is_daemon_level_exec_failure(&out) {
                    return Err(ProvioError::Sandbox(format!(
                        "docker exec failed: {}",
                        lossy(&out.stderr).trim()
                    )));
                }
                Ok(ExecOutput {
                    stdout: out.stdout,
                    stderr: out.stderr,
                    exit_code: out.code,
                    duration_ms: start.elapsed().as_millis() as u64,
                })
            }
            Captured::TimedOut => {
                let stop: Vec<&str> = vec!["stop", "-t", "0", &id.0];
                let _ = run_captured(&stop, DAEMON_CALL_TIMEOUT);
                Err(ProvioError::Sandbox(format!(
                    "execution timed out after {timeout_ms}ms and was killed \
                     (docker has no per-exec kill, so the container was stopped)"
                )))
            }
        }
    }

    /// Best-effort filesystem diff (`docker diff`), mapped back onto the
    /// workspace where possible. Empty on failure by contract — never
    /// fabricated; a daemon outage yields no diff, not a fake one.
    fn collect(&mut self, id: &SandboxId) -> Result<Artifacts> {
        let record = self.record(id)?;
        let diff = ["diff", &id.0];
        match run_ok(&diff, DAEMON_CALL_TIMEOUT, "container diff") {
            Ok(out) if out.code == 0 => Ok(Artifacts {
                files_changed: changed_files(&lossy(&out.stdout), &record.workspace),
            }),
            // Best-effort by contract: any failure yields no diff, never a
            // fabricated one.
            _ => Ok(Artifacts::default()),
        }
    }

    /// Stop and force-remove the container. Idempotent: a "no such container"
    /// report (already removed) is success. Unknown sandbox ids still attempt
    /// removal by id — the id *is* the container id.
    fn teardown(&mut self, id: SandboxId) -> Result<()> {
        let stop = ["stop", "-t", "0", &id.0];
        let _ = run_ok(&stop, DAEMON_CALL_TIMEOUT, "stop container");
        let remove = ["rm", "-f", &id.0];
        let removed = run_ok(&remove, DAEMON_CALL_TIMEOUT, "remove container")?;
        self.containers.remove(&id);
        if removed.code == 0 {
            return Ok(());
        }
        if is_no_such_container(&removed.stderr) {
            return Ok(());
        }
        Err(removed.require("remove container", &id.0).unwrap_err())
    }
}

enum Captured {
    /// The CLI exited on its own.
    Done(CapturedOutput),
    /// The deadline passed; the child was killed and reaped. Daemon-side
    /// work may continue for calls like pull — the deadline only guards
    /// against a wedged CLI or daemon.
    TimedOut,
}

#[derive(Debug)]
struct CapturedOutput {
    code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl CapturedOutput {
    fn require(self, op: &str, subject: &str) -> Result<CapturedOutput> {
        if self.code == 0 {
            return Ok(self);
        }
        Err(ProvioError::Sandbox(format!(
            "docker {op} {subject} failed (exit {code}): {stderr}",
            code = self.code,
            stderr = lossy(&self.stderr).trim()
        )))
    }
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Run a docker subcommand and insist on a clean CLI exit, mapping a deadline
/// overrun to a precise sandbox error.
fn run_ok<S: AsRef<std::ffi::OsStr>>(
    args: &[S],
    deadline: Duration,
    op: &str,
) -> Result<CapturedOutput> {
    match run_captured(args, deadline)? {
        Captured::Done(out) => Ok(out),
        Captured::TimedOut => Err(ProvioError::Sandbox(format!(
            "docker {op} timed out after {}s",
            deadline.as_secs()
        ))),
    }
}

/// Spawn `docker <args>`, drain stdout/stderr on reader threads (a chatty
/// child must never deadlock against a full pipe buffer while we poll, the
/// same pattern as the local-os backend) and wait up to `deadline`.
fn run_captured<S: AsRef<std::ffi::OsStr>>(args: &[S], deadline: Duration) -> Result<Captured> {
    run_command(Command::new(DOCKER_BIN).args(args), deadline)
}

fn run_command(cmd: &mut Command, deadline: Duration) -> Result<Captured> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            ProvioError::Sandbox(format!("docker CLI spawn failed (is docker on PATH?): {e}"))
        })?;

    let mut out_pipe = child.stdout.take().expect("piped stdout");
    let mut err_pipe = child.stderr.take().expect("piped stderr");
    let t_out = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = std::io::Read::read_to_end(&mut out_pipe, &mut b);
        b
    });
    let t_err = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = std::io::Read::read_to_end(&mut err_pipe, &mut b);
        b
    });

    let start = Instant::now();
    loop {
        match child.try_wait()? {
            Some(status) => {
                return Ok(Captured::Done(CapturedOutput {
                    code: status.code().unwrap_or(-1),
                    stdout: t_out.join().unwrap_or_default(),
                    stderr: t_err.join().unwrap_or_default(),
                }));
            }
            None if start.elapsed() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = t_out.join();
                let _ = t_err.join();
                return Ok(Captured::TimedOut);
            }
            None => thread::sleep(Duration::from_millis(5)),
        }
    }
}

/// Spec + limits -> `docker create` arguments (unit-tested without a daemon).
fn create_args(name: &str, bind: &str, image: &str, limits: ResourceLimits) -> Vec<String> {
    let mut args = vec![
        "create".to_string(),
        "--name".to_string(),
        name.to_string(),
        // Egress honesty: `none` is a real container-level deny-all.
        "--network".to_string(),
        "none".to_string(),
        "-v".to_string(),
        bind.to_string(),
    ];
    if let Some(pids) = limits.pids_limit {
        args.push("--pids-limit".to_string());
        args.push(pids.to_string());
    }
    if let Some(memory) = limits.memory_bytes {
        args.push("--memory".to_string());
        args.push(memory.to_string());
    }
    if let Some(nano_cpus) = limits.nano_cpus {
        args.push("--cpus".to_string());
        args.push((nano_cpus as f64 / 1e9).to_string());
    }
    // Blocks setuid-style privilege escalation inside the sandbox.
    args.push("--security-opt".to_string());
    args.push("no-new-privileges:true".to_string());
    args.push("--label".to_string());
    args.push("provio.managed=true".to_string());
    args.push("--label".to_string());
    args.push(format!("provio.image={image}"));
    // Keep-alive CMD override (see module docs): exec sessions need a
    // running container; a plain `docker run -d alpine` exits immediately.
    args.push(image.to_string());
    args.push(KEEPALIVE_CMD[0].to_string());
    args.push(KEEPALIVE_CMD[1].to_string());
    args
}

fn exec_args(
    container_id: &str,
    cwd: &str,
    env_pairs: &[String],
    program: &str,
    req_args: &[String],
) -> Vec<String> {
    let mut args = vec!["exec".to_string(), "-w".to_string(), cwd.to_string()];
    for pair in env_pairs {
        args.push("-e".to_string());
        args.push(pair.clone());
    }
    args.push(container_id.to_string());
    args.push(program.to_string());
    args.extend(req_args.iter().cloned());
    args
}

/// Docker's own exec failure (container gone / not running) exits 125 with a
/// daemon error text; a program's own 125 does not carry that text.
fn is_daemon_level_exec_failure(out: &CapturedOutput) -> bool {
    out.code == 125 && lossy(&out.stderr).contains("Error response from daemon")
}

fn is_no_such_container(stderr: &[u8]) -> bool {
    lossy(stderr).contains("No such container")
}

fn is_no_such_image(stderr: &[u8]) -> bool {
    lossy(stderr).contains("No such image")
}

/// Map an exec `cwd` (host path) onto the container mount, failing closed
/// the same way local-os does when it escapes or cannot be canonicalized.
fn map_cwd(workspace: &Path, req_cwd: Option<&Path>) -> Result<String> {
    let Some(cwd) = req_cwd else {
        return Ok(CONTAINER_WORKSPACE.to_string());
    };
    let target = cwd.canonicalize().map_err(|e| {
        ProvioError::Sandbox(format!(
            "cwd {} not canonicalizable (fail closed): {e}",
            cwd.display()
        ))
    })?;
    if !target.starts_with(workspace) {
        return Err(ProvioError::Sandbox(format!(
            "cwd {} escapes workspace {}",
            target.display(),
            workspace.display()
        )));
    }
    let rel = target
        .strip_prefix(workspace)
        .unwrap_or_else(|_| Path::new(""));
    let rel = rel.to_string_lossy().replace('\\', "/");
    if rel.is_empty() {
        Ok(CONTAINER_WORKSPACE.to_string())
    } else {
        Ok(format!("{CONTAINER_WORKSPACE}/{rel}"))
    }
}

/// Merge spec env under request env for one exec, dropping provio's own
/// image-selection plumbing from the run environment. Docker appends these
/// to the image's environment; the host environment never reaches the
/// container.
fn merged_exec_env(
    spec_env: &BTreeMap<String, String>,
    req_env: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut merged = spec_env.clone();
    for (k, v) in req_env {
        merged.insert(k.clone(), v.clone());
    }
    merged.remove(IMAGE_ENV_KEY);
    merged
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect()
}

/// Translate a container-internal changed path back onto the host workspace
/// when it is under the mount point; paths changed elsewhere in the container
/// are reported as-is rather than being dropped or guessed.
fn map_container_path(workspace: &Path, container_path: &str) -> PathBuf {
    if container_path == CONTAINER_WORKSPACE {
        workspace.to_path_buf()
    } else if let Some(rel) = container_path.strip_prefix(&format!("{CONTAINER_WORKSPACE}/")) {
        workspace.join(rel)
    } else {
        PathBuf::from(container_path)
    }
}

/// Paths the daemon itself writes into every container; reporting them as
/// "changed by the run" would mislead the ledger's what-changed view.
fn is_docker_injected_path(path: &str) -> bool {
    matches!(path, "/etc/hosts" | "/etc/hostname" | "/etc/resolv.conf")
}

/// `docker diff` prints one change per line: `<kind> <path>` with kind
/// 0=modified, 1=added, 2=deleted.
fn parse_diff_path(line: &str) -> Option<&str> {
    let (kind, path) = line.split_once(' ')?;
    match kind {
        "0" | "1" | "2" => Some(path.trim()),
        _ => None,
    }
}

fn changed_files(diff_output: &str, workspace: &Path) -> Vec<PathBuf> {
    diff_output
        .lines()
        .filter_map(parse_diff_path)
        .filter(|path| !is_docker_injected_path(path))
        .map(|path| map_container_path(workspace, path))
        .collect()
}

/// Docker Desktop's file-sharing layer rejects the Windows extended-length
/// prefix that `canonicalize` emits, so strip it for CLI argument strings.
fn normalize_windows_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    if let Some(rest) = raw.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = raw.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        raw.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Std-only unique temp dir (no tempfile dep — ADR-006). Auto-cleans.
    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let unique = format!("provio-docker-test-{}-{}", std::process::id(), {
                // A counter, not a timestamp: clock resolution is coarse on some
                // platforms (macOS: µs), so parallel tests collided on one dir.
                static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            });
            let p = std::env::temp_dir().join(unique);
            std::fs::create_dir_all(&p).unwrap();
            TestDir(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn spec(workspace: &Path, env: &[(&str, &str)], allowed_hosts: &[&str]) -> SandboxSpec {
        SandboxSpec {
            workspace: workspace.to_path_buf(),
            allowed_hosts: allowed_hosts.iter().map(|h| h.to_string()).collect(),
            env: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn image_precedence_spec_env_over_backend_over_default() {
        let dir = TestDir::new();
        let backend = DockerSandboxBackend::with_image("rust:1-slim");

        let plain = spec(dir.path(), &[], &[]);
        assert_eq!(backend.image_for(&plain), "rust:1-slim");

        let overridden = spec(dir.path(), &[(IMAGE_ENV_KEY, "alpine:3.20")], &[]);
        assert_eq!(backend.image_for(&overridden), "alpine:3.20");

        let empty_override = spec(dir.path(), &[(IMAGE_ENV_KEY, "")], &[]);
        assert_eq!(backend.image_for(&empty_override), "rust:1-slim");

        let default_backend = DockerSandboxBackend::new();
        assert_eq!(default_backend.image_for(&plain), DEFAULT_IMAGE);
    }

    #[test]
    fn exec_env_merges_request_over_spec_and_strips_provio_key() {
        let mut spec_env = BTreeMap::new();
        spec_env.insert("A".to_string(), "spec".to_string());
        spec_env.insert(IMAGE_ENV_KEY.to_string(), "alpine:3.20".to_string());
        let mut req_env = BTreeMap::new();
        req_env.insert("A".to_string(), "req".to_string());
        req_env.insert("B".to_string(), "req".to_string());

        let env = merged_exec_env(&spec_env, &req_env);
        assert!(env.contains(&"A=req".to_string()));
        assert!(env.contains(&"B=req".to_string()));
        assert!(
            !env.iter().any(|kv| kv.starts_with(IMAGE_ENV_KEY)),
            "provio image plumbing must not reach the run environment: {env:?}"
        );
    }

    #[test]
    fn non_empty_allowed_hosts_fail_closed_before_daemon_contact() {
        let mut backend = DockerSandboxBackend::new();
        let dir = TestDir::new();
        let s = spec(dir.path(), &[], &["api.example.com"]);
        let err = backend.prepare(&s).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("allowed_hosts"), "{msg}");
        assert!(msg.contains("failing closed"), "{msg}");
        // Deterministic regardless of daemon state: nothing was recorded.
        assert!(backend.containers.is_empty());
    }

    #[test]
    fn cwd_maps_to_container_mount_and_escapes_fail_closed() {
        let dir = TestDir::new();
        let ws = dir.path().canonicalize().unwrap();
        let sub = ws.join("sub");
        std::fs::create_dir_all(&sub).unwrap();

        assert_eq!(map_cwd(&ws, None).unwrap(), CONTAINER_WORKSPACE);
        assert_eq!(map_cwd(&ws, Some(&sub)).unwrap(), "/workspace/sub");
        let err = map_cwd(&ws, Some(dir.path().parent().unwrap())).unwrap_err();
        assert!(err.to_string().contains("escapes workspace"), "{err}");
    }

    #[test]
    fn create_args_map_spec_and_limits() {
        let args = create_args(
            "provio-sandbox-1-1",
            "C:\\work:/workspace",
            "alpine:3.20",
            ResourceLimits::default(),
        );
        let joined = args.join(" ");
        assert!(joined.contains("--network none"), "{joined}");
        assert!(joined.contains("-v C:\\work:/workspace"), "{joined}");
        assert!(joined.contains("--pids-limit 512"), "{joined}");
        assert!(
            joined.contains("--security-opt no-new-privileges:true"),
            "{joined}"
        );
        assert!(joined.contains("--label provio.managed=true"), "{joined}");
        assert!(
            joined.contains("--label provio.image=alpine:3.20"),
            "{joined}"
        );
        // Keep-alive CMD override, image last (then the CMD words).
        assert!(joined.ends_with("alpine:3.20 sleep infinity"), "{joined}");

        let limited = create_args(
            "provio-sandbox-1-2",
            "/work:/workspace",
            "rust:1-slim",
            ResourceLimits {
                pids_limit: Some(64),
                memory_bytes: Some(268_435_456),
                nano_cpus: Some(2_000_000_000),
            },
        );
        let joined = limited.join(" ");
        assert!(joined.contains("--pids-limit 64"), "{joined}");
        assert!(joined.contains("--memory 268435456"), "{joined}");
        assert!(joined.contains("--cpus 2"), "{joined}");
    }

    #[test]
    fn exec_args_carry_cwd_env_program_and_args() {
        let args = exec_args(
            "abc123",
            "/workspace/sub",
            &["A=1".to_string(), "B=2".to_string()],
            "sh",
            &["-c".to_string(), "echo hi".to_string()],
        );
        assert_eq!(
            args,
            vec![
                "exec",
                "-w",
                "/workspace/sub",
                "-e",
                "A=1",
                "-e",
                "B=2",
                "abc123",
                "sh",
                "-c",
                "echo hi"
            ]
        );
    }

    #[test]
    fn diff_output_maps_back_onto_workspace_and_filters_daemon_noise() {
        let dir = TestDir::new();
        let ws = dir.path();
        let diff = "0 /etc/hosts\n1 /workspace/a/b.txt\n2 /workspace/gone.txt\n1 /workspace2/x\n1 /tmp/elsewhere\njunk line\n";

        let files = changed_files(diff, ws);
        assert!(files.contains(&ws.join("a").join("b.txt")), "{files:?}");
        assert!(files.contains(&ws.join("gone.txt")), "{files:?}");
        // Look-alike prefixes must not be swallowed by the mount mapping.
        assert!(files.contains(&PathBuf::from("/workspace2/x")), "{files:?}");
        // Changes outside the mount are reported with their container path.
        assert!(
            files.contains(&PathBuf::from("/tmp/elsewhere")),
            "{files:?}"
        );
        // Daemon-injected noise and unparseable lines are dropped.
        assert!(!files.iter().any(|p| p.ends_with("hosts")), "{files:?}");
        assert_eq!(files.len(), 4, "{files:?}");
    }

    #[test]
    fn daemon_level_exec_failures_are_distinguished_from_program_exit_125() {
        let daemon_error = CapturedOutput {
            code: 125,
            stdout: Vec::new(),
            stderr: b"docker: Error response from daemon: Container abc is not running".to_vec(),
        };
        assert!(is_daemon_level_exec_failure(&daemon_error));

        let program_125 = CapturedOutput {
            code: 125,
            stdout: Vec::new(),
            stderr: b"some program's own complaint".to_vec(),
        };
        assert!(!is_daemon_level_exec_failure(&program_125));
    }

    #[test]
    fn missing_container_and_missing_image_are_recognized() {
        assert!(is_no_such_container(
            b"Error response from daemon: No such container: deadbeef"
        ));
        assert!(!is_no_such_container(b"some other error"));
        assert!(is_no_such_image(
            b"docker: Error response from daemon: No such image: alpine:3.20"
        ));
    }

    #[test]
    fn windows_extended_length_prefix_is_stripped_for_cli_arguments() {
        assert_eq!(
            normalize_windows_path(Path::new(r"\\?\C:\Users\provio")),
            r"C:\Users\provio"
        );
        assert_eq!(
            normalize_windows_path(Path::new("/home/provio")),
            "/home/provio"
        );
    }

    #[test]
    fn sandbox_error_carries_operation_and_exit_code() {
        let err = CapturedOutput {
            code: 7,
            stdout: Vec::new(),
            stderr: b"boom".to_vec(),
        }
        .require("create container", "provio-sandbox-1-1")
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("sandbox error"), "{msg}");
        assert!(msg.contains("create container"), "{msg}");
        assert!(msg.contains("exit 7"), "{msg}");
        assert!(msg.contains("boom"), "{msg}");
    }
}
