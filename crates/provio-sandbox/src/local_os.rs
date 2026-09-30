//! `local-os` backend — the default workstation sandbox (spec §8, §6B).
//!
//! Process-level containment (clean environment, workspace-bound cwd,
//! timeouts, dead-lock-free output capture via reader threads) plus
//! kernel-level enforcement of the [`SandboxSpec`]:
//!
//! | OS      | writes outside the workspace | network egress (empty `allowed_hosts`) |
//! |---------|------------------------------|----------------------------------------|
//! | Linux   | Landlock                     | seccomp-bpf (socket creation denied)   |
//! | macOS   | Seatbelt (`sandbox_init`)    | Seatbelt `(deny network*)`             |
//! | Windows | AppContainer token + Job     | AppContainer without capabilities      |
//!
//! Each sandbox also gets a private writable temp dir: `TMPDIR` on Unix
//! (created per sandbox, removed on teardown); on Windows `TEMP`/`TMP` is
//! the AppContainer's own `...\Packages\<name>\AC\Temp`, which the OS forces
//! for AppContainer children (removed with the profile).
//!
//! Fail closed: with the default [`EnforcementMode::Required`], `prepare`
//! refuses a spec the running kernel cannot fully enforce — including any
//! non-empty `allowed_hosts`, since no mechanism here filters by host.
//! [`LocalOsBackend::with_mode`]`(BestEffort)` is the explicit opt-in to
//! degraded mode; [`LocalOsBackend::enforcement`] then states exactly what
//! holds. Overclaiming what a sandbox enforces is the cardinal sin here.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use provio_core::error::{ProvioError, Result};
use provio_core::sandbox::{
    Artifacts, ExecOutput, ExecRequest, SandboxBackend, SandboxId, SandboxSpec,
};

use crate::enforce::{self, EnforcementMode, EnforcementReport};

/// Minimal OS baseline a child process needs to function (Windows refuses to
/// start cmd.exe without SystemRoot, PATHEXT, etc.). Least privilege means
/// "nothing but the baseline and what the run declares" — not "nothing at
/// all", which is just broken. Temp variables are then pointed at the
/// sandbox's private temp dir.
fn baseline_env() -> Vec<(String, String)> {
    #[cfg(windows)]
    const KEYS: &[&str] = &[
        "SystemRoot",
        "windir",
        "COMSPEC",
        "PATHEXT",
        "SystemDrive",
        "PATH",
        // CreateProcessW rewrites these for an AppContainer child (to the
        // container's own profile folder) and fails with
        // ERROR_ENVVAR_NOT_FOUND when they are absent.
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
    ];
    #[cfg(not(windows))]
    const KEYS: &[&str] = &["PATH", "HOME", "LANG", "TERM"];
    KEYS.iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v)))
        .collect()
}

#[cfg(windows)]
const TEMP_VARS: &[&str] = &["TEMP", "TMP"];
#[cfg(not(windows))]
const TEMP_VARS: &[&str] = &["TMPDIR"];

struct Prepared {
    spec: SandboxSpec,
    /// Canonical workspace.
    workspace: PathBuf,
    /// Canonical private temp dir.
    temp: PathBuf,
    /// Created by us (removed on teardown). False for the Windows
    /// AppContainer temp, which is removed with the container profile.
    owns_temp: bool,
    report: EnforcementReport,
    #[cfg(windows)]
    container: String,
}

pub struct LocalOsBackend {
    sandboxes: HashMap<SandboxId, Prepared>,
    mode: EnforcementMode,
}

impl Default for LocalOsBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalOsBackend {
    /// Fail-closed backend ([`EnforcementMode::Required`]).
    pub fn new() -> Self {
        Self::with_mode(EnforcementMode::Required)
    }

    /// Backend with an explicit enforcement mode. `BestEffort` is the only
    /// way to run a spec the kernel cannot fully enforce.
    pub fn with_mode(mode: EnforcementMode) -> Self {
        LocalOsBackend {
            sandboxes: HashMap::new(),
            mode,
        }
    }

    pub fn mode(&self) -> EnforcementMode {
        self.mode
    }

    /// Exactly what the kernel enforces for a prepared sandbox.
    pub fn enforcement(&self, id: &SandboxId) -> Option<&EnforcementReport> {
        self.sandboxes.get(id).map(|p| &p.report)
    }

    /// The sandbox's private, writable temp dir.
    pub fn temp_dir(&self, id: &SandboxId) -> Option<&Path> {
        self.sandboxes.get(id).map(|p| p.temp.as_path())
    }

    /// Reject an ExecRequest whose cwd escapes the sandbox workspace.
    /// Canonicalize both sides so `..` tricks fail closed.
    fn check_cwd(ws: &Path, req: &ExecRequest) -> Result<()> {
        let Some(cwd) = &req.cwd else { return Ok(()) };
        let target = cwd.canonicalize().map_err(|e| {
            ProvioError::Sandbox(format!(
                "cwd {} not canonicalizable (fail closed): {e}",
                cwd.display()
            ))
        })?;
        if !target.starts_with(ws) {
            return Err(ProvioError::Sandbox(format!(
                "cwd {} escapes workspace {}",
                target.display(),
                ws.display()
            )));
        }
        Ok(())
    }
}

/// `canonicalize`, minus Windows' `\\?\` verbatim prefix where it is not
/// needed (cmd.exe refuses verbatim paths as a working directory).
pub(crate) fn canonical(p: &Path) -> Result<PathBuf> {
    let c = p.canonicalize().map_err(|e| {
        ProvioError::Sandbox(format!(
            "{} not canonicalizable (fail closed): {e}",
            p.display()
        ))
    })?;
    #[cfg(windows)]
    {
        let s = c.to_string_lossy();
        if let Some(rest) = s.strip_prefix(r"\\?\") {
            if !rest.starts_with("UNC\\") && rest.len() < 248 {
                return Ok(PathBuf::from(rest));
            }
        }
    }
    Ok(c)
}

fn drain<R: Read + Send + 'static>(mut r: R) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut b = Vec::new();
        let _ = r.read_to_end(&mut b);
        b
    })
}

fn timed_out(timeout: Duration) -> ProvioError {
    ProvioError::Sandbox(format!(
        "execution timed out after {}ms and was killed",
        timeout.as_millis()
    ))
}

impl SandboxBackend for LocalOsBackend {
    fn name(&self) -> &'static str {
        "local-os"
    }

    fn prepare(&mut self, spec: &SandboxSpec) -> Result<SandboxId> {
        // Decide before touching the filesystem: an unenforceable spec
        // fails closed deterministically.
        let caps = crate::platform::capabilities();
        let report = enforce::plan(spec, &caps, self.mode)?;

        std::fs::create_dir_all(&spec.workspace)?;
        let workspace = canonical(&spec.workspace)?;
        #[cfg(target_os = "linux")]
        if report.apply_filesystem {
            crate::linux::check_workspace_fs(&workspace)?;
        }

        // Process-wide counter: ids (and the temp dirs named after them)
        // must not collide between backend instances.
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let n = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let id = SandboxId(format!("local-{}-{n}", std::process::id()));
        #[cfg(windows)]
        let mut report = report;
        #[cfg(windows)]
        let container = crate::windows::container_name(&workspace);
        // On Windows an AppContainer child's TEMP/TMP is forced by the OS to
        // the container's profile folder; use that as the private temp.
        #[cfg(windows)]
        let container_temp = if report.apply_filesystem {
            let (sid, temp) = crate::windows::prepare_container(&container, &workspace)?;
            report.notes.push(format!(
                "AppContainer SID {sid} holds an inheritable full-access ACE on the \
                 workspace (persists after teardown; remove with icacls /remove)"
            ));
            Some(canonical(&temp)?)
        } else {
            None
        };
        #[cfg(not(windows))]
        let container_temp: Option<PathBuf> = None;

        let owns_temp = container_temp.is_none();
        let temp = match container_temp {
            Some(t) => t,
            None => {
                let raw = std::env::temp_dir().join(format!("provio-sbx-{}-tmp", id.0));
                std::fs::create_dir_all(&raw)?;
                canonical(&raw)?
            }
        };
        if temp.starts_with(&workspace) || workspace.starts_with(&temp) {
            if owns_temp {
                let _ = std::fs::remove_dir_all(&temp);
            }
            return Err(ProvioError::Sandbox(
                "workspace and private temp dir overlap (fail closed)".into(),
            ));
        }

        self.sandboxes.insert(
            id.clone(),
            Prepared {
                spec: spec.clone(),
                workspace,
                temp,
                report,
                owns_temp,
                #[cfg(windows)]
                container,
            },
        );
        Ok(id)
    }

    fn exec(&mut self, id: &SandboxId, req: &ExecRequest) -> Result<ExecOutput> {
        let p = self
            .sandboxes
            .get(id)
            .ok_or_else(|| ProvioError::Sandbox(format!("unknown sandbox {id:?}")))?;
        Self::check_cwd(&p.workspace, req)?;

        // Least privilege: OS baseline (programs must resolve and start),
        // the private temp dir, then what the run explicitly declares.
        let temp = p.temp.to_string_lossy().into_owned();
        let mut env = baseline_env();
        env.extend(TEMP_VARS.iter().map(|k| (k.to_string(), temp.clone())));
        env.extend(p.spec.env.iter().map(|(k, v)| (k.clone(), v.clone())));
        env.extend(req.env.iter().map(|(k, v)| (k.clone(), v.clone())));
        let cwd = match &req.cwd {
            Some(c) => canonical(c)?,
            None => p.workspace.clone(),
        };
        let timeout = Duration::from_millis(req.timeout_ms.unwrap_or(600_000));

        #[cfg(windows)]
        {
            exec_windows(p, req, &cwd, &env, timeout)
        }
        #[cfg(not(windows))]
        {
            exec_unix(p, req, &cwd, &env, timeout)
        }
    }

    fn collect(&mut self, _id: &SandboxId) -> Result<Artifacts> {
        // File-diff collection is best-effort and not yet implemented.
        Ok(Artifacts::default())
    }

    fn teardown(&mut self, id: SandboxId) -> Result<()> {
        if let Some(p) = self.sandboxes.remove(&id) {
            if p.owns_temp {
                let _ = std::fs::remove_dir_all(&p.temp);
            }
            #[cfg(windows)]
            if !self.sandboxes.values().any(|o| o.container == p.container) {
                crate::windows::delete_profile(&p.container);
            }
        }
        Ok(())
    }
}

impl Drop for LocalOsBackend {
    fn drop(&mut self) {
        let ids: Vec<SandboxId> = self.sandboxes.keys().cloned().collect();
        for id in ids {
            let _ = self.teardown(id);
        }
    }
}

#[cfg(not(windows))]
fn exec_unix(
    p: &Prepared,
    req: &ExecRequest,
    cwd: &Path,
    env: &[(String, String)],
    timeout: Duration,
) -> Result<ExecOutput> {
    use std::process::{Command, Stdio};

    let mut cmd = Command::new(&req.program);
    // Own process group, so a timeout kills the whole tree (a shell's
    // children would otherwise outlive it and hold the output pipes open).
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    cmd.args(&req.args)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let writable: [&Path; 2] = [&p.workspace, &p.temp];
    let (fs, net) = (p.report.apply_filesystem, p.report.apply_network_deny);
    // Kept alive until spawn returns: the child uses the prepared state.
    #[cfg(target_os = "linux")]
    let _confinement = if fs || net {
        let c = crate::linux::Confinement::build(&writable, fs, net)?;
        c.install(&mut cmd);
        Some(c)
    } else {
        None
    };
    #[cfg(target_os = "macos")]
    let _confinement = if fs || net {
        let c = crate::macos::Confinement::build(&writable, fs, net)?;
        c.install(&mut cmd);
        Some(c)
    } else {
        None
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = (writable, fs, net);

    let start = Instant::now();
    let mut child = cmd.spawn().map_err(|e| {
        ProvioError::Sandbox(format!(
            "spawn {} failed (kernel confinement is applied before exec; fail closed): {e}",
            req.program
        ))
    })?;

    // Drain pipes on reader threads: a chatty child must never deadlock
    // against a full pipe buffer while we poll try_wait.
    let t_out = drain(child.stdout.take().expect("piped stdout"));
    let t_err = drain(child.stderr.take().expect("piped stderr"));

    let status = loop {
        match child.try_wait()? {
            Some(s) => break s,
            None if start.elapsed() > timeout => {
                // The leader is not reaped yet, so its pgid is still ours.
                crate::unix::kill_process_group(child.id());
                let _ = child.kill();
                let _ = child.wait();
                let _ = t_out.join();
                let _ = t_err.join();
                return Err(timed_out(timeout));
            }
            None => thread::sleep(Duration::from_millis(5)),
        }
    };

    Ok(ExecOutput {
        stdout: t_out.join().unwrap_or_default(),
        stderr: t_err.join().unwrap_or_default(),
        exit_code: status.code().unwrap_or(-1),
        duration_ms: start.elapsed().as_millis() as u64,
    })
}

#[cfg(windows)]
fn exec_windows(
    p: &Prepared,
    req: &ExecRequest,
    cwd: &Path,
    env: &[(String, String)],
    timeout: Duration,
) -> Result<ExecOutput> {
    let conf = crate::windows::Confinement {
        container: p.report.apply_filesystem.then_some(p.container.as_str()),
        allow_network: !p.report.apply_network_deny,
    };
    let start = Instant::now();
    let (child, out, err) = crate::windows::spawn(&conf, &req.program, &req.args, cwd, env)?;
    let t_out = drain(out);
    let t_err = drain(err);

    let remaining = timeout.saturating_sub(start.elapsed());
    let code = child.wait_timeout(remaining.as_millis() as u64)?;
    // Kill the whole job (the main process on timeout; any lingering
    // descendant otherwise) so the pipes reach EOF.
    child.finish();
    let stdout = t_out.join().unwrap_or_default();
    let stderr = t_err.join().unwrap_or_default();
    match code {
        None => Err(timed_out(timeout)),
        Some(code) => Ok(ExecOutput {
            stdout,
            stderr,
            exit_code: code,
            duration_ms: start.elapsed().as_millis() as u64,
        }),
    }
}
