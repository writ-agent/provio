//! Shared helpers for the provio-sandbox integration tests.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use provio_core::sandbox::{ExecOutput, ExecRequest, SandboxBackend, SandboxId, SandboxSpec};
use provio_sandbox::LocalOsBackend;

/// Std-only unique temp dir (no tempfile dep). Auto-cleans on Drop.
pub struct TestDir(PathBuf);

impl TestDir {
    pub fn new() -> Self {
        let unique = format!("provio-test-{}-{}", std::process::id(), {
            // A counter, not a timestamp: clock resolution is coarse on some
            // platforms (macOS: µs), so parallel tests collided on one dir.
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        });
        let p = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&p).unwrap();
        // Canonical, without Windows' verbatim prefix (cmd.exe rejects it).
        let p = p.canonicalize().unwrap();
        #[cfg(windows)]
        let p = PathBuf::from(p.to_string_lossy().trim_start_matches(r"\\?\"));
        TestDir(p)
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
    /// A fresh subdirectory (created).
    pub fn sub(&self, name: &str) -> PathBuf {
        let p = self.0.join(name);
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn spec_for(workspace: &Path) -> SandboxSpec {
    SandboxSpec {
        workspace: workspace.to_path_buf(),
        allowed_hosts: vec![],
        env: BTreeMap::new(),
    }
}

/// A test root containing `ws/` (the workspace) and `outside/` (a sibling
/// the sandbox must not write).
pub struct Layout {
    pub root: TestDir,
    pub ws: PathBuf,
    pub outside: PathBuf,
}

impl Layout {
    pub fn new() -> Self {
        let root = TestDir::new();
        let ws = root.sub("ws");
        let outside = root.sub("outside");
        Layout { root, ws, outside }
    }
    pub fn spec(&self) -> SandboxSpec {
        spec_for(&self.ws)
    }
}

pub fn req(program: &str, args: Vec<String>, timeout_ms: u64) -> ExecRequest {
    ExecRequest {
        program: program.into(),
        args,
        cwd: None,
        env: BTreeMap::new(),
        timeout_ms: Some(timeout_ms),
    }
}

pub fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// `true` when the default fail-closed backend can run on this machine.
/// When it cannot, asserts that it indeed refuses (fail closed) — and, if
/// `PROVIO_SANDBOX_REQUIRE_ENFORCEMENT` is set (CI), fails the test outright
/// so a runner without kernel support cannot pass silently.
pub fn kernel_enforcement_available() -> bool {
    let kh = provio_sandbox::kernel_hardening();
    if kh.enforced {
        return true;
    }
    let dir = TestDir::new();
    let err = LocalOsBackend::new()
        .prepare(&spec_for(dir.path()))
        .expect_err("an unenforceable spec must fail closed");
    assert!(err.to_string().contains("fail closed"), "{err}");
    assert!(
        std::env::var_os("PROVIO_SANDBOX_REQUIRE_ENFORCEMENT").is_none(),
        "kernel enforcement required but unavailable: {}",
        kh.notes
    );
    eprintln!("SKIP: kernel enforcement unavailable here: {}", kh.notes);
    false
}

// ---- probe helper: re-run this test binary inside the sandbox -----------

/// Env var selecting the probe operation (see each test file's
/// `probe_helper`), and its argument.
pub const PROBE_OP: &str = "PROVIO_PROBE_OP";
pub const PROBE_ARG: &str = "PROVIO_PROBE_ARG";

/// Outcome of one syscall-level probe run inside the sandbox.
#[derive(Debug, PartialEq, Eq)]
pub enum Probe {
    Ok,
    /// The OS error code the operation failed with.
    Err(i32),
}

/// Print the probe outcome in the format `run_probe` parses.
pub fn report(r: std::io::Result<()>) {
    match r {
        Ok(()) => println!("PROBE-RESULT ok"),
        Err(e) => println!("PROBE-RESULT err {} ({e})", e.raw_os_error().unwrap_or(-1)),
    }
}

/// Run `exe` (this test binary or a copy of it) inside sandbox `id` so that
/// only the `probe_helper` test runs, performing `op` on `arg`.
pub fn run_probe(
    b: &mut LocalOsBackend,
    id: &SandboxId,
    exe: &Path,
    op: &str,
    arg: &str,
) -> (Probe, ExecOutput) {
    let mut r = req(
        exe.to_str().unwrap(),
        vec![
            "probe_helper".into(),
            "--exact".into(),
            "--nocapture".into(),
            "--test-threads=1".into(),
        ],
        60_000,
    );
    r.env.insert(PROBE_OP.into(), op.into());
    r.env.insert(PROBE_ARG.into(), arg.into());
    let out = b.exec(id, &r).expect("probe spawn");
    let stdout = text(&out.stdout);
    // libtest prints "test probe_helper ... " right before the probe line.
    let line = stdout
        .lines()
        .find_map(|l| l.split_once("PROBE-RESULT ").map(|(_, r)| r))
        .unwrap_or_else(|| {
            panic!(
                "probe produced no result; exit {} stdout: {stdout:?} stderr: {:?}",
                out.exit_code,
                text(&out.stderr)
            )
        })
        .to_string();
    let probe = if line == "ok" {
        Probe::Ok
    } else {
        let code = line
            .strip_prefix("err ")
            .and_then(|r| r.split_whitespace().next())
            .and_then(|c| c.parse().ok())
            .unwrap_or_else(|| panic!("bad probe line {line}"));
        Probe::Err(code)
    };
    (probe, out)
}
