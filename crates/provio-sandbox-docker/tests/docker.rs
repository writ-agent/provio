//! Integration tests for the Docker backend — real daemon required.
//!
//! `#[ignore]`d and double-gated: `PROVIO_DOCKER_TEST=1` must be set *and* the
//! `docker` CLI must be able to reach a daemon (probed the same way
//! provio-sandbox's detector does). `cargo test` on any machine therefore runs
//! nothing here by default; CI and maintainers opt in explicitly.

use provio_core::sandbox::{ExecRequest, SandboxBackend, SandboxSpec};
use provio_sandbox_docker::DockerSandboxBackend;
use std::collections::BTreeMap;
use std::process::Command;

/// Std-only unique temp dir (no tempfile dep — ADR-006). Auto-cleans.
struct TestDir(std::path::PathBuf);

impl TestDir {
    fn new() -> Self {
        let unique = format!("provio-docker-it-{}-{}", std::process::id(), {
            // A counter, not a timestamp: clock resolution is coarse on some
            // platforms (macOS: µs), so parallel tests collided on one dir.
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        });
        let p = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&p).unwrap();
        TestDir(p)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn spec() -> (TestDir, SandboxSpec) {
    let dir = TestDir::new();
    let spec = SandboxSpec {
        workspace: dir.path().to_path_buf(),
        allowed_hosts: vec![],
        env: BTreeMap::new(),
    };
    (dir, spec)
}

/// Gate: env var set AND a `docker version` probe succeeds (daemon reachable).
fn integration_ready() -> bool {
    if std::env::var("PROVIO_DOCKER_TEST").as_deref() != Ok("1") {
        return false;
    }
    on_path("docker")
        && Command::new("docker")
            .arg("version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
}

/// Same PATH check as provio-sandbox's detector: `docker` (or docker.exe/.bat)
/// must resolve.
fn on_path(exe: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                let plain = dir.join(exe);
                plain.is_file()
                    || plain.with_extension("exe").is_file()
                    || plain.with_extension("bat").is_file()
            })
        })
        .unwrap_or(false)
}

fn req(program: &str, args: Vec<String>, timeout_ms: Option<u64>) -> ExecRequest {
    ExecRequest {
        program: program.into(),
        args,
        cwd: None,
        env: BTreeMap::new(),
        timeout_ms,
    }
}

#[ignore]
#[test]
fn exec_captures_output_and_exit_code() {
    if !integration_ready() {
        eprintln!("skipping: PROVIO_DOCKER_TEST=1 with a reachable daemon required");
        return;
    }
    let (_d, s) = spec();
    let mut b = DockerSandboxBackend::new();
    let id = b.prepare(&s).unwrap();
    let out = b
        .exec(
            &id,
            &req("echo", vec!["hello-provio-docker".into()], Some(10_000)),
        )
        .unwrap();
    assert_eq!(
        out.exit_code,
        0,
        "stderr was: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("hello-provio-docker"),
        "stdout was: {stdout}"
    );
    assert!(out.duration_ms > 0);
    b.teardown(id).unwrap();
}

#[ignore]
#[test]
fn exec_env_and_cwd_reach_the_container() {
    if !integration_ready() {
        eprintln!("skipping: PROVIO_DOCKER_TEST=1 with a reachable daemon required");
        return;
    }
    let (d, s) = spec();
    let mut b = DockerSandboxBackend::new();
    let id = b.prepare(&s).unwrap();

    let mut r = req(
        "sh",
        vec!["-c".into(), "echo $PROVIO_PROBE".into()],
        Some(10_000),
    );
    r.env
        .insert("PROVIO_PROBE".to_string(), "env-roundtrip".to_string());
    let out = b.exec(&id, &r).unwrap();
    assert_eq!(out.exit_code, 0);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("env-roundtrip"),
        "stdout was: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    std::fs::create_dir_all(d.path().join("subdir")).unwrap();
    let mut r = req("pwd", vec![], Some(10_000));
    r.cwd = Some(d.path().join("subdir"));
    let out = b.exec(&id, &r).unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("/workspace/subdir"),
        "cwd was: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    b.teardown(id).unwrap();
}

#[ignore]
#[test]
fn timeout_kills_and_reports() {
    if !integration_ready() {
        eprintln!("skipping: PROVIO_DOCKER_TEST=1 with a reachable daemon required");
        return;
    }
    let (_d, s) = spec();
    let mut b = DockerSandboxBackend::new();
    let id = b.prepare(&s).unwrap();
    let err = b
        .exec(&id, &req("sleep", vec!["60".into()], Some(500)))
        .unwrap_err();
    assert!(err.to_string().contains("timed out"), "{err}");
    // The container was stopped by the timeout kill; teardown must still work.
    b.teardown(id).unwrap();
}

#[ignore]
#[test]
fn collect_reports_workspace_changes() {
    if !integration_ready() {
        eprintln!("skipping: PROVIO_DOCKER_TEST=1 with a reachable daemon required");
        return;
    }
    let (d, s) = spec();
    let mut b = DockerSandboxBackend::new();
    let id = b.prepare(&s).unwrap();
    let r = req(
        "sh",
        vec![
            "-c".into(),
            "echo probe > /workspace/provio-collect-probe.txt".into(),
        ],
        Some(10_000),
    );
    let out = b.exec(&id, &r).unwrap();
    assert_eq!(
        out.exit_code,
        0,
        "stderr was: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let artifacts = b.collect(&id).unwrap();
    let probe = d.path().join("provio-collect-probe.txt");
    assert!(
        artifacts.files_changed.iter().any(|p| p == &probe),
        "files changed were: {:?}",
        artifacts.files_changed
    );
    // Daemon-injected noise must be filtered, not reported as run changes.
    assert!(
        !artifacts
            .files_changed
            .iter()
            .any(|p| p.ends_with("resolv.conf")),
        "files changed were: {:?}",
        artifacts.files_changed
    );
    b.teardown(id).unwrap();
}

#[ignore]
#[test]
fn network_none_denies_egress() {
    if !integration_ready() {
        eprintln!("skipping: PROVIO_DOCKER_TEST=1 with a reachable daemon required");
        return;
    }
    let (_d, s) = spec();
    let mut b = DockerSandboxBackend::new();
    let id = b.prepare(&s).unwrap();
    // busybox wget: with network mode none, DNS fails immediately — this is
    // the honest proof that empty allowed_hosts means deny-all egress.
    let out = b
        .exec(
            &id,
            &req(
                "wget",
                vec!["-q".into(), "-O-".into(), "http://example.com/".into()],
                Some(15_000),
            ),
        )
        .unwrap();
    assert_ne!(
        out.exit_code,
        0,
        "egress must fail with network mode none; stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    b.teardown(id).unwrap();
}

#[ignore]
#[test]
fn teardown_is_idempotent() {
    if !integration_ready() {
        eprintln!("skipping: PROVIO_DOCKER_TEST=1 with a reachable daemon required");
        return;
    }
    let (_d, s) = spec();
    let mut b = DockerSandboxBackend::new();
    let id = b.prepare(&s).unwrap();
    b.teardown(id.clone()).unwrap();
    b.teardown(id).unwrap();
}
