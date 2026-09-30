//! Acceptance tests for the local-os backend (plan: A8). Kernel-level
//! enforcement tests live in `kernel_{linux,windows,macos}.rs`.

mod common;

use common::{kernel_enforcement_available, req, spec_for, TestDir};
use provio_core::sandbox::{ExecRequest, SandboxBackend, SandboxSpec};
use provio_sandbox::{detect_backends, kernel_hardening, LocalOsBackend};

fn spec() -> (TestDir, SandboxSpec) {
    let dir = TestDir::new();
    let spec = spec_for(dir.path());
    (dir, spec)
}

#[cfg(windows)]
fn echo_req(msg: &str) -> ExecRequest {
    req("cmd", vec!["/c".into(), format!("echo {msg}")], 10_000)
}

#[cfg(not(windows))]
fn echo_req(msg: &str) -> ExecRequest {
    req("sh", vec!["-c".into(), format!("echo {msg}")], 10_000)
}

#[test]
fn exec_captures_output_and_exit_code() {
    if !kernel_enforcement_available() {
        return;
    }
    let (_d, s) = spec();
    let mut b = LocalOsBackend::new();
    let id = b.prepare(&s).unwrap();
    let out = b.exec(&id, &echo_req("hello-provio")).unwrap();
    assert_eq!(out.exit_code, 0, "stderr: {}", common::text(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("hello-provio"), "stdout was: {stdout}");
    b.teardown(id).unwrap();
}

#[test]
fn timeout_kills_sleeper() {
    if !kernel_enforcement_available() {
        return;
    }
    let (_d, s) = spec();
    let mut b = LocalOsBackend::new();
    let id = b.prepare(&s).unwrap();
    // An infinite cmd loop: ping/timeout are unsuitable inside an
    // AppContainer (no network; timeout refuses a NUL stdin).
    #[cfg(windows)]
    let r = req(
        "cmd",
        vec!["/c".into(), "for /l %i in (0,0,1) do @rem".into()],
        300,
    );
    #[cfg(not(windows))]
    let r = req("sh", vec!["-c".into(), "sleep 30".into()], 300);
    let err = b.exec(&id, &r).unwrap_err();
    assert!(err.to_string().contains("timed out"), "{err}");
}

#[test]
fn cwd_escape_is_rejected() {
    if !kernel_enforcement_available() {
        return;
    }
    let (d, s) = spec();
    let mut b = LocalOsBackend::new();
    let id = b.prepare(&s).unwrap();
    let mut r = echo_req("x");
    r.cwd = Some(d.path().parent().unwrap().to_path_buf());
    let err = b.exec(&id, &r).unwrap_err();
    assert!(err.to_string().contains("escapes workspace"), "{err}");
}

#[test]
fn child_env_is_clean_and_temp_is_private() {
    if !kernel_enforcement_available() {
        return;
    }
    std::env::set_var("PROVIO_TEST_LEAK", "1");
    let (_d, s) = spec();
    let mut b = LocalOsBackend::new();
    let id = b.prepare(&s).unwrap();
    let tmp = b.temp_dir(&id).unwrap().to_path_buf();
    assert!(tmp.is_dir());
    #[cfg(windows)]
    let r = req(
        "cmd",
        vec!["/c".into(), "echo [%PROVIO_TEST_LEAK%] [%TEMP%]".into()],
        10_000,
    );
    #[cfg(not(windows))]
    let r = req(
        "sh",
        vec!["-c".into(), "echo [$PROVIO_TEST_LEAK] [$TMPDIR]".into()],
        10_000,
    );
    let out = b.exec(&id, &r).unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("[1]"), "parent env leaked: {stdout}");
    assert!(
        stdout.contains(&format!("[{}]", tmp.display())),
        "temp not private: {stdout}"
    );
    b.teardown(id).unwrap();
    assert!(
        !tmp.exists(),
        "private temp dir must be removed on teardown"
    );
}

#[test]
fn detect_reports_local_os_and_kernel_honesty() {
    let backends = detect_backends();
    assert!(backends.iter().any(|b| b.name == "local-os" && b.available));
    assert!(backends.iter().all(|b| !b.notes.is_empty()));
    let kh = kernel_hardening();
    let caps = provio_sandbox::capabilities();
    // `enforced` is derived from the probed capabilities, never assumed.
    assert_eq!(
        kh.enforced,
        caps.filesystem.is_full() && caps.network_deny.is_full()
    );
    assert!(kh.notes.contains("filesystem:") && kh.notes.contains("network:"));
    assert!(kh.notes.contains("allowed_hosts"));
    if !kh.enforced {
        assert!(kh.notes.contains("NOT enforced") || kh.notes.contains("PARTIAL"));
    }
}

#[test]
fn prepare_matches_reported_enforcement() {
    let (_d, s) = spec();
    let mut b = LocalOsBackend::new();
    match b.prepare(&s) {
        Ok(id) => {
            let r = b.enforcement(&id).unwrap();
            assert!(r.fully_enforced(), "{r:?}");
            assert!(kernel_hardening().enforced);
        }
        Err(e) => {
            assert!(!kernel_hardening().enforced);
            assert!(e.to_string().contains("fail closed"), "{e}");
        }
    }
}

#[test]
fn non_empty_allow_list_fails_closed_by_default() {
    let (_d, mut s) = spec();
    s.allowed_hosts = vec!["api.example.com".into()];
    let err = LocalOsBackend::new().prepare(&s).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("fail closed") && msg.contains("api.example.com"),
        "{msg}"
    );
}
