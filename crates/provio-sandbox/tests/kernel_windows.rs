//! Windows kernel-enforcement tests (AppContainer + Job Object), run on the
//! local Windows host and CI's windows-latest.
//!
//! Syscall-level: a copy of this test binary is placed in the workspace
//! (the AppContainer can execute from there) and re-run inside the sandbox
//! as `probe_helper`, which issues one CreateFileW / CreateDirectoryW /
//! connect and reports the exact Win32/WinSock error code.
#![cfg(windows)]

mod common;

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{kernel_enforcement_available, req, run_probe, text, Layout, Probe};
use provio_core::sandbox::{SandboxBackend, SandboxId};
use provio_sandbox::{EnforcementMode, Level, LocalOsBackend};

const ERROR_ACCESS_DENIED: i32 = 5;

/// Runs only when re-invoked inside the sandbox with PROVIO_PROBE_OP set.
#[test]
fn probe_helper() {
    let Ok(op) = std::env::var(common::PROBE_OP) else {
        return;
    };
    let arg = std::env::var(common::PROBE_ARG).unwrap_or_default();
    let r = match op.as_str() {
        "write" => std::fs::File::create(&arg).and_then(|mut f| f.write_all(b"x")),
        "mkdir" => std::fs::create_dir(&arg),
        "remove" => std::fs::remove_file(&arg),
        "tcp" => {
            TcpStream::connect_timeout(&arg.parse().unwrap(), Duration::from_secs(3)).map(|_| ())
        }
        other => panic!("unknown probe op {other}"),
    };
    common::report(r);
}

fn prepared(l: &Layout) -> (LocalOsBackend, SandboxId, PathBuf) {
    let mut b = LocalOsBackend::new();
    let id = b.prepare(&l.spec()).unwrap();
    let r = b.enforcement(&id).unwrap();
    assert_eq!(r.filesystem_writes, Level::Enforced);
    assert_eq!(r.network_egress, Level::Enforced);
    // The AppContainer can only execute images it can read: copy this test
    // binary into the workspace.
    let exe = l.ws.join("provio-probe.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
    (b, id, exe)
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn write_inside_workspace_and_private_temp_succeeds() {
    if !kernel_enforcement_available() {
        return;
    }
    let l = Layout::new();
    let (mut b, id, exe) = prepared(&l);
    let inside = l.ws.join("inside.txt");
    assert_eq!(
        run_probe(&mut b, &id, &exe, "write", s(&inside)).0,
        Probe::Ok
    );
    assert!(inside.is_file());
    let sub = l.ws.join("subdir");
    assert_eq!(run_probe(&mut b, &id, &exe, "mkdir", s(&sub)).0, Probe::Ok);
    let tmp = b.temp_dir(&id).unwrap().join("t.txt");
    assert_eq!(run_probe(&mut b, &id, &exe, "write", s(&tmp)).0, Probe::Ok);
}

#[test]
fn write_outside_workspace_is_access_denied() {
    if !kernel_enforcement_available() {
        return;
    }
    let l = Layout::new();
    let (mut b, id, exe) = prepared(&l);

    let target = l.outside.join("escape.txt");
    let (p, _) = run_probe(&mut b, &id, &exe, "write", s(&target));
    assert_eq!(p, Probe::Err(ERROR_ACCESS_DENIED));
    assert!(!target.exists());

    let dir = l.outside.join("newdir");
    let (p, _) = run_probe(&mut b, &id, &exe, "mkdir", s(&dir));
    assert_eq!(p, Probe::Err(ERROR_ACCESS_DENIED));
    assert!(!dir.exists());

    let victim = l.outside.join("victim.txt");
    std::fs::write(&victim, b"keep").unwrap();
    let (p, _) = run_probe(&mut b, &id, &exe, "remove", s(&victim));
    assert_eq!(p, Probe::Err(ERROR_ACCESS_DENIED));
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep");

    // The user's profile — writable by the parent, not by the sandbox.
    let home = PathBuf::from(std::env::var("USERPROFILE").unwrap())
        .join(format!("provio-probe-{}.txt", std::process::id()));
    let (p, _) = run_probe(&mut b, &id, &exe, "write", s(&home));
    let _ = std::fs::remove_file(&home);
    assert_eq!(p, Probe::Err(ERROR_ACCESS_DENIED));
}

#[test]
fn shell_redirect_outside_workspace_is_denied() {
    if !kernel_enforcement_available() {
        return;
    }
    let l = Layout::new();
    let mut b = LocalOsBackend::new();
    let id = b.prepare(&l.spec()).unwrap();
    let target = l.outside.join("cmd-escape.txt");
    let inside = l.ws.join("cmd-inside.txt");
    let script = format!(
        "echo in> {} & echo out> {}",
        inside.display(),
        target.display()
    );
    let out = b
        .exec(&id, &req("cmd", vec!["/c".into(), script], 10_000))
        .unwrap();
    assert!(
        text(&out.stderr).contains("Access is denied"),
        "stderr: {}",
        text(&out.stderr)
    );
    assert!(!target.exists());
    assert_eq!(std::fs::read_to_string(&inside).unwrap().trim(), "in");
}

#[test]
fn loopback_and_external_connect_are_blocked() {
    if !kernel_enforcement_available() {
        return;
    }
    let l = Layout::new();
    let (mut b, id, exe) = prepared(&l);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    // Control: the unsandboxed parent can reach the listener.
    drop(TcpStream::connect(addr).unwrap());
    listener.accept().unwrap();
    listener.set_nonblocking(true).unwrap();

    let (p, out) = run_probe(&mut b, &id, &exe, "tcp", &addr.to_string());
    assert!(matches!(p, Probe::Err(_)), "{p:?} {}", text(&out.stdout));
    assert!(
        listener.accept().is_err(),
        "the sandboxed child reached the loopback listener"
    );
    let (p, _) = run_probe(&mut b, &id, &exe, "tcp", "1.1.1.1:443");
    assert!(matches!(p, Probe::Err(_)), "{p:?}");
}

#[test]
fn job_object_enforces_active_process_limit() {
    if !kernel_enforcement_available() {
        return;
    }
    let l = Layout::new();
    let mut b = LocalOsBackend::new();
    let id = b.prepare(&l.spec()).unwrap();
    let nested = |depth: usize| {
        let mut args = Vec::new();
        for _ in 1..depth {
            args.extend(["/c".to_string(), "cmd".to_string()]);
        }
        args.extend(["/c".to_string(), "echo deep-marker".to_string()]);
        req("cmd", args, 60_000)
    };
    let ok = b.exec(&id, &nested(8)).unwrap();
    assert!(
        text(&ok.stdout).contains("deep-marker"),
        "{}",
        text(&ok.stderr)
    );
    let limit = provio_sandbox::ACTIVE_PROCESS_LIMIT as usize;
    let over = b.exec(&id, &nested(limit + 8)).unwrap();
    assert!(
        !text(&over.stdout).contains("deep-marker"),
        "a {}-deep process chain exceeded the job's active-process limit",
        limit + 8
    );
}

#[test]
fn best_effort_allow_list_is_reported_open_and_fs_stays_confined() {
    if !kernel_enforcement_available() {
        return;
    }
    let l = Layout::new();
    let mut spec = l.spec();
    spec.allowed_hosts = vec!["example.com".into()];
    let mut b = LocalOsBackend::with_mode(EnforcementMode::BestEffort);
    let id = b.prepare(&spec).unwrap();
    let r = b.enforcement(&id).unwrap().clone();
    assert_eq!(r.network_egress, Level::NotEnforced);
    assert_eq!(r.filesystem_writes, Level::Enforced);
    assert!(!r.fully_enforced());
    let exe = l.ws.join("provio-probe.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
    let target = l.outside.join("escape.txt");
    let (p, _) = run_probe(&mut b, &id, &exe, "write", s(&target));
    assert_eq!(p, Probe::Err(ERROR_ACCESS_DENIED));
}
