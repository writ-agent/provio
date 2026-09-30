//! macOS kernel-enforcement tests (Seatbelt), run on CI's macos-latest.
//! Compile-checked (`--target x86_64-apple-darwin`) but not executed in the
//! Windows/WSL development environment.
//!
//! Syscall-level: this test binary is re-run inside the sandbox as
//! `probe_helper`, which issues exactly one syscall and reports the errno.
//! Seatbelt denials surface as EPERM (sometimes EACCES), so both are
//! accepted as "denied"; success is asserted exactly.
#![cfg(target_os = "macos")]

mod common;

use std::io::Write;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{kernel_enforcement_available, req, run_probe, text, Layout, Probe};
use provio_core::sandbox::{SandboxBackend, SandboxId};
use provio_sandbox::{EnforcementMode, Level, LocalOsBackend};

const EPERM: i32 = 1;
const EACCES: i32 = 13;
const EXDEV: i32 = 18;

fn denied(p: &Probe) -> bool {
    matches!(p, Probe::Err(EPERM) | Probe::Err(EACCES))
}

/// Runs only when re-invoked inside the sandbox with PROVIO_PROBE_OP set.
#[test]
fn probe_helper() {
    let Ok(op) = std::env::var(common::PROBE_OP) else {
        return;
    };
    let arg = std::env::var(common::PROBE_ARG).unwrap_or_default();
    let two = || {
        let (a, b) = arg.split_once('|').expect("a|b");
        (a.to_string(), b.to_string())
    };
    let r = match op.as_str() {
        "write" => std::fs::File::create(&arg).and_then(|mut f| f.write_all(b"x")),
        "append" => std::fs::OpenOptions::new()
            .append(true)
            .open(&arg)
            .and_then(|mut f| f.write_all(b"x")),
        "mkdir" => std::fs::create_dir(&arg),
        "remove" => std::fs::remove_file(&arg),
        "rename" => {
            let (a, b) = two();
            std::fs::rename(a, b)
        }
        "symlink" => {
            let (a, b) = two();
            std::os::unix::fs::symlink(a, b)
        }
        "tcp" => {
            TcpStream::connect_timeout(&arg.parse().unwrap(), Duration::from_secs(3)).map(|_| ())
        }
        "udp" => UdpSocket::bind("127.0.0.1:0").and_then(|s| s.send_to(b"x", &arg).map(|_| ())),
        "unix" => UnixStream::connect(&arg).map(|_| ()),
        other => panic!("unknown probe op {other}"),
    };
    common::report(r);
}

fn prepared(l: &Layout) -> (LocalOsBackend, SandboxId) {
    let mut b = LocalOsBackend::new();
    let id = b.prepare(&l.spec()).unwrap();
    let r = b.enforcement(&id).unwrap();
    assert!(r.fully_enforced(), "{r:?}");
    (b, id)
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn probe(b: &mut LocalOsBackend, id: &SandboxId, op: &str, arg: &str) -> Probe {
    run_probe(b, id, &std::env::current_exe().unwrap(), op, arg).0
}

#[test]
fn writes_inside_workspace_and_private_temp_succeed() {
    if !kernel_enforcement_available() {
        return;
    }
    let l = Layout::new();
    let (mut b, id) = prepared(&l);
    let f = l.ws.join("inside.txt");
    assert_eq!(probe(&mut b, &id, "write", s(&f)), Probe::Ok);
    assert_eq!(probe(&mut b, &id, "append", s(&f)), Probe::Ok);
    let d = l.ws.join("sub");
    assert_eq!(probe(&mut b, &id, "mkdir", s(&d)), Probe::Ok);
    let moved = d.join("moved.txt");
    assert_eq!(
        probe(&mut b, &id, "rename", &format!("{}|{}", s(&f), s(&moved))),
        Probe::Ok
    );
    assert_eq!(probe(&mut b, &id, "remove", s(&moved)), Probe::Ok);
    let t = b.temp_dir(&id).unwrap().join("t.txt");
    assert_eq!(probe(&mut b, &id, "write", s(&t)), Probe::Ok);
    assert_eq!(probe(&mut b, &id, "write", "/dev/null"), Probe::Ok);
}

#[test]
fn writes_outside_workspace_are_denied_by_seatbelt() {
    if !kernel_enforcement_available() {
        return;
    }
    let l = Layout::new();
    let (mut b, id) = prepared(&l);

    let f = l.outside.join("escape.txt");
    let p = probe(&mut b, &id, "write", s(&f));
    assert!(denied(&p), "{p:?}");
    assert!(!f.exists());

    let victim = l.outside.join("victim.txt");
    std::fs::write(&victim, b"keep").unwrap();
    let p = probe(&mut b, &id, "append", s(&victim));
    assert!(denied(&p), "{p:?}");
    let p = probe(&mut b, &id, "remove", s(&victim));
    assert!(denied(&p), "{p:?}");
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep");

    let p = probe(&mut b, &id, "mkdir", s(&l.outside.join("newdir")));
    assert!(denied(&p), "{p:?}");
    let p = probe(
        &mut b,
        &id,
        "symlink",
        &format!("/etc/passwd|{}", s(&l.outside.join("ln"))),
    );
    assert!(denied(&p), "{p:?}");

    let inside = l.ws.join("in.txt");
    std::fs::write(&inside, b"in").unwrap();
    let p = probe(
        &mut b,
        &id,
        "rename",
        &format!("{}|{}", s(&inside), s(&l.outside.join("moved.txt"))),
    );
    assert!(denied(&p) || p == Probe::Err(EXDEV), "{p:?}");
    assert!(inside.exists());

    if let Some(home) = std::env::var_os("HOME") {
        let h = PathBuf::from(home).join(format!(".provio-probe-{}", std::process::id()));
        let p = probe(&mut b, &id, "write", s(&h));
        let _ = std::fs::remove_file(&h);
        assert!(denied(&p), "{p:?}");
    }
}

#[test]
fn shell_grandchildren_inherit_the_profile() {
    if !kernel_enforcement_available() {
        return;
    }
    let l = Layout::new();
    let (mut b, id) = prepared(&l);
    let target = l.outside.join("sh-escape.txt");
    let script = format!(
        "echo in > inside.txt && echo quiet > /dev/null && sh -c 'echo out > {}'",
        target.display()
    );
    let out = b
        .exec(&id, &req("sh", vec!["-c".into(), script], 10_000))
        .unwrap();
    assert_ne!(out.exit_code, 0, "stderr: {}", text(&out.stderr));
    assert!(!target.exists());
    assert_eq!(
        std::fs::read_to_string(l.ws.join("inside.txt")).unwrap(),
        "in\n"
    );
}

#[test]
fn network_egress_is_denied_by_seatbelt() {
    if !kernel_enforcement_available() {
        return;
    }
    let l = Layout::new();
    let (mut b, id) = prepared(&l);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(TcpStream::connect(addr).unwrap()); // control: parent can connect
    listener.accept().unwrap();
    listener.set_nonblocking(true).unwrap();

    let p = probe(&mut b, &id, "tcp", &addr.to_string());
    assert!(denied(&p), "{p:?}");
    assert!(
        listener.accept().is_err(),
        "sandboxed child reached the listener"
    );
    let p = probe(&mut b, &id, "tcp", "1.1.1.1:443");
    assert!(denied(&p), "{p:?}");
    let p = probe(&mut b, &id, "udp", "1.1.1.1:53");
    assert!(denied(&p), "{p:?}");

    let sock = l.outside.join("s.sock");
    let _ul = UnixListener::bind(&sock).unwrap();
    let p = probe(&mut b, &id, "unix", s(&sock));
    assert!(denied(&p), "{p:?}");
}

#[test]
fn best_effort_allow_list_leaves_network_open_and_says_so() {
    if !kernel_enforcement_available() {
        return;
    }
    let l = Layout::new();
    let mut spec = l.spec();
    spec.allowed_hosts = vec!["example.com".into()];
    assert!(LocalOsBackend::new().prepare(&spec).is_err());

    let mut b = LocalOsBackend::with_mode(EnforcementMode::BestEffort);
    let id = b.prepare(&spec).unwrap();
    let r = b.enforcement(&id).unwrap().clone();
    assert_eq!(r.network_egress, Level::NotEnforced);
    assert_eq!(r.filesystem_writes, Level::Enforced);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    assert_eq!(probe(&mut b, &id, "tcp", &addr.to_string()), Probe::Ok);
    let p = probe(&mut b, &id, "write", s(&l.outside.join("escape.txt")));
    assert!(denied(&p), "{p:?}");
}
