//! Linux kernel-enforcement tests (Landlock + seccomp), run under WSL2 and
//! CI's ubuntu-latest.
//!
//! Syscall-level: this test binary is re-run inside the sandbox as
//! `probe_helper`, which issues exactly one syscall (open/mkdir/unlink/
//! rename/symlink/truncate/socket/connect/socketpair/io_uring_setup) and
//! reports the errno. Workspaces live under the system temp dir (ext4/tmpfs
//! in WSL2, not the 9p `/mnt/c` mount — see linux.rs on drvfs).
#![cfg(target_os = "linux")]

mod common;

use std::io::Write;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{kernel_enforcement_available, req, run_probe, text, Layout, Probe};
use provio_core::sandbox::{SandboxBackend, SandboxId};
use provio_sandbox::{EnforcementMode, Level, LocalOsBackend};

const EPERM: i32 = libc::EPERM;
const EACCES: i32 = libc::EACCES;
const EXDEV: i32 = libc::EXDEV;

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
        "truncate" => {
            let c = std::ffi::CString::new(arg.clone()).unwrap();
            // SAFETY: c is a valid NUL-terminated path.
            if unsafe { libc::truncate(c.as_ptr(), 0) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
        "tcp" => {
            TcpStream::connect_timeout(&arg.parse().unwrap(), Duration::from_secs(3)).map(|_| ())
        }
        "udp" => UdpSocket::bind("127.0.0.1:0").map(|_| ()),
        "unix" => UnixStream::connect(&arg).map(|_| ()),
        "socketpair" => UnixStream::pair().map(|_| ()),
        "io_uring" => {
            let mut params = [0u8; 120]; // struct io_uring_params
                                         // SAFETY: io_uring_setup(entries, params*) with a zeroed,
                                         // correctly sized params buffer.
            let fd = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1u32, params.as_mut_ptr()) };
            if fd >= 0 {
                // SAFETY: fd is a valid descriptor we own.
                unsafe { libc::close(fd as i32) };
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
        other => panic!("unknown probe op {other}"),
    };
    common::report(r);
}

fn exe() -> PathBuf {
    std::env::current_exe().unwrap()
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
    run_probe(b, id, &exe(), op, arg).0
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
    assert_eq!(std::fs::read(&f).unwrap(), b"x");
    assert_eq!(probe(&mut b, &id, "append", s(&f)), Probe::Ok);
    assert_eq!(probe(&mut b, &id, "truncate", s(&f)), Probe::Ok);
    let d = l.ws.join("sub");
    assert_eq!(probe(&mut b, &id, "mkdir", s(&d)), Probe::Ok);
    let moved = d.join("moved.txt");
    assert_eq!(
        probe(&mut b, &id, "rename", &format!("{}|{}", s(&f), s(&moved))),
        Probe::Ok
    );
    assert_eq!(
        probe(
            &mut b,
            &id,
            "symlink",
            &format!("{}|{}", s(&moved), s(&l.ws.join("ln")))
        ),
        Probe::Ok
    );
    assert_eq!(probe(&mut b, &id, "remove", s(&moved)), Probe::Ok);
    let t = b.temp_dir(&id).unwrap().join("t.txt");
    assert_eq!(probe(&mut b, &id, "write", s(&t)), Probe::Ok);
    assert_eq!(probe(&mut b, &id, "write", "/dev/null"), Probe::Ok);
}

#[test]
fn writes_outside_workspace_are_denied_by_landlock() {
    if !kernel_enforcement_available() {
        return;
    }
    let l = Layout::new();
    let (mut b, id) = prepared(&l);

    let f = l.outside.join("escape.txt");
    assert_eq!(probe(&mut b, &id, "write", s(&f)), Probe::Err(EACCES));
    assert!(!f.exists());

    let victim = l.outside.join("victim.txt");
    std::fs::write(&victim, b"keep").unwrap();
    assert_eq!(probe(&mut b, &id, "append", s(&victim)), Probe::Err(EACCES));
    assert_eq!(
        probe(&mut b, &id, "truncate", s(&victim)),
        Probe::Err(EACCES)
    );
    assert_eq!(probe(&mut b, &id, "remove", s(&victim)), Probe::Err(EACCES));
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep");

    let d = l.outside.join("newdir");
    assert_eq!(probe(&mut b, &id, "mkdir", s(&d)), Probe::Err(EACCES));
    let ln = l.outside.join("ln");
    assert_eq!(
        probe(&mut b, &id, "symlink", &format!("/etc/passwd|{}", s(&ln))),
        Probe::Err(EACCES)
    );

    // Moving a workspace file out, or an outside file in, is denied too.
    let inside = l.ws.join("in.txt");
    std::fs::write(&inside, b"in").unwrap();
    let out = probe(
        &mut b,
        &id,
        "rename",
        &format!("{}|{}", s(&inside), s(&l.outside.join("moved.txt"))),
    );
    assert!(
        matches!(out, Probe::Err(EACCES) | Probe::Err(EXDEV)),
        "{out:?}"
    );
    let back = probe(
        &mut b,
        &id,
        "rename",
        &format!("{}|{}", s(&victim), s(&l.ws.join("stolen.txt"))),
    );
    assert!(
        matches!(back, Probe::Err(EACCES) | Probe::Err(EXDEV)),
        "{back:?}"
    );
    assert!(inside.exists() && victim.exists());

    // $HOME and system paths.
    if let Some(home) = std::env::var_os("HOME") {
        let h = PathBuf::from(home).join(format!(".provio-probe-{}", std::process::id()));
        let p = probe(&mut b, &id, "write", s(&h));
        let _ = std::fs::remove_file(&h);
        assert_eq!(p, Probe::Err(EACCES));
    }
}

#[test]
fn landlock_holds_for_root() {
    if !kernel_enforcement_available() {
        return;
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("SKIP: not running as root; DAC alone would deny /etc writes");
        return;
    }
    let l = Layout::new();
    let (mut b, id) = prepared(&l);
    // Root bypasses DAC (CAP_DAC_OVERRIDE); only Landlock can deny this.
    let etc = format!("/etc/provio-probe-{}", std::process::id());
    let p = probe(&mut b, &id, "write", &etc);
    let _ = std::fs::remove_file(&etc);
    assert_eq!(p, Probe::Err(EACCES));
    // Control: the unsandboxed root parent can write there.
    std::fs::write(&etc, b"x").unwrap();
    std::fs::remove_file(&etc).unwrap();
}

#[test]
fn shell_grandchildren_inherit_the_boundary() {
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
    assert_ne!(out.exit_code, 0);
    assert!(
        text(&out.stderr).contains("Permission denied"),
        "stderr: {}",
        text(&out.stderr)
    );
    assert!(!target.exists());
    assert_eq!(
        std::fs::read_to_string(l.ws.join("inside.txt")).unwrap(),
        "in\n"
    );
}

#[test]
fn network_egress_is_denied_by_seccomp() {
    if !kernel_enforcement_available() {
        return;
    }
    let l = Layout::new();
    let (mut b, id) = prepared(&l);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    // Control: the unsandboxed parent can connect.
    drop(TcpStream::connect(addr).unwrap());
    listener.accept().unwrap();
    listener.set_nonblocking(true).unwrap();

    assert_eq!(
        probe(&mut b, &id, "tcp", &addr.to_string()),
        Probe::Err(EPERM)
    );
    assert!(
        listener.accept().is_err(),
        "sandboxed child reached the listener"
    );
    assert_eq!(probe(&mut b, &id, "tcp", "1.1.1.1:443"), Probe::Err(EPERM));
    assert_eq!(probe(&mut b, &id, "udp", ""), Probe::Err(EPERM));
    assert_eq!(probe(&mut b, &id, "io_uring", ""), Probe::Err(EPERM));

    // Pathname unix sockets (docker.sock, D-Bus, resolvers) are denied too;
    // in-process socketpair(AF_UNIX) is not.
    let sock = l.outside.join("s.sock");
    let _ul = UnixListener::bind(&sock).unwrap();
    assert_eq!(probe(&mut b, &id, "unix", s(&sock)), Probe::Err(EPERM));
    assert_eq!(probe(&mut b, &id, "socketpair", ""), Probe::Ok);
}

/// Opt-in: characterize Landlock on another filesystem (e.g. WSL2's 9p
/// `/mnt/c`). `PROVIO_SANDBOX_TEST_FS_ROOT=/mnt/c/... cargo test -- --ignored`
#[test]
#[ignore = "needs PROVIO_SANDBOX_TEST_FS_ROOT"]
fn workspace_on_custom_filesystem() {
    let Some(root) = std::env::var_os("PROVIO_SANDBOX_TEST_FS_ROOT") else {
        return;
    };
    let root = PathBuf::from(root).join(format!("provio-fs-{}", std::process::id()));
    let (ws, outside) = (root.join("ws"), root.join("outside"));
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    let mut b = LocalOsBackend::new();
    let id = match b.prepare(&common::spec_for(&ws)) {
        Ok(id) => id,
        Err(e) => {
            // 9p (WSL2 /mnt/c) is rejected up front with a clear error.
            eprintln!("fs root {}: prepare refused: {e}", root.display());
            let _ = std::fs::remove_dir_all(&root);
            assert!(e.to_string().contains("9p"), "{e}");
            return;
        }
    };
    let inside = probe(&mut b, &id, "write", s(&ws.join("in.txt")));
    let escape = probe(&mut b, &id, "write", s(&outside.join("out.txt")));
    eprintln!(
        "fs root {}: inside={inside:?} outside={escape:?}",
        root.display()
    );
    let _ = std::fs::remove_dir_all(&root);
    // Never an allow outside; inside may spuriously fail on unstable-inode
    // filesystems (documented caveat).
    assert_eq!(escape, Probe::Err(EACCES));
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
    assert!(r.notes.iter().any(|n| n.contains("OPEN")), "{:?}", r.notes);

    // The report is honest: the network really is open...
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    assert_eq!(probe(&mut b, &id, "tcp", &addr.to_string()), Probe::Ok);
    // ...and the filesystem boundary still holds.
    let f = l.outside.join("escape.txt");
    assert_eq!(probe(&mut b, &id, "write", s(&f)), Probe::Err(EACCES));
}
