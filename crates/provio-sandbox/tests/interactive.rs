//! Interactive confinement (`provio run`'s boundary), syscall level, on every
//! OS: this test binary is re-run inside the boundary as `probe_helper`,
//! performs one operation, and reports through its exit code (the child
//! inherits the terminal, so stdout is not captured): 0 = ok,
//! 100 + OS error code = failed with that code, 99 = failed without one.
//!
//! On Linux, workspaces live under the system temp dir (not WSL's 9p
//! `/mnt/c`, which Landlock rules cannot match).

mod common;

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{Layout, TestDir};
use provio_sandbox::interactive::{capabilities, Mode};
use provio_sandbox::{spawn_interactive, InteractiveReport, Level, Net, Profile};

/// The error code a denied write produces.
#[cfg(target_os = "linux")]
const WRITE_DENIED: i32 = libc::EACCES;
#[cfg(target_os = "macos")]
const WRITE_DENIED: i32 = libc::EPERM;
#[cfg(windows)]
const WRITE_DENIED: i32 = 5; // ERROR_ACCESS_DENIED

fn code_for(r: std::io::Result<()>) -> i32 {
    match r {
        Ok(()) => 0,
        Err(e) => match e.raw_os_error() {
            Some(c) if (0..150).contains(&c) => 100 + c,
            _ => 99,
        },
    }
}

/// Runs only when re-invoked inside the boundary with PROVIO_PROBE_OP set.
#[test]
fn probe_helper() {
    let Ok(op) = std::env::var(common::PROBE_OP) else {
        return;
    };
    let arg = std::env::var(common::PROBE_ARG).unwrap_or_default();
    let r = match op.as_str() {
        "write" => std::fs::File::create(&arg).and_then(|mut f| f.write_all(b"x")),
        "overwrite" => std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&arg)
            .and_then(|mut f| f.write_all(b"new")),
        "mkdir" => std::fs::create_dir(&arg),
        "remove" => std::fs::remove_file(&arg),
        "rename-over" => {
            // The atomic-write pattern: a sibling temp file renamed onto the target.
            let tmp = format!("{arg}.tmp.{}", std::process::id());
            std::fs::write(&tmp, b"planted").and_then(|_| std::fs::rename(&tmp, &arg))
        }
        "write-temp" => {
            let p = std::env::temp_dir().join(format!("probe-{}", std::process::id()));
            std::fs::write(&p, b"t").and_then(|_| {
                if arg.is_empty() || std::env::temp_dir().starts_with(&arg) {
                    Ok(())
                } else {
                    Err(std::io::Error::other("temp dir is not the private one"))
                }
            })
        }
        "tcp" => {
            TcpStream::connect_timeout(&arg.parse().unwrap(), Duration::from_secs(3)).map(|_| ())
        }
        #[cfg(target_os = "linux")]
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
        #[cfg(unix)]
        "unix-pair" => std::os::unix::net::UnixStream::pair().map(|_| ()),
        "exit" => std::process::exit(arg.parse().unwrap()),
        other => panic!("unknown probe op {other}"),
    };
    std::process::exit(code_for(r));
}

/// Interactive boundary available here? Honors PROVIO_SANDBOX_REQUIRE_ENFORCEMENT
/// (CI): an unsupported runner fails instead of skipping.
fn available() -> bool {
    let caps = capabilities();
    if caps.filesystem.is_full() {
        return true;
    }
    let dir = TestDir::new();
    let err = spawn_interactive("x", &[], &[], &profile(dir.path(), vec![], Net::Open))
        .err()
        .expect("an unenforceable boundary must fail closed");
    assert!(err.to_string().contains("fail closed"), "{err}");
    assert!(
        std::env::var_os("PROVIO_SANDBOX_REQUIRE_ENFORCEMENT").is_none(),
        "interactive kernel enforcement required but unavailable: {caps:?}"
    );
    eprintln!("SKIP: interactive enforcement unavailable: {caps:?}");
    false
}

fn net_deny_available() -> bool {
    capabilities().network_deny.is_full()
}

fn profile(ws: &Path, writable: Vec<PathBuf>, net: Net) -> Profile {
    Profile {
        workspace: ws.to_path_buf(),
        writable,
        protect: Vec::new(),
        net,
        mode: Mode::Required,
    }
}

/// Run the probe inside `p`; return (exit code, report).
fn probe(p: &Profile, op: &str, arg: &str) -> (i32, InteractiveReport) {
    let exe = std::env::current_exe().unwrap();
    let args: Vec<String> = [
        "probe_helper",
        "--exact",
        "--nocapture",
        "--test-threads=1",
        "-q",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let env = vec![
        (common::PROBE_OP.to_string(), op.to_string()),
        (common::PROBE_ARG.to_string(), arg.to_string()),
    ];
    let (child, report) = spawn_interactive(exe.to_str().unwrap(), &args, &env, p).unwrap();
    (child.wait().unwrap(), report)
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn writes_inside_workspace_temp_and_extra_dir_succeed() {
    if !available() {
        return;
    }
    let l = Layout::new();
    let extra = l.root.sub("agent-state");
    let p = profile(&l.ws, vec![extra.clone()], Net::Open);
    let (code, r) = probe(&p, "write", s(&l.ws.join("in.txt")));
    assert_eq!(code, 0);
    assert_eq!(r.filesystem_writes, Level::Enforced);
    assert!(r.writable.contains(&r.temp_dir));
    assert_eq!(std::fs::read(l.ws.join("in.txt")).unwrap(), b"x");
    assert_eq!(probe(&p, "mkdir", s(&l.ws.join("sub"))).0, 0);
    assert_eq!(probe(&p, "write", s(&extra.join("state.json"))).0, 0);
    let (code, r) = probe(&p, "write-temp", "");
    assert_eq!(code, 0);
    assert!(
        !r.temp_dir.exists(),
        "the private temp dir is removed after the run"
    );
}

#[test]
fn writes_outside_the_writable_set_are_denied() {
    if !available() {
        return;
    }
    let l = Layout::new();
    let p = profile(&l.ws, vec![], Net::Open);
    let target = l.outside.join("escape.txt");
    assert_eq!(probe(&p, "write", s(&target)).0, 100 + WRITE_DENIED);
    assert!(!target.exists());
    let dir = l.outside.join("newdir");
    assert_eq!(probe(&p, "mkdir", s(&dir)).0, 100 + WRITE_DENIED);
    assert!(!dir.exists());
    let victim = l.outside.join("victim.txt");
    std::fs::write(&victim, b"keep").unwrap();
    assert_eq!(probe(&p, "overwrite", s(&victim)).0, 100 + WRITE_DENIED);
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
}

#[test]
fn a_writable_file_can_be_rewritten_but_its_directory_stays_closed() {
    if !available() {
        return;
    }
    let l = Layout::new();
    let file = l.outside.join("agent.json");
    std::fs::write(&file, b"{}").unwrap();
    let p = profile(&l.ws, vec![file.clone()], Net::Open);
    assert_eq!(probe(&p, "overwrite", s(&file)).0, 0);
    assert_eq!(std::fs::read(&file).unwrap(), b"new");
    let other = l.outside.join("other.txt");
    assert_eq!(probe(&p, "write", s(&other)).0, 100 + WRITE_DENIED);
    assert!(!other.exists());
}

#[test]
fn exit_code_propagates() {
    if !available() {
        return;
    }
    let l = Layout::new();
    let p = profile(&l.ws, vec![], Net::Open);
    assert_eq!(probe(&p, "exit", "7").0, 7);
    assert_eq!(probe(&p, "exit", "0").0, 0);
}

#[test]
fn net_open_allows_a_loopback_connect() {
    if !available() {
        return;
    }
    let l = Layout::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (code, r) = probe(&profile(&l.ws, vec![], Net::Open), "tcp", &addr);
    assert_eq!(code, 0);
    assert_eq!(r.network_deny, Level::NotEnforced);
    assert!(r.network_line().contains("not filtered"));
}

#[test]
fn net_none_blocks_connect_or_is_refused() {
    if !available() {
        return;
    }
    let l = Layout::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let p = profile(&l.ws, vec![], Net::None);
    if !net_deny_available() {
        // Windows: a Low integrity token cannot deny network; Required
        // mode must refuse rather than pretend.
        let err = spawn_interactive("x", &[], &[], &p).err().unwrap();
        assert!(err.to_string().contains("--net none"), "{err}");
        let mut be = p.clone();
        be.mode = Mode::BestEffort;
        let (code, r) = probe(&be, "tcp", &addr);
        assert_eq!(code, 0, "best effort leaves the network open");
        assert_eq!(r.network_deny, Level::NotEnforced);
        assert!(r.network_line().contains("NOT enforced"));
        return;
    }
    let (code, r) = probe(&p, "tcp", &addr);
    assert_eq!(r.network_deny, Level::Enforced);
    #[cfg(unix)]
    assert_eq!(code, 100 + libc::EPERM);
    #[cfg(not(unix))]
    assert_ne!(code, 0);
    assert!(
        listener.accept().is_err(),
        "the confined child reached the listener"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn net_open_still_denies_io_uring_and_keeps_unix_sockets() {
    if !available() {
        return;
    }
    let l = Layout::new();
    let p = profile(&l.ws, vec![], Net::Open);
    assert_eq!(probe(&p, "io_uring", "").0, 100 + libc::EPERM);
    assert_eq!(probe(&p, "unix-pair", "").0, 0);
}

#[test]
fn unconfined_applies_nothing_and_says_so() {
    let l = Layout::new();
    let mut p = profile(&l.ws, vec![], Net::Open);
    p.mode = Mode::Unconfined;
    let target = l.outside.join("free.txt");
    let (code, r) = probe(&p, "write", s(&target));
    assert_eq!(code, 0);
    assert!(target.exists());
    assert_eq!(r.filesystem_writes, Level::NotEnforced);
    assert!(r.filesystem_line().contains("NOT enforced"));
    assert!(r.notes.iter().any(|n| n.contains("UNCONFINED")));
}

#[test]
fn missing_writable_path_fails_closed() {
    let l = Layout::new();
    let p = profile(&l.ws, vec![l.root.path().join("nope")], Net::Open);
    let err = spawn_interactive("x", &[], &[], &p).err().unwrap();
    assert!(err.to_string().contains("does not exist"), "{err}");
}

#[cfg(windows)]
#[test]
fn windows_labels_are_previewed_reported_and_idempotent() {
    use provio_sandbox::interactive::persistent_labels;
    if !available() {
        return;
    }
    let l = Layout::new();
    let extra = l.root.sub("state");
    std::fs::write(extra.join("pre-existing.txt"), b"old").unwrap();
    let p = profile(&l.ws, vec![extra.clone()], Net::Open);
    // Preview before launch: both will be labelled.
    let preview = persistent_labels(&[l.ws.clone(), extra.clone()], Mode::Required).unwrap();
    assert_eq!(preview.len(), 2, "{preview:?}");
    assert!(
        persistent_labels(std::slice::from_ref(&extra), Mode::Unconfined)
            .unwrap()
            .is_empty()
    );
    // Existing children inherit the label: overwriting one works.
    let (code, r) = probe(&p, "overwrite", s(&extra.join("pre-existing.txt")));
    assert_eq!(code, 0);
    assert_eq!(r.labelled, preview);
    assert!(
        !r.labelled.contains(&r.temp_dir),
        "the temp dir label is not persistent"
    );
    // Second run: already labelled, nothing new.
    let (_, r) = probe(&p, "exit", "0");
    assert!(r.labelled.is_empty(), "{:?}", r.labelled);
    assert!(
        persistent_labels(std::slice::from_ref(&extra), Mode::Required)
            .unwrap()
            .is_empty()
    );
    // The user's profile stays closed.
    let home = PathBuf::from(std::env::var("USERPROFILE").unwrap())
        .join(format!("provio-probe-{}.txt", std::process::id()));
    let (code, _) = probe(&p, "write", s(&home));
    let _ = std::fs::remove_file(&home);
    assert_eq!(code, 100 + WRITE_DENIED);
    // Labels applied here live only on the test tree, removed with it.
}

/// Agent config inside a writable dir must stay unwritable where the
/// kernel allows it — never claimed where it does not.
#[test]
fn protected_files_are_kept_or_reported_unprotected() {
    if !available() {
        return;
    }
    let l = Layout::new();
    let state = l.root.sub("state");
    let settings = state.join("settings.json");
    std::fs::write(&settings, b"{}").unwrap();
    let absent = state.join("settings.local.json");
    let mut p = profile(&l.ws, vec![state.clone()], Net::Open);
    p.protect = vec![settings.clone(), absent.clone()];

    // The rest of the directory stays writable.
    let (code, r) = probe(&p, "write", s(&state.join("history.jsonl")));
    assert_eq!(code, 0);
    let results = [
        probe(&p, "overwrite", s(&settings)).0,
        probe(&p, "remove", s(&settings)).0,
        probe(&p, "rename-over", s(&settings)).0,
        probe(&p, "write", s(&absent)).0,
    ];
    let intact = std::fs::read(&settings).ok().as_deref() == Some(&b"{}"[..]) && !absent.exists();
    eprintln!(
        "protection {:?}: results {results:?}, intact {intact}",
        r.protection
    );
    match r.protection {
        Level::Enforced => {
            assert!(results.iter().all(|&c| c != 0), "{results:?}");
            assert!(intact);
        }
        Level::Partial | Level::NotEnforced => {
            assert!(
                r.notes
                    .iter()
                    .any(|n| n.contains("NOT protected") || n.contains("PARTIAL")),
                "a gap must be stated: {:?}",
                r.notes
            );
        }
    }
    #[cfg(any(target_os = "linux", windows))]
    assert_eq!(r.protection, Level::NotEnforced);
    #[cfg(target_os = "macos")]
    assert_eq!(r.protection, Level::Enforced);
}
