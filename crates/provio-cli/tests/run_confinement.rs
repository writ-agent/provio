//! `provio run -- <agent>` end to end: the real `provio` binary launches a
//! fake agent inside the kernel boundary.
//!
//! Every test runs against a throwaway fake home: HOME, USERPROFILE,
//! APPDATA, LOCALAPPDATA, XDG_*, CLAUDE_CONFIG_DIR, CODEX_HOME and
//! CARGO_HOME all point into a temp dir, so nothing here reads, creates or
//! labels anything in the real home or package caches. Windows integrity
//! labels applied by a test live only on its temp tree and disappear when
//! the tree is deleted.
//!
//! The generic agent is this test binary re-run as `probe_helper` (it
//! prints `PROBE-RESULT ...` to the inherited stdout). The fake `claude`
//! is a script that echoes its arguments and the `--settings` file — the
//! real Claude Code is never started.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const PROBE_OP: &str = "PROVIO_PROBE_OP";
const PROBE_ARG: &str = "PROVIO_PROBE_ARG";

/// Runs only when re-invoked by `provio run` with PROVIO_PROBE_OP set.
#[test]
fn probe_helper() {
    let Ok(op) = std::env::var(PROBE_OP) else {
        return;
    };
    let arg = std::env::var(PROBE_ARG).unwrap_or_default();
    let r: std::io::Result<()> = match op.as_str() {
        "stdin" => {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).map(|_| {
                println!("GOT:{}", line.trim_end());
            })
        }
        "write" => std::fs::File::create(&arg).and_then(|mut f| f.write_all(b"x")),
        "exit" => std::process::exit(arg.parse().unwrap()),
        other => panic!("unknown probe op {other}"),
    };
    match r {
        Ok(()) => println!("PROBE-RESULT ok"),
        Err(e) => println!("PROBE-RESULT err {}", e.raw_os_error().unwrap_or(-1)),
    }
}

// ---- fixture ---------------------------------------------------------------

struct TempTree(PathBuf);

impl TempTree {
    fn new() -> Self {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("provio-run-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        let p = p.canonicalize().unwrap();
        #[cfg(windows)]
        let p = PathBuf::from(p.to_string_lossy().trim_start_matches(r"\\?\"));
        TempTree(p)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    root: TempTree,
    ws: PathBuf,
    home: PathBuf,
    bin: PathBuf,
    outside: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = TempTree::new();
        let mk = |name: &str| {
            let p = root.0.join(name);
            std::fs::create_dir_all(&p).unwrap();
            p
        };
        let (ws, home, bin, outside) = (mk("ws"), mk("home"), mk("bin"), mk("outside"));
        std::fs::write(
            root.0.join("provio.yaml"),
            "version: 1\ndefault: allow\nrules: []\n",
        )
        .unwrap();
        Fixture {
            root,
            ws,
            home,
            bin,
            outside,
        }
    }

    fn cache_dir(&self) -> PathBuf {
        if cfg!(windows) {
            self.home.join("AppData").join("Local").join("npm-cache")
        } else {
            self.home.join(".npm")
        }
    }

    /// `provio --policy .. --ledger .. <args>` with cwd = workspace and the
    /// whole home environment pointed at the fake home.
    fn provio(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_provio"));
        let root = &self.root.0;
        c.arg("--policy")
            .arg(root.join("provio.yaml"))
            .arg("--ledger")
            .arg(root.join("ledger").join("ledger.jsonl"))
            .args(args)
            .current_dir(&self.ws);
        let h = &self.home;
        let path = std::env::join_paths(
            std::iter::once(self.bin.clone())
                .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
        )
        .unwrap();
        c.env("PATH", path)
            .env("HOME", h)
            .env("USERPROFILE", h)
            .env("APPDATA", h.join("AppData").join("Roaming"))
            .env("LOCALAPPDATA", h.join("AppData").join("Local"))
            .env("XDG_CONFIG_HOME", h.join(".config"))
            .env("XDG_CACHE_HOME", h.join(".cache"))
            .env("XDG_DATA_HOME", h.join(".local").join("share"))
            .env("XDG_STATE_HOME", h.join(".local").join("state"))
            .env("CLAUDE_CONFIG_DIR", h.join(".claude"))
            .env("CODEX_HOME", h.join(".codex"))
            .env("CARGO_HOME", h.join(".cargo"))
            .env_remove(PROBE_OP)
            .env_remove(PROBE_ARG)
            .stdin(Stdio::null());
        c
    }

    /// `provio <flags> run -- <this test binary as probe>`.
    fn run_probe(&self, flags: &[&str], op: &str, arg: &str) -> Output {
        let exe = std::env::current_exe().unwrap();
        let mut args: Vec<&str> = vec!["run"];
        args.extend_from_slice(flags);
        args.extend_from_slice(&[
            "--",
            exe.to_str().unwrap(),
            "probe_helper",
            "--exact",
            "--nocapture",
            "--test-threads=1",
            "-q",
        ]);
        self.provio(&args)
            .env(PROBE_OP, op)
            .env(PROBE_ARG, arg)
            .output()
            .unwrap()
    }

    /// A fake `claude` on PATH: echoes its argv, prints the `--settings`
    /// file, exits 3.
    fn fake_claude(&self) {
        if cfg!(windows) {
            std::fs::write(
                self.bin.join("claude.cmd"),
                "@echo off\r\necho ARGV:%*\r\nif \"%1\"==\"--settings\" type \"%2\"\r\nexit /b 3\r\n",
            )
            .unwrap();
        } else {
            let p = self.bin.join("claude");
            std::fs::write(
                &p,
                "#!/bin/sh\necho \"ARGV:$*\"\nif [ \"$1\" = \"--settings\" ]; then cat \"$2\"; fi\nexit 3\n",
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
    }
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Interactive boundary available? Honors PROVIO_SANDBOX_REQUIRE_ENFORCEMENT
/// (CI): an unsupported runner fails instead of skipping.
fn available() -> bool {
    let caps = provio_sandbox::interactive::capabilities();
    if caps.filesystem.is_full() {
        return true;
    }
    assert!(
        std::env::var_os("PROVIO_SANDBOX_REQUIRE_ENFORCEMENT").is_none(),
        "interactive kernel enforcement required but unavailable: {caps:?}"
    );
    eprintln!("SKIP: interactive enforcement unavailable: {caps:?}");
    false
}

fn probe_result(o: &Output) -> String {
    out(o)
        .lines()
        .find_map(|l| l.split_once("PROBE-RESULT ").map(|(_, r)| r.to_string()))
        .unwrap_or_else(|| panic!("no probe result; stdout {:?} stderr {:?}", out(o), err(o)))
}

// ---- tests -------------------------------------------------------------------

#[test]
fn stdin_reaches_the_confined_agent_and_exit_code_propagates() {
    if !available() {
        return;
    }
    let f = Fixture::new();
    let exe = std::env::current_exe().unwrap();
    let mut child = f
        .provio(&[
            "run",
            "--",
            exe.to_str().unwrap(),
            "probe_helper",
            "--exact",
            "--nocapture",
            "--test-threads=1",
            "-q",
        ])
        .env(PROBE_OP, "stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"hello from the terminal\n")
        .unwrap();
    let o = child.wait_with_output().unwrap();
    assert!(
        out(&o).contains("GOT:hello from the terminal"),
        "stdout {:?} stderr {:?}",
        out(&o),
        err(&o)
    );
    assert_eq!(o.status.code(), Some(0));
    assert!(err(&o).contains("filesystem : enforced"), "{}", err(&o));
    assert!(
        err(&o).contains("network    : open, not filtered"),
        "{}",
        err(&o)
    );

    let o = f.run_probe(&[], "exit", "7");
    assert_eq!(o.status.code(), Some(7), "{}", err(&o));
    assert!(err(&o).contains("exit 7 · recorded"), "{}", err(&o));
}

#[test]
fn writes_outside_workspace_and_to_caches_are_denied_by_default() {
    if !available() {
        return;
    }
    let f = Fixture::new();
    let o = f.run_probe(&[], "write", f.ws.join("in.txt").to_str().unwrap());
    assert_eq!(probe_result(&o), "ok", "{}", err(&o));
    let o = f.run_probe(&[], "write", f.outside.join("x.txt").to_str().unwrap());
    assert!(probe_result(&o).starts_with("err"), "{}", err(&o));
    assert!(!f.outside.join("x.txt").exists());
    // Shared package caches are opt-in.
    let cache = f.cache_dir();
    std::fs::create_dir_all(&cache).unwrap();
    let target = cache.join("poison");
    let o = f.run_probe(&[], "write", target.to_str().unwrap());
    assert!(probe_result(&o).starts_with("err"), "{}", err(&o));
    let o = f.run_probe(
        &["--allow-write", cache.to_str().unwrap()],
        "write",
        target.to_str().unwrap(),
    );
    assert_eq!(probe_result(&o), "ok", "{}", err(&o));
    assert!(err(&o).contains("--allow-write"), "{}", err(&o));
}

#[test]
fn claude_gets_hooks_via_settings_inserted_after_the_program_name() {
    if !available() {
        return;
    }
    let f = Fixture::new();
    f.fake_claude();
    std::fs::create_dir_all(f.cache_dir()).unwrap();
    let o = f
        .provio(&["run", "--", "claude", "hello"])
        .output()
        .unwrap();
    let stdout = out(&o);
    let stderr = err(&o);
    assert_eq!(o.status.code(), Some(3), "stdout {stdout} stderr {stderr}");
    let argv = stdout
        .lines()
        .find_map(|l| l.strip_prefix("ARGV:"))
        .unwrap_or_else(|| panic!("fake claude did not run: {stdout} {stderr}"));
    let parts: Vec<&str> = argv.split_whitespace().collect();
    assert_eq!(parts[0], "--settings", "{argv}");
    assert!(parts[1].ends_with("claude-settings.json"), "{argv}");
    assert_eq!(parts.last(), Some(&"hello"), "{argv}");
    // The settings file routes tool calls to `provio check` and pins
    // disableAllHooks to false.
    assert!(stdout.contains("claude-code"), "{stdout}");
    assert!(stdout.contains("\"check\""), "{stdout}");
    assert!(stdout.contains("\"disableAllHooks\": false"), "{stdout}");
    // The settings file lives outside the writable set and is gone after.
    assert!(!Path::new(parts[1]).exists());
    assert!(stderr.contains("profile    : claude"), "{stderr}");
    assert!(stderr.contains("hooks      : on"), "{stderr}");
    assert!(stderr.contains("disableAllHooks pinned false"), "{stderr}");
    assert!(
        stderr.contains("provio ledger (hooks append here)"),
        "{stderr}"
    );
    // Protection of the Claude settings files is stated, never overclaimed.
    if cfg!(target_os = "macos") {
        assert!(stderr.contains("kernel-enforced read-only"), "{stderr}");
    } else {
        assert!(stderr.contains("protected  : NO"), "{stderr}");
    }
    // Caches are suggested, not granted.
    assert!(stderr.contains("caches     : not writable"), "{stderr}");
    eprintln!(
        "--- banner ---
{stderr}"
    );
    // The profile's state dir was created in the fake home.
    assert!(f.home.join(".claude").is_dir());
    #[cfg(windows)]
    assert!(
        stderr.contains("PERSISTS"),
        "labels are announced first: {stderr}"
    );
}

#[test]
fn claude_with_its_own_settings_flag_is_refused() {
    let f = Fixture::new();
    f.fake_claude();
    let o = f
        .provio(&["run", "--", "claude", "--settings", "mine.json"])
        .output()
        .unwrap();
    assert_ne!(o.status.code(), Some(0));
    assert!(err(&o).contains("already has --settings"), "{}", err(&o));
    assert!(!out(&o).contains("ARGV:"), "the agent must not start");
    // --no-hooks: provio adds nothing, the user's flag passes through.
    if available() {
        let o = f
            .provio(&[
                "run",
                "--no-hooks",
                "--",
                "claude",
                "--settings",
                "mine.json",
            ])
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(3), "{}", err(&o));
        assert!(out(&o).contains("ARGV:--settings mine.json"), "{}", out(&o));
        assert!(err(&o).contains("hooks      : off"), "{}", err(&o));
    }
}

#[test]
fn unconfined_is_loudly_labelled_and_confines_nothing() {
    let f = Fixture::new();
    let target = f.outside.join("free.txt");
    let o = f.run_probe(&["--unconfined"], "write", target.to_str().unwrap());
    assert_eq!(probe_result(&o), "ok", "{}", err(&o));
    assert!(target.exists());
    let e = err(&o);
    assert!(e.contains("UNCONFINED"), "{e}");
    assert!(e.contains("filesystem : NOT enforced"), "{e}");
    assert!(!e.contains("PERSISTS"), "{e}");
    // Contradictory combinations are refused.
    let o = f
        .provio(&["run", "--unconfined", "--net", "none", "--", "x"])
        .output()
        .unwrap();
    assert_ne!(o.status.code(), Some(0));
    assert!(err(&o).contains("cannot be combined"), "{}", err(&o));
}

#[test]
fn net_none_is_enforced_or_refused_and_best_effort_labels_the_gap() {
    if !available() {
        return;
    }
    let f = Fixture::new();
    let net_deny = provio_sandbox::interactive::capabilities()
        .network_deny
        .is_full();
    let o = f.run_probe(&["--net", "none"], "exit", "0");
    if net_deny {
        assert_eq!(o.status.code(), Some(0), "{}", err(&o));
        assert!(
            err(&o).contains("none — all network denied by the kernel"),
            "{}",
            err(&o)
        );
    } else {
        assert_ne!(o.status.code(), Some(0));
        assert!(err(&o).contains("fail closed"), "{}", err(&o));
        assert!(err(&o).contains("--best-effort"), "{}", err(&o));
        let o = f.run_probe(&["--net", "none", "--best-effort"], "exit", "0");
        assert_eq!(o.status.code(), Some(0), "{}", err(&o));
        assert!(
            err(&o).contains("NOT enforced — the network is OPEN"),
            "{}",
            err(&o)
        );
    }
    // Best effort with full filesystem support still confines writes.
    let o = f.run_probe(
        &["--best-effort"],
        "write",
        f.outside.join("be.txt").to_str().unwrap(),
    );
    assert!(probe_result(&o).starts_with("err"), "{}", err(&o));
    assert!(err(&o).contains("filesystem : enforced"), "{}", err(&o));
}

#[test]
fn missing_allow_write_path_fails_closed() {
    if !available() {
        return;
    }
    let f = Fixture::new();
    let missing = f.root.0.join("nope");
    let o = f.run_probe(&["--allow-write", missing.to_str().unwrap()], "exit", "0");
    assert_ne!(o.status.code(), Some(0));
    assert!(err(&o).contains("does not exist"), "{}", err(&o));
}
