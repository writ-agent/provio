//! Shared fixture for the per-agent `provio check` / `provio integrate` /
//! `provio run` tests (`check_codex.rs`, `check_gemini.rs`,
//! `check_cursor.rs`, `check_windsurf.rs`).
//!
//! Every process these tests start sees a throwaway fake home: HOME,
//! USERPROFILE, APPDATA, LOCALAPPDATA, XDG_*, CODEX_HOME, GEMINI_CLI_HOME,
//! CURSOR_CONFIG_DIR, CLAUDE_CONFIG_DIR and CARGO_HOME all point into the
//! project's temp dir, and the agents' own override variables are cleared.
//! The real agents are never started: `provio run` tests launch a fake agent
//! script that echoes its argv (and the files provio handed it).
#![allow(dead_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

pub const POLICY: &str = r#"version: 1
default: ask
rules:
  - id: launch
    when: tool == "process.exec"
    verdict: allow
  - id: no-rm
    when: tool == "bash" and command matches "rm -rf"
    verdict: deny
    reason: "Destructive command."
  - id: deploy
    when: tool == "bash" and command matches "^deploy"
    verdict: ask
    irreversible: true
    timeout: 10m
    reason: "Deploys need a human."
  - id: secrets-shell
    when: tool == "bash" and command matches "^cat secrets"
    verdict: redact
    patterns:
      - "\\b\\d{3}-\\d{2}-\\d{4}\\b"
  - id: ls-ok
    when: tool == "bash" and command matches "^(ls|echo)"
    verdict: allow
  - id: secrets
    when: path matches "\\.env$"
    verdict: deny
    reason: "Secrets are off limits."
  - id: read-ok
    when: tool == "fs.read"
    verdict: allow
  - id: write-src
    when: tool == "fs.write" and path matches "src"
    verdict: allow
  - id: egress
    when: tool == "http" and not url.host in hosts.allowed
    verdict: deny
    reason: "Host is not on the egress allow-list."
  - id: http-ok
    when: tool == "http"
    verdict: allow
  - id: gh-delete
    when: server == "github" and tool == "delete_repo"
    verdict: deny
    reason: "Repositories are not deleted by agents."
  - id: issues
    when: server == "github" and tool == "create_issue"
    verdict: ask
    reason: "Filing an issue speaks for the team."
  - id: gh-ok
    when: server == "github"
    verdict: allow
  - id: pii
    when: tool == "query"
    verdict: redact
    patterns:
      - "\\b\\d{3}-\\d{2}-\\d{4}\\b"
hosts:
  allowed: [api.github.com]
"#;

/// Environment variables the agents read that must not leak in from the
/// developer's machine.
const CLEARED: &[&str] = &[
    "GEMINI_CLI_SYSTEM_SETTINGS_PATH",
    "GEMINI_CLI_SYSTEM_DEFAULTS_PATH",
    "GEMINI_CLI_TRUST_WORKSPACE",
    "GEMINI_RESTRICTED_MODE",
];

/// A scratch project directory: `provio.yaml`, `.provio/ledger.jsonl` and a
/// fake home under `home/`.
pub struct Project(pub PathBuf);

impl Project {
    pub fn new() -> Self {
        let p = Self::bare();
        std::fs::write(p.0.join("provio.yaml"), POLICY).unwrap();
        p
    }

    pub fn bare() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "provio-agents-test-{}-{}-{id}",
            std::process::id(),
            std::thread::current()
                .name()
                .unwrap_or("t")
                .rsplit("::")
                .next()
                .unwrap_or("t")
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .take(24)
                .collect::<String>()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(path.join("home")).unwrap();
        std::fs::create_dir_all(path.join("bin")).unwrap();
        let path = path.canonicalize().unwrap();
        #[cfg(windows)]
        let path = PathBuf::from(path.to_string_lossy().trim_start_matches(r"\\?\"));
        Project(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn home(&self) -> PathBuf {
        self.0.join("home")
    }

    pub fn bin(&self) -> PathBuf {
        self.0.join("bin")
    }

    pub fn ledger(&self) -> PathBuf {
        self.0.join(".provio").join("ledger.jsonl")
    }

    pub fn records(&self) -> Vec<Value> {
        match std::fs::read_to_string(self.ledger()) {
            Ok(s) => s
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| serde_json::from_str(l).unwrap())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Point `c` at the fake home and scrub the agents' variables.
    pub fn isolate(&self, c: &mut Command) {
        let h = self.home();
        c.env("HOME", &h)
            .env("USERPROFILE", &h)
            .env("APPDATA", h.join("AppData").join("Roaming"))
            .env("LOCALAPPDATA", h.join("AppData").join("Local"))
            .env("XDG_CONFIG_HOME", h.join(".config"))
            .env("XDG_CACHE_HOME", h.join(".cache"))
            .env("XDG_DATA_HOME", h.join(".local").join("share"))
            .env("XDG_STATE_HOME", h.join(".local").join("state"))
            .env("CLAUDE_CONFIG_DIR", h.join(".claude"))
            .env("CODEX_HOME", h.join(".codex"))
            .env("GEMINI_CLI_HOME", &h)
            .env("CURSOR_CONFIG_DIR", h.join(".cursor"))
            .env("CARGO_HOME", h.join(".cargo"))
            .env("RUST_LOG", "off");
        for k in CLEARED {
            c.env_remove(k);
        }
    }

    /// Run `provio <args>` in the project with `stdin`.
    pub fn provio(&self, args: &[&str], stdin: &str) -> Output {
        let mut c = Command::new(env!("CARGO_BIN_EXE_provio"));
        c.args(args).current_dir(&self.0);
        self.isolate(&mut c);
        run_with_stdin(c, stdin)
    }

    /// `provio check --format <format> [extra]` with `payload`.
    pub fn hook(&self, format: &str, extra: &[&str], payload: &Value) -> Hook {
        let mut args = vec!["check", "--format", format];
        args.extend_from_slice(extra);
        Hook::from(self.provio(&args, &payload.to_string()))
    }

    pub fn verify(&self) -> String {
        let out = self.provio(&["verify"], "");
        assert!(
            out.status.success(),
            "verify failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Write a fake agent `name` into `bin/` that prints `ARGV:<args>`,
    /// then `script_tail` (sh / cmd), then exits 3.
    pub fn fake_agent(&self, name: &str, sh_tail: &str, cmd_tail: &str) {
        if cfg!(windows) {
            std::fs::write(
                self.bin().join(format!("{name}.cmd")),
                format!("@echo off\r\necho ARGV:%*\r\n{cmd_tail}\r\nexit /b 3\r\n"),
            )
            .unwrap();
        } else {
            let p = self.bin().join(name);
            std::fs::write(
                &p,
                format!("#!/bin/sh\necho \"ARGV:$*\"\n{sh_tail}\nexit 3\n"),
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
    }

    /// `provio --policy .. --ledger .. run <flags> -- <cmd>` with the fake
    /// agent's `bin/` first on PATH, inside the kernel boundary (an
    /// unconfined launch on Windows writes to the console, not to our
    /// pipes). Callers check [`boundary_available`] first.
    pub fn run_agent(&self, flags: &[&str], cmd: &[&str], env: &[(&str, &str)]) -> Output {
        let mut c = Command::new(env!("CARGO_BIN_EXE_provio"));
        c.arg("--policy")
            .arg(self.0.join("provio.yaml"))
            .arg("--ledger")
            .arg(self.ledger())
            .arg("run")
            .args(flags)
            .arg("--")
            .args(cmd)
            .current_dir(&self.0);
        self.isolate(&mut c);
        let path = std::env::join_paths(
            std::iter::once(self.bin())
                .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
        )
        .unwrap();
        c.env("PATH", path);
        for (k, v) in env {
            c.env(k, v);
        }
        c.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        spawn_retry(&mut c).wait_with_output().unwrap()
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Interactive kernel boundary available? Honors
/// PROVIO_SANDBOX_REQUIRE_ENFORCEMENT (CI): an unsupported runner fails
/// instead of skipping.
pub fn boundary_available() -> bool {
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

/// Spawn, retrying when Windows Application Control transiently blocks a
/// fresh binary (os error 4551).
pub fn spawn_retry(c: &mut Command) -> std::process::Child {
    let mut attempt = 0;
    loop {
        match c.spawn() {
            Ok(child) => return child,
            Err(e) if e.raw_os_error() == Some(4551) && attempt < 10 => {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
            Err(e) => panic!("spawn {c:?}: {e}"),
        }
    }
}

pub fn run_with_stdin(mut c: Command, stdin: &str) -> Output {
    c.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = spawn_retry(&mut c);
    {
        let mut i = child.stdin.take().unwrap();
        let _ = i.write_all(stdin.as_bytes());
    }
    child.wait_with_output().unwrap()
}

/// One hook invocation's result.
#[derive(Debug)]
pub struct Hook {
    /// The single stdout JSON line, if any.
    pub json: Option<Value>,
    pub code: i32,
    pub stderr: String,
    pub stdout: String,
}

impl From<Output> for Hook {
    fn from(out: Output) -> Self {
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
        assert!(
            lines.len() <= 1,
            "at most one stdout line expected, got {stdout:?}"
        );
        let json = lines.first().map(|l| {
            assert!(l.is_ascii(), "hook output must be ASCII: {l}");
            serde_json::from_str(l).unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {l}"))
        });
        Hook {
            json,
            code: out.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            stdout,
        }
    }
}

impl Hook {
    pub fn j(&self) -> &Value {
        self.json
            .as_ref()
            .unwrap_or_else(|| panic!("no JSON on stdout (stderr: {})", self.stderr))
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    provio_core::ledger::LedgerRecord::hash_bytes(bytes)
}

/// The shells agents use to run a hook command line.
#[derive(Clone, Copy, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Shell {
    /// `sh -c` (Codex/Cursor on Unix with a POSIX $SHELL).
    Sh,
    /// `bash -c` (Gemini CLI and Windsurf on Unix).
    Bash,
    /// `cmd.exe /C "<line>"` exactly as Codex builds it on Windows.
    Cmd,
    /// `powershell -NoProfile -Command <line>` (Codex's default shell on
    /// Windows; Windsurf's `powershell` field).
    PowerShell,
    /// Gemini CLI on Windows: PowerShell with its appended exit check.
    GeminiPowerShell,
}

/// Run hook command line `line` under `shell` with `payload` on stdin.
pub fn run_in_shell(shell: Shell, line: &str, payload: &Value, p: &Project) -> Hook {
    let mut c = match shell {
        Shell::Sh => {
            let mut c = Command::new("sh");
            c.arg("-c").arg(line);
            c
        }
        Shell::Bash => {
            let mut c = Command::new("bash");
            c.arg("-c").arg(line);
            c
        }
        Shell::Cmd => {
            let mut c = Command::new("cmd.exe");
            c.arg("/C");
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                c.raw_arg(format!("\"{line}\""));
            }
            c
        }
        Shell::PowerShell => {
            let mut c = Command::new("powershell.exe");
            c.args(["-NoProfile", "-Command", line]);
            c
        }
        Shell::GeminiPowerShell => {
            let mut c = Command::new("powershell.exe");
            c.args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!("{line}; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}"),
            ]);
            c
        }
    };
    // Hooks run from the workspace (or elsewhere): paths must be absolute.
    c.current_dir(std::env::temp_dir());
    p.isolate(&mut c);
    Hook::from(run_with_stdin(c, &payload.to_string()))
}

/// The shells to exercise a portable hook command under on this platform.
pub fn portable_shells() -> Vec<Shell> {
    if cfg!(windows) {
        vec![Shell::Cmd, Shell::PowerShell]
    } else {
        vec![Shell::Sh, Shell::Bash]
    }
}

pub fn decisions(recs: &[Value]) -> Vec<&Value> {
    recs.iter().filter(|r| r["kind"] == "decision").collect()
}

pub fn executions(recs: &[Value]) -> Vec<&Value> {
    recs.iter().filter(|r| r["kind"] == "execution").collect()
}

/// Corrupt the first ledger record so the ledger can be neither read nor
/// appended.
pub fn corrupt_ledger(p: &Project) {
    let text = std::fs::read_to_string(p.ledger()).unwrap();
    std::fs::write(p.ledger(), text.replacen('{', "X", 1)).unwrap();
}
