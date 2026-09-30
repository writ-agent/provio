//! `provio run`: governed process wrap (mode B).
//!
//! 1. The launch itself is a governed call: one `process.exec` decision is
//!    evaluated and recorded before anything runs.
//! 2. The agent is launched interactively (the user's terminal, exit code
//!    propagated) inside the kernel boundary of `provio_sandbox::interactive`:
//!    writes confined to the workspace (cwd), a private temp dir, the
//!    agent's own state dirs from its built-in profile, the ledger dir (when
//!    hooks are on) and any `--allow-write` paths (package caches are only
//!    suggested, never granted by default); network open-and-unfiltered
//!    (default) or none. Default mode refuses when the kernel cannot
//!    enforce that (fail closed); `--best-effort` runs and reports gaps;
//!    `--unconfined` launches with no boundary, loudly labelled.
//! 3. For agents with a per-invocation hook mechanism, unless
//!    `--no-hooks`, provio's hooks are passed in, so every tool call is
//!    decided by `provio check` (which runs inside the boundary and so needs
//!    the ledger dir writable). The provio-owned files live in a control dir
//!    outside the writable set:
//!    - Claude Code: `--settings <file>` (`disableAllHooks` pinned false);
//!    - OpenAI Codex CLI: `-c hooks.PreToolUse=… -c hooks.PostToolUse=…`
//!      session-flag overrides, `-c features.hooks=true`, and
//!      `--dangerously-bypass-hook-trust` (provio vets its own hooks; Codex
//!      otherwise skips a hook until it is reviewed in `/hooks`);
//!    - Gemini CLI: `GEMINI_CLI_SYSTEM_SETTINGS_PATH` → a copy of the
//!      system settings plus provio's hooks and `hooksConfig.enabled: true`
//!      (system settings override user and workspace), and
//!      `GEMINI_CLI_TRUST_WORKSPACE=true` (Gemini runs no hook at all in an
//!      untrusted folder);
//!    - Cursor CLI: `--plugin-dir <dir>` with a local plugin bundling the
//!      hooks (`failClosed`).
//!
//!    Agents without one (Windsurf is an IDE) get a pointer to
//!    `provio integrate <agent>`. After the run, provio says so if no tool call
//!    reached its hooks.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use provio_core::call::InterceptMode;
use provio_core::ledger::LedgerWriter;
use provio_core::pipeline::handle_call;
use provio_core::Timestamp;
use provio_sandbox::agents::{self, AgentProfile, EnvLookup, HookSupport, ProcessEnv};
use provio_sandbox::interactive::{self, Mode};
use provio_sandbox::{InteractiveReport, Net, Profile};
use provio_tui::{render_call_line, render_rule_note, TuiApprover};

use crate::cmds::{banner, emit_span, load_engine, make_call};
use crate::integrate::{self, Wiring};

/// Network for the wrapped agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum NetMode {
    /// The agent can reach the network (its model API); not filtered.
    Open,
    /// No network, kernel-enforced.
    None,
}

/// Everything `provio run` was asked to do.
#[derive(Debug)]
pub struct RunArgs {
    pub policy: PathBuf,
    pub ledger: PathBuf,
    pub yolo: bool,
    pub backend: String,
    pub net: NetMode,
    pub allow_write: Vec<PathBuf>,
    pub unconfined: bool,
    pub best_effort: bool,
    pub no_hooks: bool,
    pub cmd: Vec<String>,
}

/// One writable path and why it is in the set (for the banner).
struct Grant {
    path: PathBuf,
    why: String,
}

fn absolute(p: &Path, cwd: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    }
}

/// `canonicalize` without Windows' `\\?\` prefix (matches the sandbox's
/// canonical form, so banner reasons line up with the report).
fn canonical(p: &Path) -> Option<PathBuf> {
    let c = p.canonicalize().ok()?;
    #[cfg(windows)]
    {
        let s = c.to_string_lossy();
        if let Some(rest) = s.strip_prefix(r"\\?\") {
            if !rest.starts_with("UNC\\") && rest.len() < 248 {
                return Some(PathBuf::from(rest));
            }
        }
    }
    Some(c)
}

fn push_grant(grants: &mut Vec<Grant>, path: &Path, why: impl Into<String>) {
    if let Some(c) = canonical(path) {
        if !grants.iter().any(|g| g.path == c) {
            grants.push(Grant {
                path: c,
                why: why.into(),
            });
        }
    }
}

/// How the hooks were wired, for the banner.
enum Hooks {
    On {
        support: HookSupport,
        /// The provio-owned file or dir the hooks came from.
        via: PathBuf,
    },
    Off,
    Unsupported,
}

/// `caller.agent` of the decisions each hook format records.
fn hook_agent_label(s: HookSupport) -> &'static str {
    match s {
        HookSupport::ClaudeSettings => "claude-code",
        HookSupport::CodexConfigFlags => "codex",
        HookSupport::GeminiSystemSettings => "gemini-cli",
        HookSupport::CursorPluginDir => "cursor",
        HookSupport::None => "",
    }
}

/// `--flag value` / `--flag=value` / `-fvalue` values of a flag in `args`.
fn flag_values<'a>(args: &'a [String], long: &str, short: &str) -> Vec<&'a str> {
    let eq = format!("{long}=");
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == long || a == short {
            if let Some(v) = it.next() {
                out.push(v.as_str());
            }
        } else if let Some(v) = a.strip_prefix(&eq) {
            out.push(v);
        } else if let Some(v) = a.strip_prefix(short).filter(|v| !v.is_empty()) {
            if !a.starts_with("--") {
                out.push(v);
            }
        }
    }
    out
}

/// Refuse a command line that would override or switch off the hooks provio
/// is about to pass in.
fn check_hook_conflicts(support: HookSupport, args: &[String]) -> Result<()> {
    match support {
        HookSupport::ClaudeSettings => {
            if args
                .iter()
                .any(|a| a == "--settings" || a.starts_with("--settings="))
            {
                bail!(
                    "provio run passes its Claude Code hooks with --settings; your command already has \
                     --settings (Claude Code would keep only one). Move those settings into \
                     .claude/settings.json, or pass --no-hooks"
                );
            }
        }
        HookSupport::CodexConfigFlags => {
            for v in flag_values(args, "--config", "-c") {
                let key = v.split('=').next().unwrap_or("").trim();
                if key == "hooks"
                    || key.starts_with("hooks.")
                    || key == "features"
                    || key == "features.hooks"
                    || key == "features.codex_hooks"
                {
                    bail!(
                        "provio run passes its Codex hooks as `-c hooks.…` overrides and pins \
                         `features.hooks=true`; your command overrides `{key}`. Drop that \
                         override, or pass --no-hooks"
                    );
                }
            }
        }
        HookSupport::GeminiSystemSettings => {
            let env = |k: &str| ProcessEnv.get(k).map(|v| v.to_ascii_lowercase());
            if env("GEMINI_RESTRICTED_MODE").as_deref() == Some("true")
                || env("GEMINI_CLI_TRUST_WORKSPACE").as_deref() == Some("false")
            {
                bail!(
                    "provio run: GEMINI_RESTRICTED_MODE=true / GEMINI_CLI_TRUST_WORKSPACE=false make \
                     Gemini CLI run no hooks at all, so provio could not decide its tool calls. \
                     Unset it, or pass --no-hooks"
                );
            }
        }
        HookSupport::CursorPluginDir | HookSupport::None => {}
    }
    Ok(())
}

/// Codex session-flag overrides carrying provio's hooks.
fn codex_flags(w: &Wiring, args: &[String]) -> Result<Vec<String>> {
    let cmd = integrate::codex_hook_command(w)?;
    let group = format!(
        "[{{matcher={},hooks=[{{type={},command={},statusMessage={}}}]}}]",
        integrate::toml_string("*"),
        integrate::toml_string("command"),
        integrate::toml_string(&cmd),
        integrate::toml_string("provio policy check"),
    );
    let mut v = vec!["-c".to_string(), "features.hooks=true".to_string()];
    for ev in integrate::CODEX_EVENTS {
        v.push("-c".into());
        v.push(format!("hooks.{ev}={group}"));
    }
    // Codex runs a non-managed hook only once its hash is trusted in
    // /hooks; provio vets its own hooks, so trust review is bypassed for
    // this invocation (clap refuses the flag twice).
    if !args.iter().any(|a| a == "--dangerously-bypass-hook-trust") {
        v.push("--dangerously-bypass-hook-trust".into());
    }
    Ok(v)
}

fn default_gemini_system_settings() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\ProgramData\gemini-cli\settings.json")
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/GeminiCli/settings.json")
    } else {
        PathBuf::from("/etc/gemini-cli/settings.json")
    }
}

/// A provio-owned Gemini CLI *system* settings file: the current system
/// settings (kept) plus provio's hooks and `hooksConfig.enabled: true`.
/// Returns the file and the environment that points Gemini at it.
fn gemini_settings(w: &Wiring, control: &Path) -> Result<(PathBuf, Vec<(String, String)>)> {
    let orig = ProcessEnv
        .get("GEMINI_CLI_SYSTEM_SETTINGS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(default_gemini_system_settings);
    let base = match std::fs::read_to_string(&orig) {
        Ok(s) if !s.trim().is_empty() => serde_json::from_str::<serde_json::Value>(&s)
            .with_context(|| {
                format!(
                    "Gemini CLI system settings {} are not plain JSON; provio run cannot extend them",
                    orig.display()
                )
            })?,
        _ => serde_json::json!({}),
    };
    // A per-run hook name: a `hooksConfig.disabled` entry planted in the
    // user or workspace settings cannot name it in advance.
    let name = format!(
        "provio-{}-{}",
        std::process::id(),
        Timestamp::now().epoch_ms()
    );
    let mut merged =
        integrate::merge_gemini_settings(base, &integrate::gemini_hook_settings(w, &name))?;
    let root = merged
        .as_object_mut()
        .ok_or_else(|| anyhow!("Gemini CLI system settings are not a JSON object"))?;
    let hc = root
        .entry("hooksConfig")
        .or_insert_with(|| serde_json::json!({}));
    let hc = hc.as_object_mut().ok_or_else(|| {
        anyhow!("\"hooksConfig\" in the Gemini CLI system settings is not an object")
    })?;
    hc.insert("enabled".into(), serde_json::Value::Bool(true));
    let file = control.join("gemini-system-settings.json");
    std::fs::write(&file, serde_json::to_vec_pretty(&merged)?)
        .with_context(|| format!("write {}", file.display()))?;
    let defaults = ProcessEnv
        .get("GEMINI_CLI_SYSTEM_DEFAULTS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            orig.parent()
                .map(|p| p.join("system-defaults.json"))
                .unwrap_or_else(|| PathBuf::from("system-defaults.json"))
        });
    let env = vec![
        (
            "GEMINI_CLI_SYSTEM_SETTINGS_PATH".to_string(),
            file.display().to_string(),
        ),
        // Unchanged: Gemini derives the defaults path from the settings
        // path, which now points into provio's control dir.
        (
            "GEMINI_CLI_SYSTEM_DEFAULTS_PATH".to_string(),
            defaults.display().to_string(),
        ),
        ("GEMINI_CLI_TRUST_WORKSPACE".to_string(), "true".to_string()),
    ];
    Ok((file, env))
}

/// A local Cursor plugin (`.cursor-plugin/plugin.json` + `hooks/hooks.json`)
/// bundling provio's hooks, for `--plugin-dir`.
fn cursor_plugin(w: &Wiring, control: &Path) -> Result<PathBuf> {
    let dir = control.join("provio-cursor-plugin");
    std::fs::create_dir_all(dir.join(".cursor-plugin"))?;
    std::fs::create_dir_all(dir.join("hooks"))?;
    let manifest = serde_json::json!({
        "name": "provio-hooks",
        "version": "1.0.0",
        "description": "provio: policy decision and ledger record for every tool call (provio run)",
        "hooks": "./hooks/hooks.json",
    });
    std::fs::write(
        dir.join(".cursor-plugin").join("plugin.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    std::fs::write(
        dir.join("hooks").join("hooks.json"),
        serde_json::to_vec_pretty(&integrate::cursor_hook_settings(w)?)?,
    )?;
    Ok(dir)
}

/// Decisions recorded by `agent`'s hooks after ledger index `after`.
fn hook_decisions_since(ledger: &Path, after: u64, agent: &str) -> Option<usize> {
    let store = provio_ledger::open_store(ledger).ok()?;
    let mut n = 0;
    for rec in store.iter() {
        let rec = rec.ok()?;
        if rec.index > after
            && rec.kind == provio_core::ledger::RecordKind::Decision
            && rec.call.as_ref().is_some_and(|c| c.caller.agent == agent)
        {
            n += 1;
        }
    }
    Some(n)
}

/// The provio-owned control dir holding the Claude Code settings file. It is
/// deliberately NOT in the writable set: the agent cannot rewrite its own
/// hooks. Removed after the run.
struct ControlDir(PathBuf);

impl ControlDir {
    fn create() -> Result<Self> {
        let p = std::env::temp_dir().join(format!(
            "provio-run-ctl-{}-{}",
            std::process::id(),
            Timestamp::now().epoch_ms()
        ));
        std::fs::create_dir_all(&p).with_context(|| format!("create {}", p.display()))?;
        Ok(ControlDir(p))
    }
}

impl Drop for ControlDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn refusal_hint(net: Net) -> &'static str {
    if net == Net::None {
        "hint: `--net open` gives the agent the network (reported as not filtered); \
         `--best-effort` runs anyway and reports the gap"
    } else {
        "hint: `--best-effort` runs anyway and reports each gap; `--unconfined` launches with \
         no kernel boundary (launch supervision only)"
    }
}

/// `provio run -- <agent>`.
pub fn run(args: &RunArgs) -> Result<()> {
    let (policy, ledger, backend, cmd) = (
        args.policy.as_path(),
        args.ledger.as_path(),
        args.backend.as_str(),
        args.cmd.as_slice(),
    );
    if args.unconfined && (args.best_effort || args.net == NetMode::None) {
        bail!("provio run: --unconfined applies no boundary; it cannot be combined with --best-effort or --net none");
    }
    if args.unconfined && !args.allow_write.is_empty() {
        bail!("provio run: --allow-write has no effect with --unconfined (everything is writable)");
    }
    if !args.unconfined && backend != "local-os" {
        bail!("provio run: backend {backend} cannot host an interactive agent; only local-os can (or pass --unconfined)");
    }
    let net = match args.net {
        NetMode::Open => Net::Open,
        NetMode::None => Net::None,
    };
    let mode = if args.unconfined {
        Mode::Unconfined
    } else if args.best_effort {
        Mode::BestEffort
    } else {
        Mode::Required
    };
    let cwd = std::env::current_dir().context("current directory")?;
    let profile = agents::agent_profile(&cmd[0], &ProcessEnv);
    let hooks_wanted = profile.hooks != HookSupport::None && !args.no_hooks;
    if hooks_wanted {
        check_hook_conflicts(profile.hooks, &cmd[1..])?;
    }
    // Fail fast, before a human is asked to approve a launch that cannot
    // happen.
    if let Err(e) = interactive::preflight(net, mode) {
        bail!("provio run: {e}\n  {}", refusal_hint(net));
    }

    let engine = load_engine(policy, args.yolo)?;
    banner(&engine, policy, ledger);

    let mut store = provio_ledger::open_store(ledger).map_err(|e| anyhow!(e.to_string()))?;
    let session = format!("run-{}-{}", std::process::id(), Timestamp::now().epoch_ms());
    let cmdline = cmd.join(" ");
    let call = make_call(
        &session,
        0,
        "process.exec",
        serde_json::json!({ "command": cmdline }),
        InterceptMode::ProcessWrap,
    );
    let outcome = {
        let mut writer = LedgerWriter::new(&mut *store);
        handle_call(&call, &engine, &mut writer, &TuiApprover::new())
            .map_err(|e| anyhow!(e.to_string()))?
    };
    emit_span(ledger, &call, &outcome.verdict);
    eprintln!(
        "{}",
        render_call_line("process.exec", &cmdline, &outcome.verdict)
    );
    if let Some(note) = render_rule_note(&outcome.verdict) {
        eprintln!("{note}");
    }
    if !outcome.should_dispatch() {
        std::process::exit(126); // denied
    }

    // The writable set (not needed, and not created, when unconfined).
    let mut grants: Vec<Grant> = Vec::new();
    push_grant(&mut grants, &cwd, "workspace");
    if mode != Mode::Unconfined {
        let made = agents::materialize(&profile.paths).context("create the agent's state dirs")?;
        for p in &made {
            push_grant(
                &mut grants,
                &p.path,
                format!("{} — {}", profile.display, p.why),
            );
        }
        for p in &args.allow_write {
            let abs = absolute(p, &cwd);
            if canonical(&abs).is_none() {
                bail!(
                    "provio run: --allow-write {} does not exist (fail closed)",
                    p.display()
                );
            }
            push_grant(&mut grants, &abs, "--allow-write");
        }
    }

    // Per-tool-call hooks.
    let _control;
    let mut argv: Vec<String> = cmd[1..].to_vec();
    let mut agent_env = profile.env.clone();
    let hooks = if hooks_wanted {
        let provio_exe = std::env::current_exe().context("locate the provio binary")?;
        let policy_abs = canonical(policy).unwrap_or_else(|| absolute(policy, &cwd));
        let ledger_abs = if crate::cmds::is_pg(ledger) {
            // The hooks reach Postgres over the network as the agent's
            // children: no ledger dir to grant, but the connection string is
            // visible to the agent, so it must not carry a password.
            let url = ledger.to_string_lossy();
            if provio_ledger::redact_postgres_url(&url) != url {
                bail!(
                    "provio run: the Postgres ledger URL carries a password, which the agent \
                     could read from its hook command line; remove it from --ledger and use \
                     PGPASSWORD or ~/.pgpass (note: the agent's environment is readable by it)"
                );
            }
            if args.net == NetMode::None && mode != Mode::Unconfined {
                bail!(
                    "provio run: --net none would stop the hooks from reaching the Postgres \
                     ledger; use a file ledger with --net none, or --net open"
                );
            }
            ledger.to_path_buf()
        } else {
            let ledger_abs = absolute(ledger, &cwd);
            let ledger_dir = ledger_abs
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| cwd.clone());
            std::fs::create_dir_all(&ledger_dir)
                .with_context(|| format!("create {}", ledger_dir.display()))?;
            // `provio check` runs as the agent's child, inside the boundary: it
            // must append to the ledger and take `<ledger>.lock`.
            if mode != Mode::Unconfined {
                push_grant(
                    &mut grants,
                    &ledger_dir,
                    "provio ledger (hooks append here)",
                );
            }
            ledger_abs
        };
        let control = ControlDir::create()?;
        let w = Wiring {
            exe: &provio_exe,
            policy: &policy_abs,
            ledger: &ledger_abs,
        };
        let via = match profile.hooks {
            HookSupport::ClaudeSettings => {
                let mut settings =
                    integrate::claude_code_hook_settings(&provio_exe, &policy_abs, &ledger_abs);
                // Claude Code honours the `disableAllHooks` value left after
                // settings precedence, and `--settings` outranks local,
                // project and user settings: pinning `false` here means an
                // agent that writes `disableAllHooks: true` into those files
                // cannot switch provio's hooks off (only managed settings
                // could).
                if let Some(obj) = settings.as_object_mut() {
                    obj.insert("disableAllHooks".into(), serde_json::Value::Bool(false));
                }
                let file = control.0.join("claude-settings.json");
                std::fs::write(&file, serde_json::to_vec_pretty(&settings)?)
                    .with_context(|| format!("write {}", file.display()))?;
                argv.splice(0..0, ["--settings".to_string(), file.display().to_string()]);
                file
            }
            HookSupport::CodexConfigFlags => {
                let flags = codex_flags(&w, &cmd[1..]).context("provio run: Codex hooks")?;
                argv.splice(0..0, flags);
                PathBuf::from("-c hooks.PreToolUse, -c hooks.PostToolUse")
            }
            HookSupport::GeminiSystemSettings => {
                let (file, env) = gemini_settings(&w, &control.0)?;
                agent_env.retain(|(k, _)| !env.iter().any(|(e, _)| e == k));
                agent_env.extend(env);
                file
            }
            HookSupport::CursorPluginDir => {
                let dir = cursor_plugin(&w, &control.0).context("provio run: Cursor hooks")?;
                argv.splice(
                    0..0,
                    ["--plugin-dir".to_string(), dir.display().to_string()],
                );
                dir
            }
            HookSupport::None => unreachable!("hooks_wanted is false for HookSupport::None"),
        };
        _control = Some(control);
        Hooks::On {
            support: profile.hooks,
            via,
        }
    } else {
        _control = None;
        if profile.hooks != HookSupport::None {
            Hooks::Off
        } else {
            Hooks::Unsupported
        }
    };

    let mut protect = profile.protect.clone();
    protect.extend(profile.workspace_protect.iter().map(|rel| cwd.join(rel)));
    let sandbox_profile = Profile {
        workspace: cwd.clone(),
        writable: grants.iter().skip(1).map(|g| g.path.clone()).collect(),
        protect,
        net,
        mode,
    };

    // Windows: say which paths get a persistent Low integrity label BEFORE
    // anything is labelled.
    let all: Vec<PathBuf> = grants.iter().map(|g| g.path.clone()).collect();
    let to_label =
        interactive::persistent_labels(&all, mode).map_err(|e| anyhow!("provio run: {e}"))?;
    if !to_label.is_empty() {
        eprintln!(
            "\x1b[33m  provio · these paths get a Low integrity label that PERSISTS after the run \
             (any Low integrity process of yours can then write there):\x1b[0m"
        );
        for p in &to_label {
            eprintln!("      {}", p.display());
        }
        eprintln!(
            "    undo later with: icacls \"<path>\" /setintegritylevel (OI)(CI)M   (add /T to \
             reset files the agent created)"
        );
    }

    let (child, report) =
        provio_sandbox::spawn_interactive(&cmd[0], &argv, &agent_env, &sandbox_profile)
            .map_err(|e| anyhow!("provio run: {e}\n  {}", refusal_hint(net)))?;
    print_boundary(&report, &grants, &hooks, &profile);
    if profile.suggest_caches && mode != Mode::Unconfined {
        let existing = agents::materialize(&agents::tool_caches(&ProcessEnv)).unwrap_or_default();
        let missing: Vec<_> = existing
            .iter()
            .filter(|c| canonical(&c.path).is_some_and(|p| !report.writable.contains(&p)))
            .collect();
        if !missing.is_empty() {
            eprintln!("    caches     : not writable (opt in if the agent's tools need them):");
            for c in missing {
                eprintln!(
                    "                 --allow-write {}  ({})",
                    c.path.display(),
                    c.why
                );
            }
        }
    }

    // No content capture by default (spec §9): the execution record stores
    // the exit status and a hash of what was captured — intentionally
    // nothing.
    let code = child.wait().map_err(|e| anyhow!(e.to_string()))?;
    if let Hooks::On { support, .. } = &hooks {
        let agent = hook_agent_label(*support);
        if hook_decisions_since(ledger, outcome.record.index, agent) == Some(0) {
            eprintln!(
                "\x1b[33m  provio · no tool call reached provio's hooks during this run. If {} used \
                 tools, its hooks did not run (disabled, untrusted, or not supported by this \
                 version) and those calls were not governed.\x1b[0m",
                profile.display
            );
        }
    }
    let backend_label = if mode == Mode::Unconfined {
        "none (unconfined)"
    } else {
        backend
    };
    let mut writer = LedgerWriter::new(&mut *store);
    writer
        .record_execution(&outcome.record, backend_label, code, &[])
        .map_err(|e| anyhow!(e.to_string()))?;
    eprintln!("  provio · run complete · exit {code} · recorded");
    drop(_control);
    std::process::exit(code);
}

/// State exactly what is enforced (stderr; stdout belongs to the agent).
fn print_boundary(r: &InteractiveReport, grants: &[Grant], hooks: &Hooks, p: &AgentProfile) {
    let home = if cfg!(windows) {
        ProcessEnv.get("USERPROFILE")
    } else {
        ProcessEnv.get("HOME")
    }
    .and_then(|h| canonical(Path::new(&h)));
    let show = |path: &Path| agents::display_path(path, home.as_deref());
    if r.mode == Mode::Unconfined {
        eprintln!(
            "\x1b[31m  ⚠ UNCONFINED: no kernel boundary — the agent can write anywhere you can \
             and reach any host. Only the launch is governed.\x1b[0m"
        );
    } else {
        eprintln!("  provio · kernel boundary: {}", r.mechanism);
    }
    eprintln!("    profile    : {} ({})", p.name, p.display);
    eprintln!("    filesystem : {}", r.filesystem_line());
    eprintln!("    network    : {}", r.network_line());
    if r.mode != Mode::Unconfined {
        let mut first = true;
        let mut line = |text: String| {
            eprintln!(
                "    {} {text}",
                if first {
                    "writable   :"
                } else {
                    "            "
                }
            );
            first = false;
        };
        for w in &r.writable {
            let why = if *w == r.temp_dir {
                "private temp (TMPDIR/TEMP/TMP), removed after the run".to_string()
            } else {
                grants
                    .iter()
                    .find(|g| g.path == *w)
                    .map(|g| g.why.clone())
                    .unwrap_or_default()
            };
            line(format!("{}  ({why})", show(w)));
        }
    }
    match hooks {
        Hooks::On {
            support: HookSupport::CodexConfigFlags,
            ..
        } => {
            eprintln!(
                "    hooks      : on — Codex tool calls (shell, apply_patch, MCP, local function \
                 tools) are decided by `provio check` (-c hooks.PreToolUse/PostToolUse session \
                 overrides; features.hooks pinned true; --dangerously-bypass-hook-trust, so \
                 provio's hooks run without /hooks review — so does any other enabled hook)"
            );
            eprintln!(
                "                 not covered: hosted tools (web search), managed requirements \
                 (allow_managed_hooks_only, [features] hooks = false) and a nested `codex` the \
                 agent starts itself (still inside this boundary)"
            );
        }
        Hooks::On {
            support: HookSupport::GeminiSystemSettings,
            via,
        } => {
            eprintln!(
                "    hooks      : on — every Gemini CLI tool call is decided by `provio check` \
                 (GEMINI_CLI_SYSTEM_SETTINGS_PATH={}, outside the writable set: system settings \
                 override user/workspace, hooksConfig.enabled pinned true; the workspace is \
                 trusted for this run, since Gemini runs no hook in an untrusted folder)",
                via.display()
            );
            eprintln!(
                "                 not covered: a hook timeout (Gemini lets the tool run) and a \
                 nested `gemini` the agent starts itself (still inside this boundary)"
            );
        }
        Hooks::On {
            support: HookSupport::CursorPluginDir,
            via,
        } => {
            eprintln!(
                "    hooks      : on — Cursor tool calls are decided by `provio check` \
                 (--plugin-dir {}, a local plugin outside the writable set; failClosed)",
                via.display()
            );
            eprintln!(
                "                 not covered: Cursor versions that do not load plugin hooks \
                 from --plugin-dir (provio says so after the run if no call reached it)"
            );
        }
        Hooks::On { via: file, .. } => {
            eprintln!(
                "    hooks      : on — every Claude Code tool call is decided by `provio check` \
                 (--settings {}, outside the writable set; disableAllHooks pinned false, which \
                 outranks user/project/local settings)",
                file.display()
            );
            eprintln!(
                "                 not covered: managed settings (e.g. allowManagedHooksOnly) and \
                 a nested `claude` the agent starts itself (still inside this boundary)"
            );
        }
        Hooks::Off => eprintln!("    hooks      : off (--no-hooks) — only the launch is governed"),
        Hooks::Unsupported => eprintln!(
            "    hooks      : none — provio has no per-run tool-call hook for this agent; only the \
             launch is governed (Windsurf: `provio integrate windsurf`; MCP servers: `provio proxy`)"
        ),
    }
    if !r.protected.is_empty() && r.mode != Mode::Unconfined {
        let shown: Vec<String> = r.protected.iter().map(|p| show(p)).collect();
        match r.protection {
            provio_sandbox::Level::Enforced => eprintln!(
                "    protected  : {} — kernel-enforced read-only (no write, delete or replace)",
                shown.join(", ")
            ),
            _ => eprintln!(
                "    protected  : NO — the agent CAN rewrite {} (hooks planted there would run \
                 in later sessions outside provio); this kernel cannot exclude a file inside a \
                 writable directory",
                shown.join(", ")
            ),
        }
    }
    if !r.labelled.is_empty() {
        let shown: Vec<String> = r.labelled.iter().map(|p| show(p)).collect();
        eprintln!(
            "    labelled   : {} (Low integrity, persists; undo: icacls \"<path>\" \
             /setintegritylevel (OI)(CI)M)",
            shown.join(", ")
        );
    }
    for n in r.notes.iter().filter(|n| !n.starts_with("NOT protected")) {
        eprintln!("    note       : {n}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wiring() -> (PathBuf, PathBuf, PathBuf) {
        let base = std::env::temp_dir().join("provio-run-unit");
        (
            base.join("provio.exe"),
            base.join("provio.yaml"),
            base.join("ledger.jsonl"),
        )
    }

    #[test]
    fn codex_flags_are_valid_toml_without_batch_metacharacters() {
        let (e, p, l) = wiring();
        let w = Wiring {
            exe: &e,
            policy: &p,
            ledger: &l,
        };
        let flags = codex_flags(&w, &[]).unwrap();
        assert_eq!(&flags[..2], ["-c", "features.hooks=true"]);
        assert_eq!(flags.last().unwrap(), "--dangerously-bypass-hook-trust");
        let values: Vec<&String> = flags.iter().filter(|f| f.starts_with("hooks.")).collect();
        assert_eq!(values.len(), 2);
        for v in values {
            let (key, value) = v.split_once('=').unwrap();
            assert!(
                key == "hooks.PreToolUse" || key == "hooks.PostToolUse",
                "{key}"
            );
            if cfg!(windows) {
                assert!(!value.contains('"'), "{value}");
            }
            let doc: toml_edit::DocumentMut = format!("v = {value}").parse().unwrap();
            let group = doc["v"].as_array().unwrap().get(0).unwrap();
            let group = group.as_inline_table().unwrap();
            assert_eq!(group.get("matcher").unwrap().as_str(), Some("*"));
            let h = group
                .get("hooks")
                .unwrap()
                .as_array()
                .unwrap()
                .get(0)
                .unwrap();
            let h = h.as_inline_table().unwrap();
            assert_eq!(h.get("type").unwrap().as_str(), Some("command"));
            assert!(h
                .get("command")
                .unwrap()
                .as_str()
                .unwrap()
                .ends_with("check --format codex"));
        }
        // Never passed twice (clap would refuse it).
        let again = codex_flags(&w, &["--dangerously-bypass-hook-trust".into()]).unwrap();
        assert!(!again.contains(&"--dangerously-bypass-hook-trust".to_string()));
    }

    #[test]
    fn conflicting_codex_overrides_are_found() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let c = HookSupport::CodexConfigFlags;
        assert!(check_hook_conflicts(c, &args(&["-c", "hooks.PreToolUse=[]"])).is_err());
        assert!(check_hook_conflicts(c, &args(&["--config=features.hooks=false"])).is_err());
        assert!(check_hook_conflicts(c, &args(&["-cfeatures={hooks=false}"])).is_err());
        assert!(check_hook_conflicts(c, &args(&["-c", "model=o3", "exec", "hi"])).is_ok());
        assert!(check_hook_conflicts(c, &args(&["--color", "x"])).is_ok());
        let cl = HookSupport::ClaudeSettings;
        assert!(check_hook_conflicts(cl, &args(&["--settings=x.json"])).is_err());
    }
}
