//! `provio integrate`: wire provio into an agent's own configuration.
//!
//! | target        | file (project, current directory)            | events |
//! |---------------|----------------------------------------------|--------|
//! | `claude-code` | `.claude/settings.json`                      | PreToolUse, PostToolUse, PostToolUseFailure |
//! | `codex`       | `.codex/config.toml` (inline `[hooks]`)      | PreToolUse, PostToolUse |
//! | `gemini`      | `.gemini/settings.json`                      | BeforeTool, AfterTool |
//! | `cursor`      | `.cursor/hooks.json`                         | preToolUse, beforeMCPExecution, postToolUse, postToolUseFailure |
//! | `windsurf`    | `.devin/hooks.json` (or legacy `.windsurf/hooks.json`) | pre_/post_ run_command, read_code, write_code, mcp_tool_use |
//!
//! The same guarantees for every target:
//!
//! - every other setting, and every hook that is not provio's, is preserved
//!   (JSON keys come out sorted; for TOML, formatting and comments are kept, via
//!   `toml_edit`);
//! - provio's own entries — hooks that run `provio ... check --format <agent>`
//!   — are replaced, never duplicated, so running it twice changes nothing
//!   and re-running after moving the binary updates the paths;
//! - paths are absolute: the running provio executable
//!   (`std::env::current_exe`), the policy and the ledger;
//! - the policy must exist and compile first — a hook pointing at a missing
//!   policy would deny every tool call;
//! - the file is replaced atomically (write to a sibling temp file, then
//!   rename); a file that does not parse, or whose `hooks` has the wrong
//!   shape, is refused rather than overwritten.
//!
//! `--print` prints the merged configuration instead of writing it.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Map, Value};

use crate::cmds::load_engine;

/// Agents `provio integrate` knows how to configure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Target {
    /// Claude Code hooks in `.claude/settings.json`.
    ClaudeCode,
    /// OpenAI Codex CLI hooks in `.codex/config.toml`.
    Codex,
    /// Gemini CLI hooks in `.gemini/settings.json`.
    Gemini,
    /// Cursor hooks in `.cursor/hooks.json`.
    Cursor,
    /// Windsurf (Cascade) hooks in `.devin/hooks.json` / `.windsurf/hooks.json`.
    Windsurf,
}

pub fn integrate(policy: &Path, ledger: &Path, target: Target, print: bool) -> Result<()> {
    let policy = std::path::absolute(policy).context("resolve --policy")?;
    let ledger = if crate::cmds::is_pg(ledger) {
        // Hook configs are project files, often committed: never write a
        // database password into them. libpq-style fallbacks (PGPASSWORD,
        // ~/.pgpass) reach the hook through the agent's environment.
        let url = ledger.to_string_lossy();
        if provio_ledger::redact_postgres_url(&url) != url {
            bail!(
                "refusing to write a Postgres password into agent hook configuration; \
                 remove it from --ledger ({}) and provide it via PGPASSWORD or ~/.pgpass",
                crate::cmds::show_ledger(ledger)
            );
        }
        ledger.to_path_buf()
    } else {
        std::path::absolute(ledger).context("resolve --ledger")?
    };
    load_engine(&policy, false).with_context(|| {
        format!(
            "refusing to integrate: the hooks would deny every tool call until {} loads",
            policy.display()
        )
    })?;
    let exe = std::env::current_exe().context("locate the running provio executable")?;
    let w = Wiring {
        exe: &exe,
        policy: &policy,
        ledger: &ledger,
    };
    match target {
        Target::ClaudeCode => integrate_claude_code(&w, print),
        Target::Codex => integrate_codex(&w, print),
        Target::Gemini => integrate_gemini(&w, print),
        Target::Cursor => integrate_cursor(&w, print),
        Target::Windsurf => integrate_windsurf(&w, print),
    }
}

/// The absolute paths every hook entry is built from.
pub(crate) struct Wiring<'a> {
    pub exe: &'a Path,
    pub policy: &'a Path,
    pub ledger: &'a Path,
}

fn footer(w: &Wiring) -> String {
    format!(
        "  policy: {}\n  ledger: {}",
        w.policy.display(),
        w.ledger.display()
    )
}

fn integrate_claude_code(w: &Wiring, print: bool) -> Result<()> {
    let fragment = claude_code_hook_settings(w.exe, w.policy, w.ledger);
    let settings_path = PathBuf::from(".claude").join("settings.json");
    let existing = read_json_object_file(&settings_path)?;
    let merged = merge_hook_settings(existing, &fragment)?;
    let text = serde_json::to_string_pretty(&merged)? + "\n";
    if print {
        print!("{text}");
        return Ok(());
    }
    write_atomic(&settings_path, &text)?;
    eprintln!(
        "  provio · Claude Code hooks written to {} (PreToolUse, PostToolUse, PostToolUseFailure)\n{}",
        settings_path.display(),
        footer(w)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Files

/// A JSON settings file as an object: missing or blank → `{}`; anything
/// that is not valid JSON is refused.
fn read_json_object_file(path: &Path) -> Result<Value> {
    match std::fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => Ok(Value::Object(Map::new())),
        Ok(s) => serde_json::from_str::<Value>(&s)
            .with_context(|| format!("{} is not valid JSON; not touching it", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Value::Object(Map::new())),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

/// Write `text` to `path` atomically (sibling temp file + rename),
/// creating the parent directory.
pub(crate) fn write_atomic(path: &Path, text: &str) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "settings".into());
    let tmp = path.with_file_name(format!(".{name}.provio-{}.tmp", std::process::id()));
    std::fs::write(&tmp, text).with_context(|| format!("write {}", tmp.display()))?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("replace {}", path.display()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Hook command lines

/// `provio --policy P --ledger L check --format <format> [--ask defer]`.
pub(crate) fn hook_argv(w: &Wiring, format: &str, ask_defer: bool) -> Vec<String> {
    let mut v = vec![
        w.exe.display().to_string(),
        "--policy".into(),
        w.policy.display().to_string(),
        "--ledger".into(),
        w.ledger.display().to_string(),
        "check".into(),
        "--format".into(),
        format.into(),
    ];
    if ask_defer {
        v.extend(["--ask".into(), "defer".into()]);
    }
    v
}

fn is_bare(s: &str, extra: &[char]) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./:".contains(c) || extra.contains(&c))
}

/// POSIX shell (sh, bash, zsh) quoting: bare when safe, else single quotes.
pub(crate) fn posix_quote(s: &str) -> String {
    if is_bare(s, &['=', '@', '%', '+', ',']) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

pub(crate) fn posix_command(argv: &[String]) -> String {
    argv.iter()
        .map(|a| posix_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

fn powershell_quote(s: &str) -> String {
    if is_bare(s, &[]) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "''"))
    }
}

/// PowerShell: `& 'exe' args…`; with `propagate`, `; exit $LASTEXITCODE`
/// (`powershell -Command` otherwise exits 1 for any failing native
/// command, which the agent would not treat as a block).
pub(crate) fn powershell_command(argv: &[String], propagate: bool) -> String {
    let mut s = format!("& {}", format_args!("'{}'", argv[0].replace('\'', "''")));
    for a in &argv[1..] {
        s.push(' ');
        s.push_str(&powershell_quote(a));
    }
    if propagate {
        s.push_str("; exit $LASTEXITCODE");
    }
    s
}

/// A command line that runs unchanged under whichever shell the agent
/// picks (Codex and Cursor use the session's shell: sh/bash/zsh, and on
/// Windows cmd.exe or PowerShell). POSIX quoting on Unix; on Windows every
/// token must be bare (forward slashes, no spaces or shell metacharacters)
/// — a path that would need quoting is refused rather than written as a
/// hook that fails to start (and so, for most agents, does not block).
pub(crate) fn portable_command(argv: &[String]) -> Result<String> {
    if cfg!(windows) {
        let toks: Vec<String> = argv.iter().map(|a| a.replace('\\', "/")).collect();
        // `~` is literal in cmd.exe and in PowerShell except as a token's
        // first character (home), and it is common in 8.3 short paths
        // (C:/Users/RUNNER~1/...).
        if let Some(bad) = toks
            .iter()
            .find(|t| !is_bare(t, &['~']) || t.starts_with('~'))
        {
            bail!(
                "{bad:?} cannot be written into a hook command that works under both cmd.exe and \
                 PowerShell (it needs quoting). Move provio, the policy and the ledger to paths \
                 without spaces or shell metacharacters (e.g. `--policy C:/work/proj/provio.yaml`)"
            );
        }
        Ok(toks.join(" "))
    } else {
        Ok(posix_command(argv))
    }
}

/// Is `cmd` (a hook command line, any quoting) provio's gateway for
/// `format`?
fn is_provio_command(cmd: &str, format: &str) -> bool {
    let plain: String = cmd.chars().filter(|c| *c != '\'' && *c != '"').collect();
    // `writ`: hooks written before the rename (writ → provio) are ours too,
    // so re-integrating replaces them instead of adding a second hook.
    (plain.contains("provio") || plain.contains("writ"))
        && plain.contains(&format!("check --format {format}"))
}

// ---------------------------------------------------------------------------
// Claude Code / Gemini CLI shape: {"hooks": {Event: [{matcher, hooks: [...]}]}}

/// Merge `fragment` (`{"hooks": {event: [groups]}}`) into `settings`,
/// replacing provio's own previous hook entries and keeping everything else.
pub(crate) fn merge_hook_settings(settings: Value, fragment: &Value) -> Result<Value> {
    merge_hook_groups(settings, fragment, &is_provio_hook, "Claude Code settings")
}

/// [`merge_hook_settings`] for any agent with Claude Code's grouped shape.
fn merge_hook_groups(
    mut settings: Value,
    fragment: &Value,
    is_ours: &dyn Fn(&Value) -> bool,
    label: &str,
) -> Result<Value> {
    let root = settings
        .as_object_mut()
        .ok_or_else(|| anyhow!("{label} must be a JSON object; not touching it"))?;
    let hooks = root
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()));
    let hooks = hooks
        .as_object_mut()
        .ok_or_else(|| anyhow!("\"hooks\" in {label} is not an object; not touching it"))?;
    let Some(new_hooks) = fragment.get("hooks").and_then(Value::as_object) else {
        bail!("internal: hook fragment has no \"hooks\" object");
    };
    for (event, new_groups) in new_hooks {
        let groups = hooks
            .entry(event.clone())
            .or_insert_with(|| Value::Array(Vec::new()));
        let groups = groups.as_array_mut().ok_or_else(|| {
            anyhow!("\"hooks.{event}\" in {label} is not an array; not touching it")
        })?;
        // Drop provio's previous handlers; drop groups left empty by that.
        groups.retain_mut(|group| {
            let Some(list) = group.get_mut("hooks").and_then(Value::as_array_mut) else {
                return true;
            };
            let before = list.len();
            list.retain(|h| !is_ours(h));
            !(before > 0 && list.is_empty())
        });
        if let Some(arr) = new_groups.as_array() {
            groups.extend(arr.iter().cloned());
        }
    }
    Ok(settings)
}

/// A command hook that runs provio's Claude Code gateway: exec form with a
/// `provio` executable and `check`/`claude-code` in its args, or a shell-form
/// command line containing `check --format claude-code`.
fn is_provio_hook(h: &Value) -> bool {
    let Some(cmd) = h.get("command").and_then(Value::as_str) else {
        return false;
    };
    if let Some(args) = h.get("args").and_then(Value::as_array) {
        let stem = Path::new(cmd)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        let has = |a: &str| args.iter().any(|x| x.as_str() == Some(a));
        return (stem.eq_ignore_ascii_case("provio") || stem.eq_ignore_ascii_case("writ"))
            && has("check")
            && has("claude-code");
    }
    cmd.contains("check --format claude-code")
}

/// The Claude Code settings fragment (`{"hooks": {...}}`) that routes every
/// tool call through `provio check --format claude-code`. Shared by
/// `provio integrate claude-code` and `provio run -- claude` (which passes it to
/// Claude Code with `--settings`). `provio_exe` is the absolute path of the
/// provio binary; `policy`/`ledger` are passed through as absolute paths.
///
/// Exec form (`command` + `args`, no shell) so paths with spaces, quotes or
/// backslashes need no quoting on any platform. `PostToolUseFailure` records
/// the execution of tools that failed. `--ask defer` turns a provio `ask` into
/// Claude Code's own permission prompt.
pub(crate) fn claude_code_hook_settings(
    provio_exe: &Path,
    policy: &Path,
    ledger: &Path,
) -> serde_json::Value {
    let hook = serde_json::json!([{
        "matcher": "*",
        "hooks": [{
            "type": "command",
            "command": provio_exe.display().to_string(),
            "args": [
                "--policy", policy.display().to_string(),
                "--ledger", ledger.display().to_string(),
                "check", "--format", "claude-code", "--ask", "defer"
            ]
        }]
    }]);
    serde_json::json!({ "hooks": {
        "PreToolUse": hook,
        "PostToolUse": hook,
        "PostToolUseFailure": hook,
    } })
}

// ---------------------------------------------------------------------------
// Gemini CLI

/// Gemini CLI runs a hook command with `bash -c` (Unix) or PowerShell
/// `-Command` (Windows, which appends its own `$LASTEXITCODE` check).
pub(crate) fn gemini_hook_command(w: &Wiring) -> String {
    let argv = hook_argv(w, "gemini", true);
    if cfg!(windows) {
        powershell_command(&argv, false)
    } else {
        posix_command(&argv)
    }
}

/// The Gemini CLI settings fragment: `BeforeTool` decides, `AfterTool`
/// records (and redacts). `name` identifies the hook in Gemini's
/// `hooksConfig.disabled` list. The timeout is Gemini's maximum patience,
/// not provio's latency: a timed-out hook does not block in Gemini CLI.
pub(crate) fn gemini_hook_settings(w: &Wiring, name: &str) -> Value {
    let group = json!([{
        "matcher": "*",
        "hooks": [{
            "type": "command",
            "name": name,
            "command": gemini_hook_command(w),
            "timeout": 600_000,
            "description": "provio: policy decision and ledger record for this tool call",
        }]
    }]);
    json!({"hooks": {"BeforeTool": group, "AfterTool": group}})
}

pub(crate) fn merge_gemini_settings(settings: Value, fragment: &Value) -> Result<Value> {
    merge_hook_groups(
        settings,
        fragment,
        &|h| {
            h.get("command")
                .and_then(Value::as_str)
                .is_some_and(|c| is_provio_command(c, "gemini"))
        },
        "Gemini CLI settings",
    )
}

fn integrate_gemini(w: &Wiring, print: bool) -> Result<()> {
    let path = PathBuf::from(".gemini").join("settings.json");
    let existing = read_json_object_file(&path)?;
    let merged = merge_gemini_settings(existing, &gemini_hook_settings(w, "provio"))?;
    let disabled = merged
        .pointer("/hooksConfig/enabled")
        .and_then(Value::as_bool)
        == Some(false);
    let text = serde_json::to_string_pretty(&merged)? + "\n";
    if print {
        print!("{text}");
        return Ok(());
    }
    write_atomic(&path, &text)?;
    eprintln!(
        "  provio · Gemini CLI hooks written to {} (BeforeTool, AfterTool)\n{}\n  note: Gemini CLI runs hooks only in a trusted folder; project hooks are shown to you once as new",
        path.display(),
        footer(w)
    );
    if disabled {
        eprintln!(
            "  \x1b[33mwarning: {} sets hooksConfig.enabled = false — no hook runs until that is removed\x1b[0m",
            path.display()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Flat shape (Cursor, Windsurf): {"hooks": {event: [handler, ...]}}

/// Merge the flat `fragment` into `settings`: provio's previous handlers are
/// replaced; top-level keys of the fragment other than `hooks` (Cursor's
/// `version`) are added only when missing.
fn merge_flat_hooks(
    mut settings: Value,
    fragment: &Value,
    is_ours: &dyn Fn(&Value) -> bool,
    label: &str,
) -> Result<Value> {
    let root = settings
        .as_object_mut()
        .ok_or_else(|| anyhow!("{label} must be a JSON object; not touching it"))?;
    let Some(frag) = fragment.as_object() else {
        bail!("internal: hook fragment is not an object");
    };
    for (k, v) in frag.iter().filter(|(k, _)| k.as_str() != "hooks") {
        root.entry(k.clone()).or_insert_with(|| v.clone());
    }
    let hooks = root
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()));
    let hooks = hooks
        .as_object_mut()
        .ok_or_else(|| anyhow!("\"hooks\" in {label} is not an object; not touching it"))?;
    let Some(new_hooks) = frag.get("hooks").and_then(Value::as_object) else {
        bail!("internal: hook fragment has no \"hooks\" object");
    };
    for (event, new_list) in new_hooks {
        let list = hooks
            .entry(event.clone())
            .or_insert_with(|| Value::Array(Vec::new()));
        let list = list.as_array_mut().ok_or_else(|| {
            anyhow!("\"hooks.{event}\" in {label} is not an array; not touching it")
        })?;
        list.retain(|h| !is_ours(h));
        if let Some(arr) = new_list.as_array() {
            list.extend(arr.iter().cloned());
        }
    }
    Ok(settings)
}

fn command_is(h: &Value, format: &str) -> bool {
    ["command", "powershell"].iter().any(|k| {
        h.get(*k)
            .and_then(Value::as_str)
            .is_some_and(|c| is_provio_command(c, format))
    })
}

// ---------------------------------------------------------------------------
// Cursor

/// Cursor runs `command` through a shell; `portable_command` keeps it
/// valid under any of them.
pub(crate) fn cursor_hook_command(w: &Wiring) -> Result<String> {
    portable_command(&hook_argv(w, "cursor", true))
}

/// The Cursor hooks fragment. `failClosed: true` makes a crash, timeout or
/// non-zero exit of the hook block the action (Cursor fails open without
/// it). MCP calls are decided at `beforeMCPExecution`, which carries the
/// server identity and supports `ask`.
pub(crate) fn cursor_hook_settings(w: &Wiring) -> Result<Value> {
    let h = json!([{
        "command": cursor_hook_command(w)?,
        "timeout": 60,
        "failClosed": true,
    }]);
    Ok(json!({"version": 1, "hooks": {
        "preToolUse": h,
        "beforeMCPExecution": h,
        "postToolUse": h,
        "postToolUseFailure": h,
    }}))
}

pub(crate) fn merge_cursor_hooks(settings: Value, fragment: &Value) -> Result<Value> {
    merge_flat_hooks(
        settings,
        fragment,
        &|h| command_is(h, "cursor"),
        "Cursor hooks.json",
    )
}

fn integrate_cursor(w: &Wiring, print: bool) -> Result<()> {
    let path = PathBuf::from(".cursor").join("hooks.json");
    let existing = read_json_object_file(&path)?;
    let merged = merge_cursor_hooks(existing, &cursor_hook_settings(w)?)?;
    let text = serde_json::to_string_pretty(&merged)? + "\n";
    if print {
        print!("{text}");
        return Ok(());
    }
    write_atomic(&path, &text)?;
    eprintln!(
        "  provio · Cursor hooks written to {} (preToolUse, beforeMCPExecution, postToolUse, postToolUseFailure; failClosed)\n{}\n  note: project hooks run only in a trusted workspace; Cursor cloud agents do not run beforeMCPExecution",
        path.display(),
        footer(w)
    );
    if Path::new(".claude").join("settings.json").is_file() {
        let s =
            std::fs::read_to_string(Path::new(".claude").join("settings.json")).unwrap_or_default();
        if s.contains("claude-code") && s.contains("check") {
            eprintln!(
                "  \x1b[33mwarning: .claude/settings.json has provio's Claude Code hooks; Cursor runs those too \
                 (third-party hooks) and they refuse Cursor payloads — turn off Cursor's \
                 third-party hook import for this project\x1b[0m"
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Windsurf (Cascade)

const WINDSURF_EVENTS: &[&str] = &[
    "pre_run_command",
    "pre_read_code",
    "pre_write_code",
    "pre_mcp_tool_use",
    "post_run_command",
    "post_read_code",
    "post_write_code",
    "post_mcp_tool_use",
];

/// Cascade runs `command` with `bash -c` and `powershell` with
/// `powershell -Command` (Windows).
pub(crate) fn windsurf_hook_settings(w: &Wiring) -> Value {
    let argv = hook_argv(w, "windsurf", false);
    let h = json!([{
        "command": posix_command(&argv),
        "powershell": powershell_command(&argv, true),
        "show_output": false,
    }]);
    let hooks: Map<String, Value> = WINDSURF_EVENTS
        .iter()
        .map(|e| (e.to_string(), h.clone()))
        .collect();
    json!({ "hooks": hooks })
}

pub(crate) fn merge_windsurf_hooks(settings: Value, fragment: &Value) -> Result<Value> {
    merge_flat_hooks(
        settings,
        fragment,
        &|h| command_is(h, "windsurf"),
        "Windsurf hooks.json",
    )
}

/// `.devin/hooks.json` is current; `.windsurf/hooks.json` is used only
/// when the former is absent, so an existing legacy file is merged into
/// rather than shadowed.
fn windsurf_path() -> PathBuf {
    let devin = PathBuf::from(".devin").join("hooks.json");
    let legacy = PathBuf::from(".windsurf").join("hooks.json");
    if !devin.exists() && legacy.is_file() {
        legacy
    } else {
        devin
    }
}

fn integrate_windsurf(w: &Wiring, print: bool) -> Result<()> {
    let path = windsurf_path();
    let existing = read_json_object_file(&path)?;
    let merged = merge_windsurf_hooks(existing, &windsurf_hook_settings(w))?;
    let text = serde_json::to_string_pretty(&merged)? + "\n";
    if print {
        print!("{text}");
        return Ok(());
    }
    write_atomic(&path, &text)?;
    eprintln!(
        "  provio · Windsurf (Cascade) hooks written to {} (pre_/post_ run_command, read_code, write_code, mcp_tool_use)\n{}",
        path.display(),
        footer(w)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// OpenAI Codex CLI

pub(crate) const CODEX_EVENTS: &[&str] = &["PreToolUse", "PostToolUse"];

/// Codex runs a hook command through the session's shell (sh/bash/zsh,
/// PowerShell or cmd.exe on Windows).
pub(crate) fn codex_hook_command(w: &Wiring) -> Result<String> {
    portable_command(&hook_argv(w, "codex", false))
}

fn codex_is_ours(t: &dyn toml_edit::TableLike) -> bool {
    t.get("command")
        .and_then(|i| i.as_str())
        .is_some_and(|c| is_provio_command(c, "codex"))
}

/// Remove provio's handlers from one matcher group; true when the group had
/// handlers and none is left.
fn codex_strip_group(group: &mut dyn toml_edit::TableLike) -> bool {
    let Some(item) = group.get_mut("hooks") else {
        return false;
    };
    match item {
        toml_edit::Item::ArrayOfTables(aot) => {
            let before = aot.len();
            let keep: Vec<usize> = (0..before)
                .filter(|i| !aot.get(*i).is_some_and(|t| codex_is_ours(t)))
                .collect();
            for i in (0..before).rev() {
                if !keep.contains(&i) {
                    aot.remove(i);
                }
            }
            before > 0 && aot.is_empty()
        }
        toml_edit::Item::Value(toml_edit::Value::Array(arr)) => {
            let before = arr.len();
            arr.retain(|v| !v.as_inline_table().is_some_and(|t| codex_is_ours(t)));
            before > 0 && arr.is_empty()
        }
        _ => false,
    }
}

/// Merge provio's inline `[hooks]` into a Codex `config.toml`, preserving
/// everything else byte for byte where `toml_edit` can.
pub(crate) fn merge_codex_toml(text: &str, command: &str) -> Result<String> {
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|e| anyhow!("config.toml is not valid TOML ({e}); not touching it"))?;
    let root = doc.as_table_mut();
    if !root.contains_key("hooks") {
        let mut t = toml_edit::Table::new();
        t.set_implicit(true);
        root.insert("hooks", toml_edit::Item::Table(t));
    }
    let hooks = root
        .get_mut("hooks")
        .and_then(toml_edit::Item::as_table_mut)
        .ok_or_else(|| {
            anyhow!(
                "\"hooks\" in config.toml is not a table (e.g. an inline table); not touching it"
            )
        })?;
    for event in CODEX_EVENTS {
        match hooks.get_mut(event) {
            None => {
                let mut aot = toml_edit::ArrayOfTables::new();
                aot.push(codex_group_table(command));
                hooks.insert(event, toml_edit::Item::ArrayOfTables(aot));
            }
            Some(toml_edit::Item::ArrayOfTables(aot)) => {
                let n = aot.len();
                for i in (0..n).rev() {
                    let emptied = aot.get_mut(i).is_some_and(|g| codex_strip_group(g));
                    if emptied {
                        aot.remove(i);
                    }
                }
                aot.push(codex_group_table(command));
            }
            Some(toml_edit::Item::Value(toml_edit::Value::Array(arr))) => {
                let mut kept = toml_edit::Array::new();
                for v in arr.iter() {
                    let mut v = v.clone();
                    let emptied = v
                        .as_inline_table_mut()
                        .is_some_and(|g| codex_strip_group(g));
                    if !emptied {
                        kept.push_formatted(v);
                    }
                }
                kept.push(codex_group_inline(command));
                *arr = kept;
            }
            Some(_) => bail!("\"hooks.{event}\" in config.toml is not an array; not touching it"),
        }
    }
    Ok(doc.to_string())
}

fn codex_group_table(command: &str) -> toml_edit::Table {
    let mut h = toml_edit::Table::new();
    h.insert("type", toml_edit::value("command"));
    h.insert("command", toml_edit::value(command));
    h.insert("statusMessage", toml_edit::value("provio policy check"));
    let mut handlers = toml_edit::ArrayOfTables::new();
    handlers.push(h);
    let mut g = toml_edit::Table::new();
    g.insert("matcher", toml_edit::value("*"));
    g.insert("hooks", toml_edit::Item::ArrayOfTables(handlers));
    g
}

fn codex_group_inline(command: &str) -> toml_edit::InlineTable {
    let mut h = toml_edit::InlineTable::new();
    h.insert("type", "command".into());
    h.insert("command", command.into());
    h.insert("statusMessage", "provio policy check".into());
    let mut handlers = toml_edit::Array::new();
    handlers.push(h);
    let mut g = toml_edit::InlineTable::new();
    g.insert("matcher", "*".into());
    g.insert("hooks", toml_edit::Value::Array(handlers));
    g
}

/// A TOML string for `codex -c key=value` overrides: a literal string
/// (`'…'`) when possible — no `"`, so the argument also survives a
/// Windows batch-file launcher (`codex.cmd`) — else a basic string.
pub(crate) fn toml_string(s: &str) -> String {
    if !s.contains(['\'', '\n', '\r']) {
        format!("'{s}'")
    } else {
        toml_edit::Value::from(s).to_string().trim().to_string()
    }
}

fn integrate_codex(w: &Wiring, print: bool) -> Result<()> {
    let command = codex_hook_command(w)?;
    let path = PathBuf::from(".codex").join("config.toml");
    let existing = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let merged = merge_codex_toml(&existing, &command)
        .with_context(|| format!("merge provio's hooks into {}", path.display()))?;
    let hooks_off = existing
        .parse::<toml_edit::DocumentMut>()
        .ok()
        .and_then(|d| {
            let f = d.get("features")?;
            f.get("hooks")
                .or_else(|| f.get("codex_hooks"))
                .and_then(|i| i.as_bool())
        })
        == Some(false);
    if print {
        print!("{merged}");
        return Ok(());
    }
    write_atomic(&path, &merged)?;
    eprintln!(
        "  provio · Codex hooks written to {} (PreToolUse, PostToolUse)\n{}\n  \x1b[33mnext: Codex runs a new hook only after you review and trust it — start `codex` in this project and trust provio's hooks in /hooks. Until then they are skipped (the tools run ungoverned). Project .codex/ hooks load only in a trusted project.\x1b[0m",
        path.display(),
        footer(w)
    );
    if hooks_off {
        eprintln!(
            "  \x1b[33mwarning: {} sets [features] hooks = false — no hook runs until that is removed\x1b[0m",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn frag(exe: &str) -> Value {
        claude_code_hook_settings(
            Path::new(exe),
            Path::new("/p/provio.yaml"),
            Path::new("/p/l.jsonl"),
        )
    }

    #[test]
    fn merge_preserves_and_is_idempotent() {
        let existing = json!({
            "model": "opus",
            "permissions": {"allow": ["Bash(ls)"]},
            "hooks": {
                "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "lint.sh"}]}],
                "Stop": [{"hooks": [{"type": "command", "command": "notify"}]}]
            }
        });
        let once = merge_hook_settings(existing.clone(), &frag("/bin/provio")).unwrap();
        let twice = merge_hook_settings(once.clone(), &frag("/bin/provio")).unwrap();
        assert_eq!(once, twice);
        assert_eq!(once["model"], "opus");
        assert_eq!(once["hooks"]["Stop"], existing["hooks"]["Stop"]);
        let pre = once["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 2);
        assert_eq!(pre[0]["hooks"][0]["command"], "lint.sh");
        assert_eq!(pre[1]["hooks"][0]["command"], "/bin/provio");

        // Moving the binary replaces the entry instead of adding one.
        let moved = merge_hook_settings(once, &frag("/opt/provio.exe")).unwrap();
        let pre = moved["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 2);
        assert_eq!(pre[1]["hooks"][0]["command"], "/opt/provio.exe");
    }

    #[test]
    fn old_shell_form_entry_is_replaced() {
        let existing = json!({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": "\"/x/provio\" --policy \"a\" --ledger \"b\" check --format claude-code --ask defer"}
        ]}]}});
        let merged = merge_hook_settings(existing, &frag("/bin/provio")).unwrap();
        assert_eq!(merged["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn refuses_non_object_settings() {
        assert!(merge_hook_settings(json!([1]), &frag("/bin/provio")).is_err());
        assert!(merge_hook_settings(json!({"hooks": 3}), &frag("/bin/provio")).is_err());
    }

    fn argv() -> Vec<String> {
        ["/opt/my tools/provio", "--policy", "/p/it's.yaml", "check"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn quoting() {
        assert_eq!(
            posix_command(&argv()),
            r#"'/opt/my tools/provio' --policy '/p/it'\''s.yaml' check"#
        );
        assert_eq!(
            powershell_command(&argv(), true),
            "& '/opt/my tools/provio' --policy '/p/it''s.yaml' check; exit $LASTEXITCODE"
        );
        let ok: Vec<String> = ["C:\\w\\provio.exe", "--policy", "C:\\w\\provio.yaml"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let p = portable_command(&ok).unwrap();
        if cfg!(windows) {
            assert_eq!(p, "C:/w/provio.exe --policy C:/w/provio.yaml");
            assert!(portable_command(&argv()).is_err());
        } else {
            assert!(p.starts_with("'C:\\w\\provio.exe'"), "{p}");
        }
        assert!(is_provio_command(
            &powershell_command(&hook_argv(&wiring(), "gemini", true), false),
            "gemini"
        ));
        assert!(is_provio_command(
            &posix_command(&hook_argv(&wiring(), "cursor", true)),
            "cursor"
        ));
        assert!(!is_provio_command("lint.sh --format codex", "codex"));
    }

    fn wiring() -> Wiring<'static> {
        Wiring {
            exe: Path::new("/opt/provio/provio"),
            policy: Path::new("/p/provio.yaml"),
            ledger: Path::new("/p/.provio/ledger.jsonl"),
        }
    }

    #[test]
    fn codex_toml_merge_preserves_comments_and_is_idempotent() {
        let existing = "# my codex config\nmodel = \"gpt-5\" # pinned\n\n[features]\nweb = true\n\n[[hooks.PreToolUse]]\nmatcher = \"^Bash$\"\n\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = \"python3 lint.py\"\n";
        let once = merge_codex_toml(
            existing,
            "/opt/provio/provio --policy /p/provio.yaml --ledger /l check --format codex",
        )
        .unwrap();
        assert!(
            once.starts_with("# my codex config\nmodel = \"gpt-5\" # pinned\n"),
            "{once}"
        );
        assert!(once.contains("python3 lint.py"));
        let twice = merge_codex_toml(
            &once,
            "/opt/provio/provio --policy /p/provio.yaml --ledger /l check --format codex",
        )
        .unwrap();
        assert_eq!(once, twice);
        let moved = merge_codex_toml(
            &once,
            "/new/provio --policy /p/provio.yaml --ledger /l check --format codex",
        )
        .unwrap();
        assert!(!moved.contains("/opt/provio/provio"), "{moved}");
        let doc: toml_edit::DocumentMut = moved.parse().unwrap();
        let pre = doc["hooks"]["PreToolUse"].as_array_of_tables().unwrap();
        assert_eq!(pre.len(), 2);
        assert_eq!(pre.get(0).unwrap()["matcher"].as_str(), Some("^Bash$"));
        let provio = pre.get(1).unwrap()["hooks"].as_array_of_tables().unwrap();
        assert_eq!(provio.get(0).unwrap()["type"].as_str(), Some("command"));
        assert!(doc["hooks"]["PostToolUse"].is_array_of_tables());
        assert_eq!(doc["features"]["web"].as_bool(), Some(true));
    }

    #[test]
    fn codex_toml_inline_arrays_and_refusals() {
        let inline = "[hooks]\nPreToolUse = [{ matcher = \"*\", hooks = [{ type = \"command\", command = \"a.sh\" }, { type = \"command\", command = \"provio check --format codex\" }] }]\n";
        let m = merge_codex_toml(inline, "provio --x check --format codex").unwrap();
        let doc: toml_edit::DocumentMut = m.parse().unwrap();
        let arr = doc["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 2, "{m}");
        assert_eq!(
            merge_codex_toml(&m, "provio --x check --format codex").unwrap(),
            m
        );
        assert!(merge_codex_toml("hooks = 3\n", "c").is_err());
        assert!(merge_codex_toml("[hooks]\nPreToolUse = \"x\"\n", "c").is_err());
        assert!(merge_codex_toml("not = [valid", "c").is_err());
        assert!(merge_codex_toml("hooks = { PreToolUse = [] }\n", "c").is_err());
    }

    #[test]
    fn flat_merges() {
        let w = wiring();
        let frag = windsurf_hook_settings(&w);
        let existing = json!({"hooks": {"pre_run_command": [{"command": "audit.sh"}]}, "x": 1});
        let once = merge_windsurf_hooks(existing, &frag).unwrap();
        assert_eq!(once, merge_windsurf_hooks(once.clone(), &frag).unwrap());
        assert_eq!(
            once["hooks"]["pre_run_command"].as_array().unwrap().len(),
            2
        );
        assert_eq!(once["x"], 1);
        assert!(merge_windsurf_hooks(json!({"hooks": {"pre_read_code": {}}}), &frag).is_err());

        let g = gemini_hook_settings(&w, "provio");
        let existing = json!({"hooks": {"BeforeTool": [{"matcher": "write_file", "hooks": [{"type": "command", "command": "sec.sh"}]}]}});
        let once = merge_gemini_settings(existing, &g).unwrap();
        assert_eq!(once, merge_gemini_settings(once.clone(), &g).unwrap());
        assert_eq!(once["hooks"]["BeforeTool"].as_array().unwrap().len(), 2);
    }

    #[cfg(windows)]
    #[test]
    fn portable_command_accepts_short_path_tildes_but_not_a_leading_one() {
        let ok = portable_command(&["C:/Users/RUNNER~1/AppData/provio.exe".to_string()]);
        assert_eq!(ok.unwrap(), "C:/Users/RUNNER~1/AppData/provio.exe");
        assert!(portable_command(&["~/provio.exe".to_string()]).is_err());
        assert!(portable_command(&["C:/Program Files/provio.exe".to_string()]).is_err());
    }
}
