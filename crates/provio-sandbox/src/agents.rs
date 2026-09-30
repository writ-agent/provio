//! Built-in agent profiles for interactive runs (`provio run -- <agent>`).
//!
//! A profile names the state/config/cache paths an agent CLI writes
//! outside the workspace, so the kernel boundary can let it work without
//! opening the rest of the home directory. Profiles are keyed by the
//! command's basename, case-insensitively, with `.exe` / `.cmd` / `.bat` /
//! `.ps1` / `.js` stripped. Unknown commands get the generic profile:
//! workspace + private temp only.
//!
//! Paths are resolved from the environment the agent will see (HOME /
//! USERPROFILE, XDG_*, APPDATA / LOCALAPPDATA, the agents' own override
//! variables such as `CLAUDE_CONFIG_DIR` and `CODEX_HOME`).

use std::path::{Path, PathBuf};

/// One writable path of a profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfilePath {
    pub path: PathBuf,
    /// Why it is writable (shown in the banner).
    pub why: &'static str,
    /// Directory (everything beneath) or a single file.
    pub kind: PathKind,
    /// Create it when missing (the agent would create it anyway). When
    /// false, a missing path is simply not granted.
    pub create: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Dir,
    /// A file; when `create` is set and it is missing, it is created with
    /// this initial content.
    File(&'static str),
}

/// What provio knows about an agent CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentProfile {
    /// Profile key (`claude`, `codex`, `gemini`, `cursor`, `aider`,
    /// `generic`).
    pub name: &'static str,
    /// Human name.
    pub display: &'static str,
    /// Agent state/config/cache paths.
    pub paths: Vec<ProfilePath>,
    /// Environment set for the agent (e.g. disabling a self-updater that
    /// would need to write outside the boundary).
    pub env: Vec<(String, String)>,
    /// Agent configuration files beneath [`AgentProfile::paths`] that must
    /// stay unwritable where the kernel allows it (they could plant hooks
    /// that run in later sessions outside provio).
    pub protect: Vec<PathBuf>,
    /// Same, relative to the workspace (e.g. `.claude/settings.json`).
    pub workspace_protect: Vec<&'static str>,
    /// Package caches this agent commonly writes through the tools it
    /// runs; suggested (never granted by default) via `--allow-write`.
    pub suggest_caches: bool,
    /// How provio's per-tool-call hooks can be passed to this agent for one
    /// invocation (`provio run`), if at all.
    pub hooks: HookSupport,
}

/// Per-invocation hook injection an agent supports (see `provio run`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookSupport {
    /// No per-invocation hook mechanism provio knows of.
    None,
    /// Claude Code: `--settings <file>` (outranks user/project settings).
    ClaudeSettings,
    /// OpenAI Codex CLI: `-c hooks.<Event>=[...]` session-flag overrides
    /// plus `--dangerously-bypass-hook-trust` (provio vets its own hooks).
    CodexConfigFlags,
    /// Gemini CLI: `GEMINI_CLI_SYSTEM_SETTINGS_PATH` pointing at a
    /// provio-owned system settings file (system settings override user and
    /// workspace settings).
    GeminiSystemSettings,
    /// Cursor CLI (`agent` / `cursor-agent`): `--plugin-dir <dir>` with a
    /// provio-owned local plugin that bundles the hooks.
    CursorPluginDir,
}

/// Environment lookup for path resolution (injected for tests).
pub trait EnvLookup {
    fn get(&self, key: &str) -> Option<String>;
}

/// The real process environment.
pub struct ProcessEnv;

impl EnvLookup for ProcessEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok().filter(|v| !v.is_empty())
    }
}

impl<F: Fn(&str) -> Option<String>> EnvLookup for F {
    fn get(&self, key: &str) -> Option<String> {
        self(key).filter(|v| !v.is_empty())
    }
}

/// The profile key for a command: its basename, lower-cased, without a
/// Windows launcher extension.
pub fn agent_key(program: &str) -> String {
    let base = program
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(program)
        .to_ascii_lowercase();
    for ext in [".exe", ".cmd", ".bat", ".ps1", ".js"] {
        if let Some(stem) = base.strip_suffix(ext) {
            return stem.to_string();
        }
    }
    base
}

struct Dirs {
    home: Option<PathBuf>,
    /// XDG_CONFIG_HOME or ~/.config.
    config: Option<PathBuf>,
    /// Linux: XDG_CACHE_HOME or ~/.cache; macOS: ~/Library/Caches;
    /// Windows: %LOCALAPPDATA%.
    cache: Option<PathBuf>,
    /// Windows %LOCALAPPDATA%.
    local_app_data: Option<PathBuf>,
}

impl Dirs {
    fn from(env: &dyn EnvLookup) -> Self {
        let home = if cfg!(windows) {
            env.get("USERPROFILE").or_else(|| env.get("HOME"))
        } else {
            env.get("HOME")
        }
        .map(PathBuf::from);
        let local_app_data = env.get("LOCALAPPDATA").map(PathBuf::from);
        let config = env
            .get("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| home.as_ref().map(|h| h.join(".config")));
        let cache = if cfg!(windows) {
            local_app_data.clone()
        } else if cfg!(target_os = "macos") {
            home.as_ref().map(|h| h.join("Library").join("Caches"))
        } else {
            env.get("XDG_CACHE_HOME")
                .map(PathBuf::from)
                .or_else(|| home.as_ref().map(|h| h.join(".cache")))
        };
        Dirs {
            home,
            config,
            cache,
            local_app_data,
        }
    }
}

fn dir(path: PathBuf, why: &'static str, create: bool) -> ProfilePath {
    ProfilePath {
        path,
        why,
        kind: PathKind::Dir,
        create,
    }
}

fn claude(d: &Dirs, env: &dyn EnvLookup) -> AgentProfile {
    let mut paths = Vec::new();
    let mut protect = Vec::new();
    match env.get("CLAUDE_CONFIG_DIR") {
        // Everything (settings, credentials, projects, .claude.json)
        // lives in the override dir.
        Some(c) => {
            let c = PathBuf::from(c);
            protect.push(c.join("settings.json"));
            paths.push(dir(c, "config (CLAUDE_CONFIG_DIR)", true));
        }
        None => {
            if let Some(h) = &d.home {
                protect.push(h.join(".claude").join("settings.json"));
                paths.push(dir(h.join(".claude"), "state and config", true));
                // Global config. Created as `{}` when missing: a file rule
                // needs an existing file, and Claude Code merges defaults
                // into an empty object.
                paths.push(ProfilePath {
                    path: h.join(".claude.json"),
                    why: "global config",
                    kind: PathKind::File("{}"),
                    create: true,
                });
            }
        }
    }
    if let Some(c) = &d.config {
        paths.push(dir(c.join("claude"), "config (XDG)", false));
    }
    if let Some(c) = &d.cache {
        paths.push(dir(c.join("claude-cli-nodejs"), "cache", true));
    }
    AgentProfile {
        name: "claude",
        display: "Claude Code",
        paths,
        // The self-updater would rewrite the install outside the boundary.
        env: vec![("DISABLE_AUTOUPDATER".into(), "1".into())],
        protect,
        workspace_protect: vec![".claude/settings.json", ".claude/settings.local.json"],
        suggest_caches: true,
        hooks: HookSupport::ClaudeSettings,
    }
}

fn simple(
    name: &'static str,
    display: &'static str,
    override_var: Option<&str>,
    dot_dir: &str,
    d: &Dirs,
    env: &dyn EnvLookup,
) -> AgentProfile {
    let base = override_var
        .and_then(|v| env.get(v))
        .map(PathBuf::from)
        .or_else(|| d.home.as_ref().map(|h| h.join(dot_dir)));
    AgentProfile {
        name,
        display,
        paths: base
            .map(|p| vec![dir(p, "agent state", true)])
            .unwrap_or_default(),
        env: Vec::new(),
        protect: Vec::new(),
        workspace_protect: Vec::new(),
        suggest_caches: true,
        hooks: HookSupport::None,
    }
}

/// OpenAI Codex CLI: everything lives in `CODEX_HOME` (default `~/.codex`):
/// config.toml, hooks.json, auth, sessions, logs. Hooks load from
/// `config.toml`/`hooks.json` next to every config layer, so both are
/// protected there and in the workspace's `.codex/`.
fn codex(d: &Dirs, env: &dyn EnvLookup) -> AgentProfile {
    let mut p = simple(
        "codex",
        "OpenAI Codex CLI",
        Some("CODEX_HOME"),
        ".codex",
        d,
        env,
    );
    if let Some(base) = p.paths.first().map(|p| p.path.clone()) {
        p.protect = vec![base.join("config.toml"), base.join("hooks.json")];
    }
    p.workspace_protect = vec![".codex/config.toml", ".codex/hooks.json"];
    p.hooks = HookSupport::CodexConfigFlags;
    p
}

/// Gemini CLI: `~/.gemini` (or `$GEMINI_CLI_HOME/.gemini`) holds
/// settings.json, OAuth credentials, history and tmp.
fn gemini(d: &Dirs, env: &dyn EnvLookup) -> AgentProfile {
    let base = env
        .get("GEMINI_CLI_HOME")
        .map(|h| PathBuf::from(h).join(".gemini"))
        .or_else(|| d.home.as_ref().map(|h| h.join(".gemini")));
    let mut p = simple("gemini", "Gemini CLI", None, ".gemini", d, env);
    p.paths = base
        .clone()
        .map(|b| vec![dir(b, "agent state", true)])
        .unwrap_or_default();
    p.protect = base
        .map(|b| vec![b.join("settings.json")])
        .unwrap_or_default();
    p.workspace_protect = vec![".gemini/settings.json"];
    p.hooks = HookSupport::GeminiSystemSettings;
    p
}

/// Cursor CLI (`agent`, formerly `cursor-agent`): `~/.cursor` (or
/// `CURSOR_CONFIG_DIR`) holds cli-config.json, chats, worktrees and user
/// hooks. Cursor also loads Claude Code hook files, so those are
/// protected too. The install dir (`~/.local/share/cursor-agent`) is not
/// granted: that is the self-updater's.
fn cursor(d: &Dirs, env: &dyn EnvLookup) -> AgentProfile {
    let mut p = simple(
        "cursor",
        "Cursor CLI",
        Some("CURSOR_CONFIG_DIR"),
        ".cursor",
        d,
        env,
    );
    if let Some(base) = p.paths.first().map(|p| p.path.clone()) {
        p.protect.push(base.join("hooks.json"));
    }
    if let Some(h) = &d.home {
        p.protect.push(h.join(".claude").join("settings.json"));
    }
    p.workspace_protect = vec![
        ".cursor/hooks.json",
        ".claude/settings.json",
        ".claude/settings.local.json",
    ];
    p.hooks = HookSupport::CursorPluginDir;
    p
}

/// The built-in profile for `program` (see the module docs).
pub fn agent_profile(program: &str, env: &dyn EnvLookup) -> AgentProfile {
    let d = Dirs::from(env);
    match agent_key(program).as_str() {
        "claude" => claude(&d, env),
        "codex" => codex(&d, env),
        "gemini" => gemini(&d, env),
        // The Cursor CLI installs as `agent` (and, earlier, `cursor-agent`).
        "cursor-agent" | "agent" => cursor(&d, env),
        "aider" => {
            // ~/.aider holds caches, analytics and oauth keys; aider's
            // history/tag caches live in the repo (workspace).
            let mut p = simple("aider", "aider", None, ".aider", &d, env);
            if let Some(c) = &d.cache {
                p.paths.push(dir(c.join("aider"), "aider cache", false));
            }
            p
        }
        _ => AgentProfile {
            name: "generic",
            display: "generic agent",
            paths: Vec::new(),
            env: Vec::new(),
            protect: Vec::new(),
            workspace_protect: Vec::new(),
            suggest_caches: false,
            hooks: HookSupport::None,
        },
    }
}

/// Package-manager caches agents commonly trigger (npm, pip, uv, cargo).
/// Never writable by default: a writable cache is a cache-poisoning channel
/// into later unconfined runs of the same tools. `provio run` only
/// *suggests* the ones that exist, for `--allow-write`.
pub fn tool_caches(env: &dyn EnvLookup) -> Vec<ProfilePath> {
    let d = Dirs::from(env);
    let mut out = Vec::new();
    let mut add = |p: Option<PathBuf>, why: &'static str| {
        if let Some(p) = p {
            out.push(dir(p, why, false));
        }
    };
    if cfg!(windows) {
        add(
            d.local_app_data.as_ref().map(|l| l.join("npm-cache")),
            "npm cache",
        );
        add(
            d.local_app_data
                .as_ref()
                .map(|l| l.join("pip").join("Cache")),
            "pip cache",
        );
        add(
            d.local_app_data
                .as_ref()
                .map(|l| l.join("uv").join("cache")),
            "uv cache",
        );
    } else {
        add(d.home.as_ref().map(|h| h.join(".npm")), "npm cache");
        add(d.cache.as_ref().map(|c| c.join("pip")), "pip cache");
        add(
            env.get("XDG_CACHE_HOME")
                .map(PathBuf::from)
                .or_else(|| d.home.as_ref().map(|h| h.join(".cache")))
                .map(|c| c.join("uv")),
            "uv cache",
        );
    }
    let cargo = env
        .get("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| d.home.as_ref().map(|h| h.join(".cargo")));
    add(
        cargo.as_ref().map(|c| c.join("registry")),
        "cargo registry cache",
    );
    add(cargo.as_ref().map(|c| c.join("git")), "cargo git cache");
    out
}

/// Create the missing `create` paths of `paths`; return the ones that now
/// exist (missing optional ones are dropped).
pub fn materialize(paths: &[ProfilePath]) -> std::io::Result<Vec<ProfilePath>> {
    let mut out = Vec::new();
    for p in paths {
        let exists = match p.kind {
            PathKind::Dir => p.path.is_dir(),
            PathKind::File(_) => p.path.is_file(),
        };
        if !exists {
            if !p.create {
                continue;
            }
            match p.kind {
                PathKind::Dir => std::fs::create_dir_all(&p.path)?,
                PathKind::File(initial) => {
                    if let Some(parent) = p.path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    // create_new: never clobber a file that appeared meanwhile.
                    match std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&p.path)
                    {
                        Ok(mut f) => std::io::Write::write_all(&mut f, initial.as_bytes())?,
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(e) => return Err(e),
                    }
                }
            }
        }
        out.push(p.clone());
    }
    Ok(out)
}

/// `path` relative to `home` as `~/...` for display, else as is.
pub fn display_path(path: &Path, home: Option<&Path>) -> String {
    if let Some(h) = home {
        if let Ok(rest) = path.strip_prefix(h) {
            let sep = std::path::MAIN_SEPARATOR;
            return format!("~{sep}{}", rest.display());
        }
    }
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| m.get(k).cloned()
    }

    fn home() -> (&'static str, &'static str) {
        if cfg!(windows) {
            ("USERPROFILE", r"C:\Users\u")
        } else {
            ("HOME", "/home/u")
        }
    }

    #[test]
    fn keys_strip_path_case_and_launcher_extensions() {
        assert_eq!(agent_key("claude"), "claude");
        assert_eq!(agent_key(r"C:\npm\Claude.CMD"), "claude");
        assert_eq!(agent_key("/usr/local/bin/codex"), "codex");
        assert_eq!(agent_key("Gemini.exe"), "gemini");
        assert_eq!(agent_key("aider"), "aider");
        assert_eq!(agent_key("my-tool"), "my-tool");
    }

    #[test]
    fn claude_profile_covers_state_config_and_cache() {
        let (hk, hv) = home();
        let e = env(&[(hk, hv), ("LOCALAPPDATA", r"C:\Users\u\AppData\Local")]);
        let p = agent_profile("claude", &e);
        assert_eq!(p.hooks, HookSupport::ClaudeSettings);
        let h = PathBuf::from(hv);
        let paths: Vec<&PathBuf> = p.paths.iter().map(|p| &p.path).collect();
        assert!(paths.contains(&&h.join(".claude")));
        assert!(paths.contains(&&h.join(".claude.json")));
        assert!(p
            .paths
            .iter()
            .any(|p| p.path.ends_with("claude-cli-nodejs")));
        assert!(p.env.contains(&("DISABLE_AUTOUPDATER".into(), "1".into())));
        assert_eq!(p.protect, vec![h.join(".claude").join("settings.json")]);
        assert!(p.workspace_protect.contains(&".claude/settings.local.json"));
        let json = p
            .paths
            .iter()
            .find(|p| p.path.ends_with(".claude.json"))
            .unwrap();
        assert_eq!(json.kind, PathKind::File("{}"));
    }

    #[test]
    fn overrides_are_honoured() {
        let (hk, hv) = home();
        let e = env(&[
            (hk, hv),
            ("CLAUDE_CONFIG_DIR", "/cfg/claude"),
            ("CODEX_HOME", "/cx"),
        ]);
        let c = agent_profile("claude", &e);
        assert_eq!(c.paths[0].path, PathBuf::from("/cfg/claude"));
        assert!(!c.paths.iter().any(|p| p.path.ends_with(".claude.json")));
        let x = agent_profile("codex", &e);
        assert_eq!(x.paths[0].path, PathBuf::from("/cx"));
    }

    #[test]
    fn other_agents_and_generic() {
        let (hk, hv) = home();
        let e = env(&[(hk, hv)]);
        let h = PathBuf::from(hv);
        assert_eq!(agent_profile("codex", &e).paths[0].path, h.join(".codex"));
        assert_eq!(agent_profile("gemini", &e).paths[0].path, h.join(".gemini"));
        assert_eq!(agent_profile("aider", &e).paths[0].path, h.join(".aider"));
        let g = agent_profile("bash", &e);
        assert_eq!(g.name, "generic");
        assert!(g.paths.is_empty() && g.hooks == HookSupport::None);
    }

    #[test]
    fn hook_capable_agents_protect_their_hook_files() {
        let (hk, hv) = home();
        let e = env(&[(hk, hv)]);
        let h = PathBuf::from(hv);
        let x = agent_profile("codex", &e);
        assert_eq!(x.hooks, HookSupport::CodexConfigFlags);
        assert!(x.protect.contains(&h.join(".codex").join("config.toml")));
        assert!(x.protect.contains(&h.join(".codex").join("hooks.json")));
        assert!(x.workspace_protect.contains(&".codex/hooks.json"));

        let g = agent_profile("gemini", &e);
        assert_eq!(g.hooks, HookSupport::GeminiSystemSettings);
        assert_eq!(g.protect, vec![h.join(".gemini").join("settings.json")]);
        let g = agent_profile("gemini", &env(&[(hk, hv), ("GEMINI_CLI_HOME", "/gh")]));
        assert_eq!(g.paths[0].path, PathBuf::from("/gh").join(".gemini"));

        for name in ["agent", "cursor-agent", r"C:\bin\cursor-agent.cmd"] {
            let c = agent_profile(name, &e);
            assert_eq!(c.name, "cursor", "{name}");
            assert_eq!(c.hooks, HookSupport::CursorPluginDir);
            assert_eq!(c.paths[0].path, h.join(".cursor"));
            assert!(c.protect.contains(&h.join(".cursor").join("hooks.json")));
            assert!(c.workspace_protect.contains(&".claude/settings.json"));
        }
        let c = agent_profile("agent", &env(&[(hk, hv), ("CURSOR_CONFIG_DIR", "/cc")]));
        assert_eq!(c.paths[0].path, PathBuf::from("/cc"));
    }

    #[test]
    fn tool_caches_are_optional() {
        let (hk, hv) = home();
        let e = env(&[(hk, hv), ("LOCALAPPDATA", r"C:\Users\u\AppData\Local")]);
        let caches = tool_caches(&e);
        assert!(caches.iter().all(|c| !c.create));
        assert!(caches.iter().any(|c| c.why == "npm cache"));
        assert!(caches.iter().any(|c| c.path.ends_with("registry")));
    }

    #[test]
    fn materialize_creates_only_what_it_should() {
        let root = std::env::temp_dir().join(format!("provio-agents-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let want = [
            dir(root.join("made"), "x", true),
            dir(root.join("absent"), "x", false),
            ProfilePath {
                path: root.join("cfg.json"),
                why: "x",
                kind: PathKind::File("{}"),
                create: true,
            },
        ];
        let got = materialize(&want).unwrap();
        assert_eq!(got.len(), 2);
        assert!(root.join("made").is_dir());
        assert!(!root.join("absent").exists());
        assert_eq!(
            std::fs::read_to_string(root.join("cfg.json")).unwrap(),
            "{}"
        );
        std::fs::write(root.join("cfg.json"), "keep").unwrap();
        materialize(&want).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("cfg.json")).unwrap(),
            "keep"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
