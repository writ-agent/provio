//! Interactive confinement: the kernel boundary for `provio run -- <agent>`.
//!
//! The batch backend ([`crate::LocalOsBackend`]) runs non-interactive
//! commands with stdin null and output piped. An agent CLI needs the
//! opposite: the user's terminal (stdin/stdout/stderr inherited, TTY
//! behaviour intact), the user's environment, unrestricted reads (node,
//! toolchains, its own install), and usually the network (its model API).
//! What the boundary confines is **writes** (and, with [`Net::None`],
//! all network):
//!
//! | OS      | writes confined to the writable set            | [`Net::None`]              |
//! |---------|------------------------------------------------|----------------------------|
//! | Linux   | Landlock (files and dirs; tty/pty devices)     | seccomp: `socket(2)` EPERM |
//! | macOS   | Seatbelt `(deny file-write*)` + allow-list     | Seatbelt `(deny network*)` |
//! | Windows | Low integrity token + Low labels on the set    | not enforceable (refused)  |
//!
//! The writable set is: the workspace, a private temp dir created per run
//! (TMPDIR / TEMP / TMP point at it; removed when the run ends), and the
//! caller's extra paths (agent state dirs, `--allow-write`). With
//! [`Net::Open`] the network is open and **not filtered**: no mechanism
//! here filters by host, and [`InteractiveReport`] says so.
//!
//! Fail closed: in [`Mode::Required`] (default) a run whose filesystem
//! boundary (or requested `Net::None`) the kernel cannot fully enforce is
//! refused before anything is spawned. [`Mode::BestEffort`] applies what
//! the kernel supports and reports every gap; [`Mode::Unconfined`] applies
//! nothing and says so.

use std::path::PathBuf;

use provio_core::error::{ProvioError, Result};

use crate::enforce::{Capabilities, Level, Support};
use crate::local_os::canonical;

/// Network for the interactive child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Net {
    /// Network open (the agent must reach its model API). Not filtered.
    #[default]
    Open,
    /// No network at all, kernel-enforced where supported.
    None,
}

/// How strictly gaps between the request and the kernel are treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Refuse to launch unless everything requested is kernel-enforced.
    #[default]
    Required,
    /// Apply what the kernel supports; report each gap.
    BestEffort,
    /// No kernel boundary at all (launch supervision only).
    Unconfined,
}

/// What an interactive run asks for.
#[derive(Debug, Clone)]
pub struct Profile {
    /// The directory the agent works in (its cwd); writable.
    pub workspace: PathBuf,
    /// Extra writable paths (directories: everything beneath; files: that
    /// file). Each must exist.
    pub writable: Vec<PathBuf>,
    /// Files beneath writable directories that must stay unwritable (agent
    /// configuration that could weaken governance or plant hooks for later
    /// unconfined sessions). They may be absent. Enforcement differs per OS
    /// and is reported in [`InteractiveReport::protection`].
    pub protect: Vec<PathBuf>,
    pub net: Net,
    pub mode: Mode,
}

/// Exactly what a launched interactive run enforces (shown verbatim).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteractiveReport {
    pub mode: Mode,
    pub net: Net,
    /// Writes outside [`InteractiveReport::writable`] denied by the kernel.
    pub filesystem_writes: Level,
    /// Only meaningful for [`Net::None`]: network denied by the kernel.
    /// With [`Net::Open`] it is always `NotEnforced` (open, unfiltered).
    pub network_deny: Level,
    pub mechanism: String,
    /// Canonical writable set, as granted: workspace, private temp dir,
    /// then the caller's extra paths.
    pub writable: Vec<PathBuf>,
    /// The run's private temp dir (removed when the run ends).
    pub temp_dir: PathBuf,
    /// The [`Profile::protect`] files, absolute.
    pub protected: Vec<PathBuf>,
    /// Whether the kernel keeps [`InteractiveReport::protected`]
    /// unwritable (create, write, delete and rename-over included).
    pub protection: Level,
    /// Windows: paths that received a Low mandatory integrity label in this
    /// run. The label PERSISTS after the run (any Low integrity process of
    /// this user can then write there); undo with
    /// `icacls <path> /setintegritylevel (OI)(CI)M`. Empty elsewhere.
    pub labelled: Vec<PathBuf>,
    /// Gaps and hardening notes.
    pub notes: Vec<String>,
}

impl InteractiveReport {
    /// One line describing the filesystem boundary.
    pub fn filesystem_line(&self) -> String {
        match (self.mode, self.filesystem_writes) {
            (Mode::Unconfined, _) => "NOT enforced — unconfined (launch supervision only)".into(),
            (_, Level::Enforced) => {
                "enforced — writes outside the writable paths are denied by the kernel".into()
            }
            (_, Level::Partial) => "PARTIAL — see notes".into(),
            (_, Level::NotEnforced) => {
                "NOT enforced — the kernel cannot confine writes here".into()
            }
        }
    }

    /// One line describing the network.
    pub fn network_line(&self) -> String {
        match (self.net, self.network_deny) {
            (Net::Open, _) => "open, not filtered (the kernel cannot filter by host)".into(),
            (Net::None, Level::Enforced) => "none — all network denied by the kernel".into(),
            (Net::None, Level::Partial) => "none requested — PARTIAL, see notes".into(),
            (Net::None, Level::NotEnforced) => {
                "none requested but NOT enforced — the network is OPEN".into()
            }
        }
    }
}

/// What this machine's kernel can enforce for interactive runs.
pub fn capabilities() -> Capabilities {
    #[cfg(windows)]
    {
        crate::windows_interactive::capabilities()
    }
    #[cfg(not(windows))]
    {
        crate::platform::capabilities()
    }
}

/// Windows: which of `paths` (existing) would receive a new, persistent Low
/// mandatory label from a confined run — so a caller can list them before
/// launching. Always empty on other platforms and for unconfined runs.
pub fn persistent_labels(paths: &[PathBuf], mode: Mode) -> Result<Vec<PathBuf>> {
    if mode == Mode::Unconfined || !capabilities().filesystem.applicable() {
        return Ok(Vec::new());
    }
    #[cfg(windows)]
    {
        let canon: Vec<PathBuf> = paths.iter().map(|p| canonical(p)).collect::<Result<_>>()?;
        crate::windows_interactive::unlabelled(&canon)
    }
    #[cfg(not(windows))]
    {
        let _ = paths;
        Ok(Vec::new())
    }
}

/// Check, without spawning or touching the filesystem, whether a run with
/// `net` and `mode` would be allowed on this machine (the same decision
/// [`spawn_interactive`] makes first).
pub fn preflight(net: Net, mode: Mode) -> Result<()> {
    plan(&capabilities(), net, mode).map(|_| ())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    pub(crate) filesystem_writes: Level,
    pub(crate) network_deny: Level,
    pub(crate) apply_fs: bool,
    pub(crate) apply_net_deny: bool,
    pub(crate) notes: Vec<String>,
}

fn refuse(what: &str, why: &str) -> ProvioError {
    ProvioError::Sandbox(format!(
        "the kernel cannot enforce {what} for this run: {why}. Refusing to launch (fail closed)"
    ))
}

/// Decide what an interactive run enforces (pure; no syscalls).
pub(crate) fn plan(caps: &Capabilities, net: Net, mode: Mode) -> Result<Plan> {
    let mut notes = Vec::new();
    if mode == Mode::Unconfined {
        notes.push(
            "UNCONFINED: no kernel boundary; the agent can write anywhere this user can and \
             reach any host"
                .into(),
        );
        return Ok(Plan {
            filesystem_writes: Level::NotEnforced,
            network_deny: Level::NotEnforced,
            apply_fs: false,
            apply_net_deny: false,
            notes,
        });
    }
    let required = mode == Mode::Required;
    let filesystem_writes = match &caps.filesystem {
        Support::Full => Level::Enforced,
        Support::Partial(why) | Support::Unavailable(why) if required => {
            return Err(refuse("the filesystem write boundary", why));
        }
        Support::Partial(why) => {
            notes.push(format!("filesystem confinement is partial: {why}"));
            Level::Partial
        }
        Support::Unavailable(why) => {
            notes.push(format!(
                "filesystem writes are NOT confined by the kernel: {why}"
            ));
            Level::NotEnforced
        }
    };
    let (network_deny, apply_net_deny) = match net {
        Net::Open => (Level::NotEnforced, false),
        Net::None => match &caps.network_deny {
            Support::Full => (Level::Enforced, true),
            Support::Partial(why) | Support::Unavailable(why) if required => {
                return Err(refuse("--net none (deny all network)", why));
            }
            Support::Partial(why) => {
                notes.push(format!("network deny is partial: {why}"));
                (Level::Partial, true)
            }
            Support::Unavailable(why) => {
                notes.push(format!("network is NOT blocked (open): {why}"));
                (Level::NotEnforced, false)
            }
        },
    };
    Ok(Plan {
        filesystem_writes,
        network_deny,
        apply_fs: caps.filesystem.applicable(),
        apply_net_deny,
        notes,
    })
}

/// The run's private temp dir; removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn create() -> Result<Self> {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let raw = std::env::temp_dir().join(format!("provio-run-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&raw)?;
        Ok(TempDir(canonical(&raw)?))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(windows)]
const TEMP_VARS: &[&str] = &["TEMP", "TMP"];
#[cfg(not(windows))]
const TEMP_VARS: &[&str] = &["TMPDIR"];

/// A running interactive agent. Dropping it without [`wait`] kills
/// nothing on Unix (the agent is the terminal's foreground job) but ends
/// the Windows job; the private temp dir is removed either way.
///
/// [`wait`]: InteractiveChild::wait
pub struct InteractiveChild {
    #[cfg(unix)]
    child: std::process::Child,
    #[cfg(unix)]
    _signals: crate::unix::SignalGuard,
    #[cfg(windows)]
    child: Option<crate::windows_interactive::InteractiveChild>,
    _temp: TempDir,
}

impl InteractiveChild {
    /// OS process id of the agent.
    pub fn id(&self) -> u32 {
        #[cfg(unix)]
        {
            self.child.id()
        }
        #[cfg(windows)]
        {
            self.child.as_ref().map_or(0, |c| c.id())
        }
    }

    /// Wait for the agent to exit and return its exit code (Unix: a death
    /// by signal N is reported as 128 + N, the shell convention). The
    /// private temp dir is removed afterwards.
    pub fn wait(mut self) -> Result<i32> {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            let status = self.child.wait()?;
            Ok(status
                .code()
                .or_else(|| status.signal().map(|s| 128 + s))
                .unwrap_or(-1))
        }
        #[cfg(windows)]
        {
            match self.child.take() {
                Some(c) => c.wait(),
                None => Err(ProvioError::Sandbox("child already waited".into())),
            }
        }
    }
}

/// Absolute form of a (possibly absent) file: canonical parent + name.
fn absolute_file(p: &std::path::Path) -> Result<PathBuf> {
    if let Ok(c) = canonical(p) {
        return Ok(c);
    }
    let (Some(parent), Some(name)) = (p.parent(), p.file_name()) else {
        return Err(ProvioError::Sandbox(format!(
            "protected path {} has no parent (fail closed)",
            p.display()
        )));
    };
    Ok(canonical(parent)
        .unwrap_or_else(|_| parent.to_path_buf())
        .join(name))
}

/// How the protected files are kept unwritable on this OS.
fn protection_level(protected: &[PathBuf], apply_fs: bool, notes: &mut Vec<String>) -> Level {
    if protected.is_empty() {
        return Level::Enforced;
    }
    if !apply_fs {
        return Level::NotEnforced;
    }
    if cfg!(target_os = "macos") {
        // Seatbelt deny rules after the allow list: last match wins, and a
        // path rule covers create, unlink and rename-over too.
        Level::Enforced
    } else if cfg!(windows) {
        protection_windows(protected, notes)
    } else {
        notes.push(format!(
            "NOT protected: Landlock cannot exclude a file beneath a writable directory, so \
             the agent can rewrite {}",
            protected
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        Level::NotEnforced
    }
}

#[cfg(windows)]
fn protection_windows(protected: &[PathBuf], notes: &mut Vec<String>) -> Level {
    crate::windows_interactive::protection_level(protected, notes)
}
#[cfg(not(windows))]
fn protection_windows(_: &[PathBuf], _: &mut Vec<String>) -> Level {
    Level::NotEnforced
}

fn dedup_push(v: &mut Vec<PathBuf>, p: PathBuf) {
    if !v.contains(&p) {
        v.push(p);
    }
}

/// Launch `program args` interactively inside the boundary described by
/// `profile`. The child inherits provio's terminal / standard handles and
/// environment, plus `env` (applied last) and the temp variables pointed at
/// the private temp dir; its cwd is the workspace.
pub fn spawn_interactive(
    program: &str,
    args: &[String],
    env: &[(String, String)],
    profile: &Profile,
) -> Result<(InteractiveChild, InteractiveReport)> {
    let caps = capabilities();
    let plan = plan(&caps, profile.net, profile.mode)?;

    let workspace = canonical(&profile.workspace)?;
    if !workspace.is_dir() {
        return Err(ProvioError::Sandbox(format!(
            "workspace {} is not a directory",
            workspace.display()
        )));
    }
    let temp = TempDir::create()?;
    let mut writable = vec![workspace.clone()];
    dedup_push(&mut writable, temp.0.clone());
    for p in &profile.writable {
        let c = canonical(p).map_err(|_| {
            ProvioError::Sandbox(format!(
                "writable path {} does not exist (fail closed)",
                p.display()
            ))
        })?;
        dedup_push(&mut writable, c);
    }
    let mut notes = plan.notes.clone();
    let protected: Vec<PathBuf> = profile
        .protect
        .iter()
        .map(|p| absolute_file(p))
        .collect::<Result<_>>()?;
    let protection = protection_level(&protected, plan.apply_fs, &mut notes);
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut labelled: Vec<PathBuf> = Vec::new();

    #[cfg(target_os = "linux")]
    if plan.apply_fs {
        crate::linux::check_workspace_fs(&workspace)?;
    }
    #[cfg(windows)]
    if plan.apply_fs {
        let added = crate::windows_interactive::label_writable(&writable)?;
        labelled = added.into_iter().filter(|p| *p != temp.0).collect();
    }

    let temp_s = temp.0.to_string_lossy().into_owned();
    let mut child_env: Vec<(String, String)> = TEMP_VARS
        .iter()
        .map(|k| (k.to_string(), temp_s.clone()))
        .collect();
    child_env.extend(env.iter().cloned());

    let report = InteractiveReport {
        mode: profile.mode,
        net: profile.net,
        filesystem_writes: plan.filesystem_writes,
        network_deny: plan.network_deny,
        mechanism: if profile.mode == Mode::Unconfined {
            "none (unconfined)".into()
        } else {
            caps.mechanism.clone()
        },
        writable: writable.clone(),
        temp_dir: temp.0.clone(),
        protected: protected.clone(),
        protection,
        labelled,
        notes,
    };

    #[cfg(unix)]
    {
        use std::process::{Command, Stdio};
        let mut cmd = Command::new(program);
        cmd.args(args)
            .envs(child_env.iter().map(|(k, v)| (k, v)))
            .current_dir(&workspace)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let refs: Vec<&std::path::Path> = writable.iter().map(PathBuf::as_path).collect();
        let (fs, net_deny) = (plan.apply_fs, plan.apply_net_deny);
        #[cfg(target_os = "linux")]
        let _confinement = if profile.mode == Mode::Unconfined {
            None
        } else {
            use crate::linux::NetFilter;
            let net = if net_deny {
                NetFilter::DenyAll
            } else if crate::linux::seccomp_filter_supported() {
                NetFilter::OpenHardened
            } else {
                NetFilter::None
            };
            let c = crate::linux::Confinement::build_interactive(&refs, fs, net)?;
            c.install(&mut cmd);
            Some(c)
        };
        #[cfg(target_os = "macos")]
        let _confinement = if fs || net_deny {
            let prot: Vec<&std::path::Path> = protected.iter().map(PathBuf::as_path).collect();
            let c = crate::macos::Confinement::build_interactive(&refs, &prot, fs, net_deny)?;
            c.install(&mut cmd);
            Some(c)
        } else {
            None
        };
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let _ = (refs, fs, net_deny);

        crate::unix::reset_signals_in_child(&mut cmd);
        let signals = crate::unix::SignalGuard::install();
        let child = cmd.spawn().map_err(|e| {
            ProvioError::Sandbox(format!(
                "spawn {program} failed (confinement is applied before exec; fail closed): {e}"
            ))
        })?;
        signals.forward_to(child.id());
        Ok((
            InteractiveChild {
                child,
                _signals: signals,
                _temp: temp,
            },
            report,
        ))
    }
    #[cfg(windows)]
    {
        // The full environment: provio's own (minus cmd.exe's per-drive
        // `=C:` entries), then the overrides.
        let mut full: Vec<(String, String)> = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .filter(|(k, _)| !k.is_empty() && !k.contains('='))
            .collect();
        full.extend(child_env);
        let child =
            crate::windows_interactive::spawn(program, args, &workspace, &full, plan.apply_fs)?;
        Ok((
            InteractiveChild {
                child: Some(child),
                _temp: temp,
            },
            report,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(fs: Support, net: Support) -> Capabilities {
        Capabilities {
            filesystem: fs,
            network_deny: net,
            mechanism: "test".into(),
        }
    }

    #[test]
    fn required_with_full_support_enforces_fs_and_leaves_net_open() {
        let p = plan(
            &caps(Support::Full, Support::Full),
            Net::Open,
            Mode::Required,
        )
        .unwrap();
        assert_eq!(p.filesystem_writes, Level::Enforced);
        assert_eq!(p.network_deny, Level::NotEnforced);
        assert!(p.apply_fs && !p.apply_net_deny);
    }

    #[test]
    fn required_refuses_missing_fs_or_net_none() {
        let e = plan(
            &caps(Support::Unavailable("no ll".into()), Support::Full),
            Net::Open,
            Mode::Required,
        )
        .unwrap_err();
        assert!(e.to_string().contains("fail closed") && e.to_string().contains("no ll"));
        let e = plan(
            &caps(Support::Full, Support::Unavailable("no wfp".into())),
            Net::None,
            Mode::Required,
        )
        .unwrap_err();
        assert!(e.to_string().contains("--net none") && e.to_string().contains("no wfp"));
        // Net open does not need network-deny support.
        plan(
            &caps(Support::Full, Support::Unavailable("no wfp".into())),
            Net::Open,
            Mode::Required,
        )
        .unwrap();
    }

    #[test]
    fn best_effort_reports_gaps() {
        let p = plan(
            &caps(
                Support::Partial("hole".into()),
                Support::Unavailable("no wfp".into()),
            ),
            Net::None,
            Mode::BestEffort,
        )
        .unwrap();
        assert_eq!(p.filesystem_writes, Level::Partial);
        assert_eq!(p.network_deny, Level::NotEnforced);
        assert!(p.apply_fs && !p.apply_net_deny);
        assert_eq!(p.notes.len(), 2);
    }

    #[test]
    fn unconfined_applies_nothing_and_says_so() {
        let p = plan(
            &caps(Support::Full, Support::Full),
            Net::Open,
            Mode::Unconfined,
        )
        .unwrap();
        assert!(!p.apply_fs && !p.apply_net_deny);
        assert!(p.notes[0].contains("UNCONFINED"));
    }

    #[test]
    fn report_lines_never_overclaim() {
        let mut r = InteractiveReport {
            mode: Mode::Required,
            net: Net::Open,
            filesystem_writes: Level::Enforced,
            network_deny: Level::NotEnforced,
            mechanism: "m".into(),
            writable: vec![],
            temp_dir: PathBuf::new(),
            protected: vec![],
            protection: Level::Enforced,
            labelled: vec![],
            notes: vec![],
        };
        assert!(r.network_line().contains("not filtered"));
        r.net = Net::None;
        assert!(r.network_line().contains("OPEN"));
        r.network_deny = Level::Enforced;
        assert!(r.network_line().contains("denied by the kernel"));
        r.mode = Mode::Unconfined;
        assert!(r.filesystem_line().contains("NOT enforced"));
    }
}
