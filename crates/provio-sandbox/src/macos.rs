//! macOS kernel enforcement for `local-os` (spec §6B): Seatbelt.
//!
//! The SBPL profile is generated and turned into a C string in the parent;
//! the child, between `fork` and `exec`, calls `sandbox_init(profile, 0,
//! &err)` (libsystem_sandbox, part of libSystem — deprecated in headers but
//! present and used by Apple's own tools). The profile is inherited by
//! everything the child execs.
//!
//! Profile shape (last matching rule wins in SBPL):
//! - `(allow default)` — reads, exec, mach IPC are not restricted (the spec
//!   restricts writes and egress only);
//! - `(deny file-write*)` then `(allow file-write* ...)` beneath the
//!   canonical workspace and the sandbox's private temp dir, plus
//!   `/dev/null`, `/dev/zero`, `/dev/fd/N`, `/dev/stdout`, `/dev/stderr`,
//!   `/dev/dtracehelper`;
//! - `(deny network*)` when the spec denies egress — this includes unix
//!   domain sockets (e.g. mDNSResponder's socket, a DNS channel).
//!
//! Residual: mach services reachable under `(allow default)` (e.g. system
//! daemons that perform network I/O on a client's behalf) are not blocked.
//!
//! Async-signal-safety: `sandbox_init` compiles the profile in the child,
//! which allocates. That is sound on macOS because libSystem registers
//! pthread_atfork handlers that leave libmalloc usable in a forked child,
//! and the child never returns to Rust code that could observe inconsistent
//! state: it either execs or reports the error and exits. It is still
//! the least async-signal-safe step in this crate, and the one to revisit
//! first (e.g. a re-exec trampoline) if a problem ever shows up.

use std::ffi::{c_char, c_int, CString};
use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use provio_core::error::{ProvioError, Result};

use crate::enforce::{Capabilities, Support};

extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

pub(crate) fn capabilities() -> Capabilities {
    Capabilities {
        filesystem: Support::Full,
        network_deny: Support::Full,
        mechanism: "Seatbelt (sandbox_init with a generated SBPL profile)".into(),
    }
}

/// Quote a path as an SBPL string literal. Canonical, UTF-8, no control
/// characters — anything else fails closed.
fn sbpl_string(p: &Path) -> Result<String> {
    let s = p.to_str().ok_or_else(|| {
        ProvioError::Sandbox(format!(
            "path {} is not UTF-8; cannot express it in a Seatbelt profile (fail closed)",
            p.display()
        ))
    })?;
    if s.chars().any(char::is_control) {
        return Err(ProvioError::Sandbox(format!(
            "path {s:?} contains control characters (fail closed)"
        )));
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    Ok(out)
}

/// Generate the SBPL profile. `writable_dirs` must be canonical (Seatbelt
/// matches on resolved paths: `/tmp` is `/private/tmp`).
pub(crate) fn profile(
    writable_dirs: &[&Path],
    confine_fs: bool,
    deny_network: bool,
) -> Result<String> {
    let mut p = String::from("(version 1)\n(allow default)\n");
    if confine_fs {
        p.push_str("(deny file-write*)\n(allow file-write*\n");
        for d in writable_dirs {
            p.push_str(&format!("    (subpath {})\n", sbpl_string(d)?));
        }
        p.push_str(
            "    (literal \"/dev/null\")\n    (literal \"/dev/zero\")\n    \
             (literal \"/dev/stdout\")\n    (literal \"/dev/stderr\")\n    \
             (literal \"/dev/dtracehelper\")\n    (regex #\"^/dev/fd/[0-9]+$\"))\n",
        );
    }
    if deny_network {
        p.push_str("(deny network*)\n");
    }
    Ok(p)
}

/// Escape a path for an SBPL `#"..."` regex literal (raw: backslashes are
/// literal, `"` cannot appear).
fn sbpl_regex_literal(p: &Path) -> Result<String> {
    let s = p.to_str().ok_or_else(|| {
        ProvioError::Sandbox(format!(
            "path {} is not UTF-8; cannot express it in a Seatbelt profile (fail closed)",
            p.display()
        ))
    })?;
    if s.chars().any(|c| c.is_control() || c == '"') {
        return Err(ProvioError::Sandbox(format!(
            "path {s:?} contains a quote or control character (fail closed)"
        )));
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if "\\.^$*+?()[]{}|".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    Ok(out)
}

/// Interactive profile (`provio run`): writes confined to `writable`
/// (directories as subpaths; files as literals plus their `<file>.<suffix>`
/// siblings, which atomic-rename writers such as Claude Code's
/// `~/.claude.json.tmp.<pid>.<hex>` need), the terminal devices, and
/// optionally no network at all. `protect` files stay unwritable even
/// beneath a writable subpath: their deny rules come after the allow list
/// (the last matching SBPL rule wins) and cover create, write, unlink and
/// rename-over.
pub(crate) fn profile_interactive(
    writable: &[&Path],
    protect: &[&Path],
    confine_fs: bool,
    deny_network: bool,
) -> Result<String> {
    let mut p = String::from("(version 1)\n(allow default)\n");
    if confine_fs {
        p.push_str("(deny file-write*)\n(allow file-write*\n");
        for w in writable {
            if w.is_dir() {
                p.push_str(&format!("    (subpath {})\n", sbpl_string(w)?));
            } else {
                p.push_str(&format!("    (literal {})\n", sbpl_string(w)?));
                p.push_str(&format!(
                    "    (regex #\"^{}\\.[^/]+$\")\n",
                    sbpl_regex_literal(w)?
                ));
            }
        }
        p.push_str(
            "    (literal \"/dev/null\")\n    (literal \"/dev/zero\")\n    \
             (literal \"/dev/stdout\")\n    (literal \"/dev/stderr\")\n    \
             (literal \"/dev/dtracehelper\")\n    (literal \"/dev/tty\")\n    \
             (literal \"/dev/ptmx\")\n    (regex #\"^/dev/ttys[0-9]+$\")\n    \
             (regex #\"^/dev/fd/[0-9]+$\"))\n",
        );
        for f in protect {
            p.push_str(&format!(
                "(deny file-write* (literal {}))\n",
                sbpl_string(f)?
            ));
        }
    }
    if deny_network {
        p.push_str("(deny network*)\n");
    }
    Ok(p)
}

/// Parent-side prepared confinement.
pub(crate) struct Confinement {
    profile: Arc<CString>,
}

impl Confinement {
    /// Interactive variant (see [`profile_interactive`]).
    pub(crate) fn build_interactive(
        writable: &[&Path],
        protect: &[&Path],
        confine_fs: bool,
        deny_network: bool,
    ) -> Result<Self> {
        Self::from_text(profile_interactive(
            writable,
            protect,
            confine_fs,
            deny_network,
        )?)
    }

    pub(crate) fn build(
        writable_dirs: &[&Path],
        confine_fs: bool,
        deny_network: bool,
    ) -> Result<Self> {
        Self::from_text(profile(writable_dirs, confine_fs, deny_network)?)
    }

    fn from_text(text: String) -> Result<Self> {
        let profile = CString::new(text).map_err(|_| {
            ProvioError::Sandbox("Seatbelt profile contains NUL (fail closed)".into())
        })?;
        Ok(Confinement {
            profile: Arc::new(profile),
        })
    }

    pub(crate) fn install(&self, cmd: &mut Command) {
        let profile = Arc::clone(&self.profile);
        let apply = move || {
            let mut err: *mut c_char = std::ptr::null_mut();
            // SAFETY: profile is a valid NUL-terminated string; err is a
            // valid out-pointer, freed with sandbox_free_error.
            let rc = unsafe { sandbox_init(profile.as_ptr(), 0, &mut err) };
            if rc != 0 {
                if !err.is_null() {
                    // SAFETY: err was allocated by sandbox_init.
                    unsafe { sandbox_free_error(err) };
                }
                return Err(io::Error::from_raw_os_error(1 /* EPERM */));
            }
            Ok(())
        };
        // SAFETY: `apply` runs in the forked child; it reads only the
        // profile C string prepared before the fork and calls sandbox_init
        // (see the module docs for why its allocation is acceptable after
        // fork on macOS).
        unsafe {
            cmd.pre_exec(apply);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_denies_writes_and_network_and_escapes_paths() {
        let p = profile(&[Path::new("/private/tmp/a \"b\\c")], true, true).unwrap();
        assert!(p.contains("(deny file-write*)"));
        assert!(p.contains("(subpath \"/private/tmp/a \\\"b\\\\c\")"));
        assert!(p.contains("(deny network*)"));
        let open = profile(&[Path::new("/w")], true, false).unwrap();
        assert!(!open.contains("network"));
    }

    #[test]
    fn interactive_profile_allows_files_siblings_and_ttys() {
        let dir = std::env::temp_dir().canonicalize().unwrap();
        let file = dir.join(format!("provio-sbpl-{}.json", std::process::id()));
        std::fs::write(&file, b"{}").unwrap();
        let prot = dir.join("settings.json");
        let p = profile_interactive(
            &[dir.as_path(), file.as_path()],
            &[prot.as_path()],
            true,
            false,
        )
        .unwrap();
        let _ = std::fs::remove_file(&file);
        assert!(p.contains(&format!("(subpath \"{}\")", dir.display())));
        assert!(p.contains(&format!("(literal \"{}\")", file.display())));
        assert!(p.contains("\\.json\\.[^/]+$\")"), "{p}");
        assert!(p.contains("/dev/ttys"));
        assert!(!p.contains("network"));
        let deny = format!("(deny file-write* (literal \"{}\"))", prot.display());
        let allow_at = p.find("(allow file-write*").unwrap();
        assert!(
            p.find(&deny).unwrap() > allow_at,
            "deny must follow the allow list"
        );
        assert!(profile_interactive(&[dir.as_path()], &[], true, true)
            .unwrap()
            .contains("(deny network*)"));
    }

    #[test]
    fn control_characters_fail_closed() {
        assert!(profile(&[Path::new("/tmp/a\nb")], true, true).is_err());
    }
}
