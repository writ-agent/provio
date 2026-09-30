//! Enforcement planning for the `local-os` backend (spec §6B).
//!
//! Pure logic, no syscalls: given what the spec demands ([`SandboxSpec`]),
//! what this kernel can enforce ([`Capabilities`], from `platform`), and how
//! strict the operator asked us to be ([`EnforcementMode`]), decide whether
//! a run may proceed and exactly what will be enforced. Fail closed is the
//! default: [`EnforcementMode::Required`] refuses any run whose spec cannot
//! be fully enforced by the kernel.

use provio_core::error::{ProvioError, Result};
use provio_core::sandbox::SandboxSpec;

/// How strictly `local-os` treats a gap between the spec and what the
/// kernel can enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EnforcementMode {
    /// Fail closed (default): refuse to prepare a sandbox whose spec the
    /// kernel cannot fully enforce.
    #[default]
    Required,
    /// Explicit opt-in to degraded mode: apply whatever the kernel supports
    /// and run anyway. The per-sandbox [`EnforcementReport`] states every
    /// gap; nothing is silently upgraded to "enforced".
    BestEffort,
}

/// How much of one protection this kernel can provide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Support {
    /// The protection is fully enforced by the kernel.
    Full,
    /// Enforced with a known hole (the string names it). Not good enough for
    /// [`EnforcementMode::Required`].
    Partial(String),
    /// Not available at all (the string says why).
    Unavailable(String),
}

impl Support {
    pub fn is_full(&self) -> bool {
        matches!(self, Support::Full)
    }
    /// Whether the mechanism can be applied at all (full or partial).
    pub fn applicable(&self) -> bool {
        !matches!(self, Support::Unavailable(_))
    }
}

/// What this machine's kernel can enforce for `local-os` children.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    /// Writes confined to the workspace (+ the sandbox's private temp dir).
    pub filesystem: Support,
    /// All network egress denied.
    pub network_deny: Support,
    /// Human-readable mechanism, e.g. "Landlock ABI v3 + seccomp-bpf".
    pub mechanism: String,
}

/// Whether one protection is in force for a prepared sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Enforced,
    /// Applied, but with a known hole (see the report's notes).
    Partial,
    NotEnforced,
}

/// Exactly what a prepared sandbox enforces. `provio` surfaces this verbatim
/// (spec §6: coverage honesty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementReport {
    pub mode: EnforcementMode,
    /// Out-of-workspace writes denied by the kernel.
    pub filesystem_writes: Level,
    /// Network egress denied by the kernel. An allow-list (non-empty
    /// `allowed_hosts`) is never reported as enforced: no `local-os`
    /// mechanism filters by host.
    pub network_egress: Level,
    pub mechanism: String,
    pub notes: Vec<String>,
    /// Apply the filesystem confinement (full or partial) at spawn.
    pub(crate) apply_filesystem: bool,
    /// Apply the deny-all network filter at spawn.
    pub(crate) apply_network_deny: bool,
}

impl EnforcementReport {
    /// True only when every protection the spec demands is kernel-enforced.
    pub fn fully_enforced(&self) -> bool {
        self.filesystem_writes == Level::Enforced && self.network_egress == Level::Enforced
    }
}

fn refuse(what: &str, why: &str) -> ProvioError {
    ProvioError::Sandbox(format!(
        "local-os cannot enforce {what}: {why}. Refusing to run (fail closed); \
         degraded execution requires an explicit EnforcementMode::BestEffort"
    ))
}

/// Decide what a run of `spec` will enforce on a machine with `caps`.
pub(crate) fn plan(
    spec: &SandboxSpec,
    caps: &Capabilities,
    mode: EnforcementMode,
) -> Result<EnforcementReport> {
    let required = mode == EnforcementMode::Required;
    let mut notes = Vec::new();

    let filesystem_writes = match &caps.filesystem {
        Support::Full => Level::Enforced,
        Support::Partial(hole) if required => {
            return Err(refuse("the workspace write boundary", hole));
        }
        Support::Unavailable(why) if required => {
            return Err(refuse("the workspace write boundary", why));
        }
        Support::Partial(hole) => {
            notes.push(format!("filesystem confinement is partial: {hole}"));
            Level::Partial
        }
        Support::Unavailable(why) => {
            notes.push(format!(
                "filesystem writes are NOT confined by the kernel: {why}"
            ));
            Level::NotEnforced
        }
    };

    let (network_egress, apply_network_deny) = if spec.allowed_hosts.is_empty() {
        match &caps.network_deny {
            Support::Full => (Level::Enforced, true),
            Support::Partial(hole) | Support::Unavailable(hole) if required => {
                return Err(refuse("deny-all network egress", hole));
            }
            Support::Partial(hole) => {
                notes.push(format!("network deny is partial: {hole}"));
                (Level::Partial, true)
            }
            Support::Unavailable(why) => {
                notes.push(format!("network egress is NOT blocked: {why}"));
                (Level::NotEnforced, false)
            }
        }
    } else {
        let shown: Vec<&str> = spec
            .allowed_hosts
            .iter()
            .take(5)
            .map(String::as_str)
            .collect();
        let why = format!(
            "the per-host egress allow-list [{}{}] is not kernel-enforceable by \
             local-os (Landlock/seccomp, Seatbelt and AppContainer filter by \
             socket family or all-or-nothing, never by hostname)",
            shown.join(", "),
            if spec.allowed_hosts.len() > 5 {
                ", ..."
            } else {
                ""
            }
        );
        if required {
            return Err(refuse("the egress allow-list", &why));
        }
        notes.push(format!("network egress is fully OPEN: {why}"));
        (Level::NotEnforced, false)
    };

    Ok(EnforcementReport {
        mode,
        filesystem_writes,
        network_egress,
        mechanism: caps.mechanism.clone(),
        notes,
        apply_filesystem: caps.filesystem.applicable(),
        apply_network_deny,
    })
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

    fn spec(hosts: &[&str]) -> SandboxSpec {
        SandboxSpec {
            workspace: "ws".into(),
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
            env: Default::default(),
        }
    }

    #[test]
    fn full_support_is_fully_enforced() {
        let r = plan(
            &spec(&[]),
            &caps(Support::Full, Support::Full),
            EnforcementMode::Required,
        )
        .unwrap();
        assert!(r.fully_enforced());
        assert!(r.apply_filesystem && r.apply_network_deny);
        assert!(r.notes.is_empty());
    }

    #[test]
    fn missing_fs_enforcement_fails_closed_by_default() {
        let err = plan(
            &spec(&[]),
            &caps(Support::Unavailable("no Landlock".into()), Support::Full),
            EnforcementMode::default(),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("fail closed") && msg.contains("no Landlock"),
            "{msg}"
        );
    }

    #[test]
    fn partial_fs_enforcement_fails_closed_by_default() {
        let err = plan(
            &spec(&[]),
            &caps(Support::Partial("truncate open".into()), Support::Full),
            EnforcementMode::Required,
        )
        .unwrap_err();
        assert!(err.to_string().contains("truncate open"));
    }

    #[test]
    fn missing_net_enforcement_fails_closed_by_default() {
        let err = plan(
            &spec(&[]),
            &caps(Support::Full, Support::Unavailable("no seccomp".into())),
            EnforcementMode::Required,
        )
        .unwrap_err();
        assert!(err.to_string().contains("no seccomp"));
    }

    #[test]
    fn allow_list_is_never_claimed_and_fails_closed() {
        let full = caps(Support::Full, Support::Full);
        let err = plan(
            &spec(&["api.example.com"]),
            &full,
            EnforcementMode::Required,
        )
        .unwrap_err();
        assert!(err.to_string().contains("api.example.com"));

        let r = plan(
            &spec(&["api.example.com"]),
            &full,
            EnforcementMode::BestEffort,
        )
        .unwrap();
        assert_eq!(r.network_egress, Level::NotEnforced);
        assert!(!r.apply_network_deny);
        assert_eq!(r.filesystem_writes, Level::Enforced);
        assert!(!r.fully_enforced());
        assert!(r.notes.iter().any(|n| n.contains("OPEN")));
    }

    #[test]
    fn best_effort_reports_every_gap() {
        let r = plan(
            &spec(&[]),
            &caps(
                Support::Unavailable("no Landlock".into()),
                Support::Unavailable("no seccomp".into()),
            ),
            EnforcementMode::BestEffort,
        )
        .unwrap();
        assert_eq!(r.filesystem_writes, Level::NotEnforced);
        assert_eq!(r.network_egress, Level::NotEnforced);
        assert!(!r.apply_filesystem && !r.apply_network_deny);
        assert_eq!(r.notes.len(), 2);
    }

    #[test]
    fn best_effort_applies_partial_protection() {
        let r = plan(
            &spec(&[]),
            &caps(Support::Partial("hole".into()), Support::Full),
            EnforcementMode::BestEffort,
        )
        .unwrap();
        assert_eq!(r.filesystem_writes, Level::Partial);
        assert!(r.apply_filesystem);
    }
}
