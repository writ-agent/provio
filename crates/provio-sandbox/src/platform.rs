//! Kernel-level hardening status per platform.
//!
//! HONESTY REQUIREMENT (spec §6, §15): nothing here may claim enforcement
//! that is not implemented and tested. `provio doctor` surfaces these notes
//! verbatim so users know exactly which guarantees hold. The values are
//! *probed* on the running machine (Landlock ABI, seccomp filter mode,
//! AppContainer + firewall services), not assumed from the target OS.

use crate::enforce::{Capabilities, Support};

/// What the current platform's kernel boundary enforces for `local-os`.
#[derive(Debug, Clone)]
pub struct KernelHardening {
    pub platform: &'static str,
    /// True only when both the workspace write boundary and deny-all egress
    /// are fully enforced by this kernel (implemented and tested).
    pub enforced: bool,
    /// The mechanism enforcing the boundary (spec §6B).
    pub mechanism: String,
    /// Workspace write boundary support on this machine.
    pub filesystem: Support,
    /// Deny-all network egress support on this machine.
    pub network: Support,
    /// Shown by `provio doctor`.
    pub notes: String,
}

/// What this machine's kernel can enforce (probed at call time).
pub fn capabilities() -> Capabilities {
    #[cfg(target_os = "linux")]
    {
        crate::linux::capabilities()
    }
    #[cfg(target_os = "macos")]
    {
        crate::macos::capabilities()
    }
    #[cfg(windows)]
    {
        crate::windows::capabilities()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Capabilities {
            filesystem: Support::Unavailable("unsupported platform".into()),
            network_deny: Support::Unavailable("unsupported platform".into()),
            mechanism: "none".into(),
        }
    }
}

const PLATFORM: &str = if cfg!(target_os = "linux") {
    "linux"
} else if cfg!(target_os = "macos") {
    "macos"
} else if cfg!(windows) {
    "windows"
} else {
    "other"
};

/// What is enforced when support is full, per platform.
const FS_DETAIL: &str = if cfg!(target_os = "linux") {
    "writes outside the workspace and the sandbox's private temp dir are denied by \
     Landlock (holds for a root child too)"
} else if cfg!(target_os = "macos") {
    "writes outside the workspace and the sandbox's private temp dir are denied by the \
     Seatbelt profile"
} else {
    "the AppContainer token can write only where its per-workspace SID is granted (the \
     workspace, plus the container's own profile folder that holds its TEMP); reads are \
     limited the same way plus locations readable by ALL APPLICATION PACKAGES"
};

const NET_DETAIL: &str = if cfg!(target_os = "linux") {
    "seccomp denies socket(2) for every family (AF_UNIX included), non-AF_UNIX \
     socketpair(2), and io_uring_setup(2)"
} else if cfg!(target_os = "macos") {
    "the Seatbelt profile denies network* (including unix-domain sockets)"
} else {
    "the AppContainer has no network capabilities, so Windows' AppContainer WFP filters \
     block all outbound connections, loopback included"
};

const RESIDUAL: &str = if cfg!(target_os = "linux") {
    "reads and exec are not restricted; Landlock rules on filesystems with unstable inodes \
     (WSL2 /mnt/c drvfs, some FUSE) may spuriously deny writes inside the workspace"
} else if cfg!(target_os = "macos") {
    "reads, exec and mach IPC are not restricted (a system daemon reachable over mach could \
     perform I/O on the child's behalf)"
} else {
    "objects writable by ALL APPLICATION PACKAGES remain writable; programs under the user \
     profile cannot be executed inside the AppContainer; the workspace keeps the \
     AppContainer ACE after teardown"
};

fn describe(s: &Support, detail: &str) -> String {
    match s {
        Support::Full => format!("enforced — {detail}"),
        Support::Partial(hole) => format!("PARTIAL — {hole}"),
        Support::Unavailable(why) => format!("NOT enforced — {why}"),
    }
}

pub fn kernel_hardening() -> KernelHardening {
    let caps = capabilities();
    let enforced = caps.filesystem.is_full() && caps.network_deny.is_full();
    let notes = format!(
        "filesystem: {}. network: {}. residual: {}. A non-empty egress allow-list \
         (allowed_hosts) is never kernel-enforced by local-os: it fails closed unless \
         best-effort mode is explicitly enabled, which then leaves the network open. {}",
        describe(&caps.filesystem, FS_DETAIL),
        describe(&caps.network_deny, NET_DETAIL),
        RESIDUAL,
        if enforced {
            "Default mode is fail closed."
        } else {
            "Default (fail-closed) mode REFUSES to run on this machine until the missing \
             enforcement is available."
        }
    );
    KernelHardening {
        platform: PLATFORM,
        enforced,
        mechanism: caps.mechanism,
        filesystem: caps.filesystem,
        network: caps.network_deny,
        notes,
    }
}
