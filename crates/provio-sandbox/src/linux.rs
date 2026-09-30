//! Linux kernel enforcement for `local-os` (spec §6B): Landlock confines
//! filesystem *writes*, seccomp-bpf denies socket creation.
//!
//! Everything that allocates or can fail in interesting ways — opening the
//! rule paths, creating the Landlock ruleset, compiling the BPF program —
//! happens in the parent. The child, between `fork` and `exec`
//! (`CommandExt::pre_exec`), only issues three raw syscalls
//! (`prctl(PR_SET_NO_NEW_PRIVS)`, `landlock_restrict_self`, `seccomp`) on
//! memory that was fully prepared before the fork: async-signal-safe.
//!
//! What is enforced:
//! - **Filesystem.** Every Landlock write right the running ABI knows
//!   (write/truncate files, create/remove/rename entries, make
//!   nodes/symlinks/sockets/fifos, `refer`, and device ioctls on ABI >= 5)
//!   is handled, and granted only beneath the workspace and the sandbox's
//!   private temp dir (plus write/truncate on `/dev/null`, `/dev/zero`,
//!   `/dev/full`). Reads and exec are deliberately *not* handled: the spec
//!   restricts writes only. Landlock is not a DAC check, so it holds for a
//!   root child too, and a Landlock-confined process can neither mount nor
//!   ptrace a process outside its domain. On ABI >= 6 the child is also
//!   scoped: no signals to, and no abstract-unix-socket connections into,
//!   processes outside the sandbox.
//! - **Network (deny-all).** `socket(2)` fails with `EPERM` for *every*
//!   family — AF_UNIX included, because a pathname unix socket
//!   (docker.sock, D-Bus, systemd-resolved) is a proxy to egress and to
//!   the host. `socketpair(AF_UNIX)` stays allowed (in-process IPC, no
//!   peer outside the sandbox). `io_uring_setup(2)` is denied (IORING_OP_SOCKET
//!   would bypass the socket filter). The x32 ABI variants of those
//!   syscalls are denied too; foreign-architecture syscalls (i386 via
//!   `int 0x80`) kill the process (seccompiler's arch check).
//!
//! Known caveat: Landlock rules identify directories by inode. On
//! filesystems whose inodes are not stable a rule may stop matching; the
//! failure mode is a spurious *deny* inside the workspace, never an allow
//! outside it. Measured on WSL2's 9p drvfs (`/mnt/c`): every write inside
//! the workspace is denied, so `prepare` rejects 9p workspaces with a clear
//! error ([`check_workspace_fs`]). Other network/FUSE filesystems are not
//! detected and may show the same spurious denies.

use std::collections::BTreeMap;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use landlock::{
    Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, Scope, ABI,
};
use provio_core::error::{ProvioError, Result};
use seccompiler::{
    sock_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule, TargetArch,
};

use crate::enforce::{Capabilities, Support};

/// `LANDLOCK_CREATE_RULESET_VERSION` (uapi/linux/landlock.h).
const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;

/// Highest Landlock ABI whose semantics this adapter was written and
/// reviewed against. Newer kernels are driven at this ABI (the kernel's
/// compatibility contract keeps older ABIs' behavior stable).
const MAX_ABI: i32 = 6;

/// Device files every child may still write (`cmd > /dev/null`).
const WRITABLE_DEVICES: &[&str] = &["/dev/null", "/dev/zero", "/dev/full"];

/// Interactive runs also need the controlling terminal and pty creation
/// (editors, pagers, credential prompts and pty-spawning tools open them
/// directly rather than using the inherited descriptors).
const INTERACTIVE_DEVICES: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/tty",
    "/dev/ptmx",
];

/// Directories beneath which interactive runs may write: pty slaves, and
/// POSIX shared memory (`shm_open`: Python multiprocessing, Chromium).
const INTERACTIVE_DEVICE_DIRS: &[&str] = &["/dev/pts", "/dev/shm"];

/// Which seccomp filter an interactive child gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetFilter {
    /// No filter.
    None,
    /// Deny-all egress (the batch backend's filter).
    DenyAll,
    /// Network open: only AF_UNIX / AF_INET / AF_INET6 / AF_NETLINK
    /// sockets may be created, and io_uring is denied (kernel attack
    /// surface; its socket ops would bypass the family check).
    OpenHardened,
}

/// The running kernel's Landlock ABI version; 0 when unsupported/disabled.
pub(crate) fn landlock_abi() -> i32 {
    // SAFETY: with a NULL attr and size 0, LANDLOCK_CREATE_RULESET_VERSION
    // only returns the ABI version; the kernel reads no user memory.
    let v = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if v < 0 {
        0
    } else {
        v as i32
    }
}

/// Whether seccomp *filter* mode exists (CONFIG_SECCOMP_FILTER). Probing
/// with a NULL program installs nothing: the kernel copies the program
/// header first and fails with EFAULT when the mode is supported, EINVAL
/// when it is not.
pub(crate) fn seccomp_filter_supported() -> bool {
    // SAFETY: integer arguments only; a NULL program pointer is rejected by
    // the kernel's copy_from_user with EFAULT, nothing is dereferenced here.
    let rc = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    rc == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EFAULT)
}

fn target_arch() -> Option<TargetArch> {
    if cfg!(target_arch = "x86_64") {
        Some(TargetArch::x86_64)
    } else if cfg!(target_arch = "aarch64") {
        Some(TargetArch::aarch64)
    } else if cfg!(target_arch = "riscv64") {
        Some(TargetArch::riscv64)
    } else {
        None
    }
}

pub(crate) fn capabilities() -> Capabilities {
    let abi = landlock_abi();
    let filesystem = match abi {
        a if a <= 0 => Support::Unavailable(
            "Landlock is not available in this kernel (needs Linux >= 5.13 built with \
             CONFIG_SECURITY_LANDLOCK=y and `landlock` in the active LSM list)"
                .into(),
        ),
        1 | 2 => Support::Partial(format!(
            "Landlock ABI v{abi} cannot restrict truncate(2): an existing file outside the \
             workspace could be truncated (needs ABI v3, Linux >= 6.2)"
        )),
        _ => Support::Full,
    };
    let network_deny = if target_arch().is_none() {
        Support::Unavailable(format!(
            "no seccomp filter is built for the {} architecture",
            std::env::consts::ARCH
        ))
    } else if !seccomp_filter_supported() {
        Support::Unavailable(
            "seccomp-bpf filtering is not available in this kernel (CONFIG_SECCOMP_FILTER)".into(),
        )
    } else {
        Support::Full
    };
    let mechanism = if abi > 0 {
        format!(
            "Landlock ABI v{} (filesystem writes) + seccomp-bpf (socket creation)",
            abi.min(MAX_ABI)
        )
    } else {
        "Landlock (unavailable) + seccomp-bpf (socket creation)".into()
    };
    Capabilities {
        filesystem,
        network_deny,
        mechanism,
    }
}

/// `V9FS_MAGIC` (linux/magic.h): 9p, which backs WSL2's `/mnt/c` drvfs.
const V9FS_MAGIC: i64 = 0x0102_1997;

/// Refuse workspaces on filesystems where Landlock rules cannot match
/// (9p: inodes are not stable, so *every* write inside the workspace would
/// be denied). Not a security gap — the failure is a deny — but a clear
/// error beats a sandbox where nothing can be written.
pub(crate) fn check_workspace_fs(ws: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(ws.as_os_str().as_bytes()) else {
        return Err(ProvioError::Sandbox(format!(
            "workspace {} contains NUL (fail closed)",
            ws.display()
        )));
    };
    // SAFETY: plain-old-data out-struct; zero is a valid initial state.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: c is NUL-terminated and st a valid out-pointer.
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return Ok(()); // unknown: the Landlock rule open will surface errors
    }
    #[allow(clippy::unnecessary_cast)] // f_type's width differs per libc target
    let fs_type = st.f_type as i64;
    if fs_type == V9FS_MAGIC {
        return Err(ProvioError::Sandbox(format!(
            "workspace {} is on a 9p filesystem (e.g. WSL2's /mnt/c drvfs) where Landlock \
             rules cannot match inodes, so every write inside it would be denied; place the \
             workspace on a Linux filesystem (ext4/btrfs/tmpfs, e.g. under /home or /tmp)",
            ws.display()
        )));
    }
    Ok(())
}

fn ll_err(e: impl std::fmt::Display) -> ProvioError {
    ProvioError::Sandbox(format!(
        "landlock ruleset construction failed (fail closed): {e}"
    ))
}

/// Parent-side prepared confinement. Must outlive the `spawn` call of the
/// `Command` it was installed into (the child uses the ruleset fd).
pub(crate) struct Confinement {
    ruleset: Option<OwnedFd>,
    bpf: Option<Arc<BpfProgram>>,
}

impl Confinement {
    /// Build the Landlock ruleset (when `confine_fs`) granting writes only
    /// beneath `writable_dirs`, and the deny-all-network BPF program (when
    /// `deny_network`). Runs in the parent.
    pub(crate) fn build(
        writable_dirs: &[&Path],
        confine_fs: bool,
        deny_network: bool,
    ) -> Result<Self> {
        Self::build_with(
            writable_dirs,
            WRITABLE_DEVICES,
            &[],
            confine_fs,
            if deny_network {
                NetFilter::DenyAll
            } else {
                NetFilter::None
            },
        )
    }

    /// Interactive variant (`provio run`): `writable` may name files as well
    /// as directories; the terminal devices an interactive agent needs are
    /// writable too; `net` picks the seccomp filter.
    pub(crate) fn build_interactive(
        writable: &[&Path],
        confine_fs: bool,
        net: NetFilter,
    ) -> Result<Self> {
        Self::build_with(
            writable,
            INTERACTIVE_DEVICES,
            INTERACTIVE_DEVICE_DIRS,
            confine_fs,
            net,
        )
    }

    fn build_with(
        writable: &[&Path],
        devices: &[&str],
        device_dirs: &[&str],
        confine_fs: bool,
        net: NetFilter,
    ) -> Result<Self> {
        let ruleset = if confine_fs {
            Some(build_ruleset(writable, devices, device_dirs)?)
        } else {
            None
        };
        let bpf = match net {
            NetFilter::None => None,
            NetFilter::DenyAll => Some(Arc::new(build_network_filter()?)),
            NetFilter::OpenHardened => Some(Arc::new(build_open_network_filter()?)),
        };
        Ok(Confinement { ruleset, bpf })
    }

    /// Arrange for the child to apply this confinement before `exec`.
    pub(crate) fn install(&self, cmd: &mut Command) {
        let fd: RawFd = self.ruleset.as_ref().map_or(-1, |f| f.as_raw_fd());
        let bpf = self.bpf.clone();
        // SAFETY: the closure runs in the forked child. It only reads memory
        // prepared before the fork (an fd number and an immutable BPF
        // program behind an Arc that is not cloned or dropped in the child)
        // and calls async-signal-safe raw syscalls; it never allocates,
        // locks, or touches thread-local state.
        unsafe {
            cmd.pre_exec(move || apply_in_child(fd, bpf.as_deref().map(Vec::as_slice)));
        }
    }
}

fn build_ruleset(writable: &[&Path], devices: &[&str], device_dirs: &[&str]) -> Result<OwnedFd> {
    let abi_num = landlock_abi().min(MAX_ABI);
    if abi_num <= 0 {
        return Err(ProvioError::Sandbox(
            "Landlock is not available in this kernel (fail closed)".into(),
        ));
    }
    let abi = ABI::from(abi_num);
    let write = AccessFs::from_write(abi);
    let mut ruleset = Ruleset::default()
        // Never let the crate silently drop a right we asked for.
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(write)
        .map_err(ll_err)?;
    if abi >= ABI::V6 {
        ruleset = ruleset.scope(Scope::from_all(abi)).map_err(ll_err)?;
    }
    let mut created = ruleset.create().map_err(ll_err)?;
    let file_write = write & AccessFs::from_file(abi);
    for path in writable {
        let fd = PathFd::new(path).map_err(|e| {
            ProvioError::Sandbox(format!(
                "cannot open {} for the Landlock rule (fail closed): {e}",
                path.display()
            ))
        })?;
        // A rule on a file may only carry file rights.
        let rights = if path.is_dir() { write } else { file_write };
        created = created
            .add_rule(PathBeneath::new(fd, rights))
            .map_err(ll_err)?;
    }
    for dev in devices {
        if let Ok(fd) = PathFd::new(dev) {
            created = created
                .add_rule(PathBeneath::new(fd, file_write))
                .map_err(ll_err)?;
        }
    }
    for dir in device_dirs {
        if Path::new(dir).is_dir() {
            if let Ok(fd) = PathFd::new(dir) {
                created = created
                    .add_rule(PathBeneath::new(fd, write))
                    .map_err(ll_err)?;
            }
        }
    }
    let fd: Option<OwnedFd> = created.into();
    fd.ok_or_else(|| ll_err("the kernel returned no ruleset fd"))
}

/// Deny-all egress: every `socket(2)`, non-AF_UNIX `socketpair(2)`, and
/// `io_uring_setup(2)` fail with EPERM; everything else is allowed.
fn build_network_filter() -> Result<BpfProgram> {
    let err = |e: seccompiler::BackendError| {
        ProvioError::Sandbox(format!(
            "seccomp filter construction failed (fail closed): {e}"
        ))
    };
    let arch = target_arch().ok_or_else(|| {
        ProvioError::Sandbox(format!(
            "no seccomp filter for architecture {} (fail closed)",
            std::env::consts::ARCH
        ))
    })?;
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    // An empty rule list matches the syscall unconditionally.
    rules.insert(libc::SYS_socket, vec![]);
    rules.insert(
        libc::SYS_socketpair,
        vec![SeccompRule::new(vec![SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Ne,
            libc::AF_UNIX as u64,
        )
        .map_err(err)?])
        .map_err(err)?],
    );
    rules.insert(libc::SYS_io_uring_setup, vec![]);
    #[cfg(target_arch = "x86_64")]
    {
        // x32 ABI: same AUDIT_ARCH_X86_64, syscall number | 0x4000_0000.
        const X32: i64 = 0x4000_0000;
        rules.insert(X32 | libc::SYS_socket, vec![]);
        rules.insert(X32 | libc::SYS_socketpair, vec![]);
        rules.insert(X32 | libc::SYS_io_uring_setup, vec![]);
    }
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(err)?;
    BpfProgram::try_from(filter).map_err(err)
}

/// Network open, hardened: `socket(2)` / `socketpair(2)` of any family but
/// AF_UNIX, AF_INET, AF_INET6 and AF_NETLINK, and `io_uring_setup(2)`, fail
/// with EPERM (x32 variants: denied outright).
fn build_open_network_filter() -> Result<BpfProgram> {
    let err = |e: seccompiler::BackendError| {
        ProvioError::Sandbox(format!(
            "seccomp filter construction failed (fail closed): {e}"
        ))
    };
    let arch = target_arch().ok_or_else(|| {
        ProvioError::Sandbox(format!(
            "no seccomp filter for architecture {} (fail closed)",
            std::env::consts::ARCH
        ))
    })?;
    let other_family = || -> Result<Vec<SeccompRule>> {
        let conds = [
            libc::AF_UNIX,
            libc::AF_INET,
            libc::AF_INET6,
            libc::AF_NETLINK,
        ]
        .iter()
        .map(|&f| {
            SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, f as u64)
                .map_err(err)
        })
        .collect::<Result<Vec<_>>>()?;
        Ok(vec![SeccompRule::new(conds).map_err(err)?])
    };
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    rules.insert(libc::SYS_socket, other_family()?);
    rules.insert(libc::SYS_socketpair, other_family()?);
    rules.insert(libc::SYS_io_uring_setup, vec![]);
    #[cfg(target_arch = "x86_64")]
    {
        const X32: i64 = 0x4000_0000;
        rules.insert(X32 | libc::SYS_socket, vec![]);
        rules.insert(X32 | libc::SYS_socketpair, vec![]);
        rules.insert(X32 | libc::SYS_io_uring_setup, vec![]);
    }
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(err)?;
    BpfProgram::try_from(filter).map_err(err)
}

/// Runs in the forked child. Async-signal-safe: raw syscalls only.
fn apply_in_child(ruleset_fd: RawFd, bpf: Option<&[sock_filter]>) -> io::Result<()> {
    // SAFETY: prctl with integer arguments; required before an unprivileged
    // landlock_restrict_self / seccomp, and keeps setuid binaries from
    // regaining privileges inside the sandbox.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if ruleset_fd >= 0 {
        // SAFETY: ruleset_fd is a valid Landlock ruleset fd inherited from
        // the parent (kept open until spawn returns); flags must be 0.
        if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0u32) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    if let Some(prog) = bpf {
        let fprog = libc::sock_fprog {
            len: prog.len() as libc::c_ushort,
            // seccompiler::sock_filter is #[repr(C)] with the exact layout
            // of the kernel's struct sock_filter (u16, u8, u8, u32).
            filter: prog.as_ptr() as *mut libc::sock_filter,
        };
        // SAFETY: fprog points at a live, correctly laid out BPF program for
        // the duration of the call; the kernel copies it before returning.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                0 as libc::c_uint,
                &fprog as *const libc::sock_fprog,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_filter_compiles_for_this_arch() {
        if target_arch().is_some() {
            let prog = build_network_filter().unwrap();
            assert!(!prog.is_empty() && prog.len() < 4096);
            let open = build_open_network_filter().unwrap();
            assert!(!open.is_empty() && open.len() < 4096);
        }
    }

    #[test]
    fn capabilities_are_consistent_with_probes() {
        let caps = capabilities();
        assert_eq!(caps.filesystem.applicable(), landlock_abi() > 0);
        assert_eq!(
            caps.network_deny.is_full(),
            target_arch().is_some() && seccomp_filter_supported()
        );
    }
}
