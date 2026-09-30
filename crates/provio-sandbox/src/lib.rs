//! provio-sandbox — `SandboxBackend` adapters (spec §8).
//!
//! Provio's opinion is about *which* call runs, not *how* it is contained.
//! `local-os` is the default workstation backend; container/VM/cluster
//! adapters are detected if present (see [`detect::detect_backends`]).

// `unsafe` is confined to the per-OS kernel-enforcement modules below (raw
// syscalls / Win32 calls, each block minimal with a SAFETY comment).
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod agents;
pub mod detect;
pub mod enforce;
pub mod interactive;
pub mod local_os;
pub mod platform;

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux;
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod macos;
#[cfg(unix)]
#[allow(unsafe_code)]
mod unix;
#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;
#[cfg(windows)]
#[allow(unsafe_code)]
mod windows_interactive;

pub use detect::{detect_backends, BackendInfo};
pub use enforce::{Capabilities, EnforcementMode, EnforcementReport, Level, Support};
pub use interactive::{spawn_interactive, InteractiveChild, InteractiveReport, Net, Profile};
pub use local_os::LocalOsBackend;
pub use platform::{capabilities, kernel_hardening, KernelHardening};

/// Maximum simultaneously live processes per run on Windows (Job Object).
#[cfg(windows)]
pub use windows::ACTIVE_PROCESS_LIMIT;
/// Maximum simultaneously live processes in an interactive run on Windows.
#[cfg(windows)]
pub use windows_interactive::INTERACTIVE_PROCESS_LIMIT;

use provio_core::sandbox::SandboxBackend;

/// Name -> backend for everything available on this machine.
pub struct SandboxRegistry {
    pub backends: Vec<(&'static str, Box<dyn SandboxBackend>)>,
}

impl SandboxRegistry {
    pub fn detect() -> Self {
        let backends: Vec<(&'static str, Box<dyn SandboxBackend>)> =
            vec![("local-os", Box::new(LocalOsBackend::new()))];
        // docker/microsandbox/firecracker/k8s adapters register here as their
        // waves land; detect::detect_backends() reports them honestly.
        SandboxRegistry { backends }
    }

    pub fn get(&mut self, name: &str) -> Option<&mut Box<dyn SandboxBackend>> {
        self.backends
            .iter_mut()
            .find(|(n, _)| *n == name)
            .map(|(_, b)| b)
    }
}
