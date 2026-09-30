//! Backend detection — optional backends are detected if present, never
//! required (spec §12 correction: single static binary, optional adapters).

use std::process::Command;

#[derive(Debug, Clone)]
pub struct BackendInfo {
    pub name: &'static str,
    pub available: bool,
    pub notes: String,
}

fn on_path(exe: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                let plain = dir.join(exe);
                plain.is_file()
                    || plain.with_extension("exe").is_file()
                    || plain.with_extension("bat").is_file()
            })
        })
        .unwrap_or(false)
}

fn docker_reachable() -> bool {
    on_path("docker")
        && Command::new("docker")
            .arg("info")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
}

/// What this machine can actually run. `provio doctor` renders this with the
/// coverage honesty the spec demands (§6): present-but-unenforced paths are
/// stated, never implied.
pub fn detect_backends() -> Vec<BackendInfo> {
    vec![
        {
            let kh = crate::platform::kernel_hardening();
            BackendInfo {
                name: "local-os",
                available: true,
                notes: if kh.enforced {
                    format!(
                        "kernel-enforced workspace write boundary + deny-all egress ({})",
                        kh.mechanism
                    )
                } else {
                    format!(
                        "kernel enforcement INCOMPLETE on this machine ({}); fail-closed \
                         default refuses runs it cannot enforce — see kernel boundary below",
                        kh.mechanism
                    )
                },
            }
        },
        BackendInfo {
            name: "docker",
            available: docker_reachable(),
            notes: if docker_reachable() {
                "daemon reachable; cgroups v2 + namespaces adapter (wave 2)".into()
            } else {
                "docker not found or daemon unreachable".into()
            },
        },
        BackendInfo {
            name: "microsandbox",
            available: false,
            notes: "libkrun microVM adapter — wave 3".into(),
        },
        BackendInfo {
            name: "firecracker/e2b",
            available: false,
            notes: "KVM microVM adapter — wave 3".into(),
        },
        BackendInfo {
            name: "k8s",
            available: false,
            notes: "kubernetes-sigs/agent-sandbox adapter — wave 3".into(),
        },
    ]
}

use provio_core::sandbox::SandboxBackend;

use crate::local_os::LocalOsBackend;

/// Instantiable backends by name. Wave 1: local-os only (honest — docker and
/// microVM adapters land in waves 2–3; `detect_backends` reports their
/// availability separately so `provio doctor` stays truthful).
pub struct SandboxRegistry {
    backends: Vec<(&'static str, Box<dyn SandboxBackend>)>,
}

impl Default for SandboxRegistry {
    fn default() -> Self {
        Self::detect()
    }
}

impl SandboxRegistry {
    pub fn detect() -> Self {
        SandboxRegistry {
            backends: vec![("local-os", Box::new(LocalOsBackend::new()))],
        }
    }

    pub fn get(&mut self, name: &str) -> Option<&mut Box<dyn SandboxBackend>> {
        self.backends
            .iter_mut()
            .find(|(n, _)| *n == name)
            .map(|(_, b)| b)
    }

    pub fn default(&mut self) -> &mut Box<dyn SandboxBackend> {
        self.get("local-os").expect("local-os is always present")
    }
}
