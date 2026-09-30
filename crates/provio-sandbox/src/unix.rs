//! Small Unix process helpers shared by the Linux and macOS paths.

/// SIGKILL every process in process group `pgid`. Callers must only use
/// this while the group leader is still unreaped (alive or zombie), so the
/// pgid cannot have been recycled for an unrelated group.
pub(crate) fn kill_process_group(pgid: u32) {
    let Ok(pgid) = libc::pid_t::try_from(pgid) else {
        return;
    };
    if pgid <= 1 {
        return; // never signal init or "every process" (pgid 0/-1 semantics)
    }
    // SAFETY: killpg with a positive pgid and a valid signal number has no
    // memory-safety preconditions; ESRCH (group already gone) is ignored.
    unsafe {
        libc::killpg(pgid, libc::SIGKILL);
    }
}

// ---- interactive runs: signal handling ------------------------------------

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;

/// Pid of the interactive child that SIGTERM/SIGHUP are forwarded to.
static FORWARD_TO: AtomicI32 = AtomicI32::new(0);

/// Saved dispositions and how many guards are live (tests spawn in
/// parallel; the first guard installs, the last restores).
static GUARDS: Mutex<(usize, Vec<(libc::c_int, libc::sigaction)>)> = Mutex::new((0, Vec::new()));

/// Ignored in provio while the agent runs: the terminal delivers them to the
/// whole foreground process group, so the agent gets them directly (the
/// way `system(3)` behaves). Forwarding them too would deliver twice.
const IGNORED: [libc::c_int; 2] = [libc::SIGINT, libc::SIGQUIT];
/// Forwarded to the agent: sent to provio alone (kill, a closing terminal).
const FORWARDED: [libc::c_int; 2] = [libc::SIGTERM, libc::SIGHUP];

extern "C" fn forward(sig: libc::c_int) {
    let pid = FORWARD_TO.load(Ordering::Relaxed);
    if pid > 0 {
        // SAFETY: kill is async-signal-safe; pid is our own unreaped child.
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

fn set_action(sig: libc::c_int, handler: libc::sighandler_t) -> libc::sigaction {
    // SAFETY: plain-old-data structs, zero-initialized, then filled; the
    // handler is SIG_IGN or an extern "C" fn(c_int) that only calls kill.
    unsafe {
        let mut new: libc::sigaction = std::mem::zeroed();
        new.sa_sigaction = handler;
        new.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut new.sa_mask);
        let mut old: libc::sigaction = std::mem::zeroed();
        libc::sigaction(sig, &new, &mut old);
        old
    }
}

/// While alive, provio ignores SIGINT/SIGQUIT and forwards SIGTERM/SIGHUP to
/// the interactive child (see [`SignalGuard::forward_to`]).
pub(crate) struct SignalGuard;

impl SignalGuard {
    pub(crate) fn install() -> Self {
        let mut g = GUARDS.lock().unwrap_or_else(|e| e.into_inner());
        if g.0 == 0 {
            let mut saved = Vec::new();
            for sig in IGNORED {
                saved.push((sig, set_action(sig, libc::SIG_IGN)));
            }
            for sig in FORWARDED {
                let h = forward as extern "C" fn(libc::c_int) as libc::sighandler_t;
                saved.push((sig, set_action(sig, h)));
            }
            g.1 = saved;
        }
        g.0 += 1;
        SignalGuard
    }

    pub(crate) fn forward_to(&self, pid: u32) {
        FORWARD_TO.store(i32::try_from(pid).unwrap_or(0), Ordering::Relaxed);
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        let mut g = GUARDS.lock().unwrap_or_else(|e| e.into_inner());
        g.0 = g.0.saturating_sub(1);
        if g.0 == 0 {
            FORWARD_TO.store(0, Ordering::Relaxed);
            for (sig, old) in g.1.drain(..) {
                // SAFETY: restoring a disposition previously returned by
                // sigaction.
                unsafe {
                    libc::sigaction(sig, &old, std::ptr::null_mut());
                }
            }
        }
    }
}

/// Reset SIGINT/SIGQUIT to their defaults in the child before exec (it
/// would otherwise inherit provio's SIG_IGN across exec).
pub(crate) fn reset_signals_in_child(cmd: &mut std::process::Command) {
    // SAFETY: the closure runs between fork and exec and only calls
    // signal(2), which is async-signal-safe.
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(cmd, || {
            for sig in IGNORED {
                libc::signal(sig, libc::SIG_DFL);
            }
            Ok(())
        });
    }
}
