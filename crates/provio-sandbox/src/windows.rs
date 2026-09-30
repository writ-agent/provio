//! Windows kernel enforcement for `local-os` (spec §6B): AppContainer
//! token + Job Object.
//!
//! The child is created by `CreateProcessW` with
//! `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`, which gives it an
//! AppContainer token: Low integrity, a per-workspace AppContainer SID, and
//! (in deny-all mode) **no capabilities**. It is created suspended, put in a
//! Job Object, then resumed.
//!
//! What is enforced:
//! - **Filesystem writes.** An AppContainer process can only open objects
//!   whose DACL grants its AppContainer SID (or ALL APPLICATION PACKAGES),
//!   and its Low integrity level blocks write-up on everything else.
//!   `prepare` registers the container profile and adds one inheritable
//!   full-access ACE for the SID to the workspace; nothing else is granted.
//!   The only other location the container can write is its own profile
//!   folder (`%LOCALAPPDATA%\Packages\<name>\AC`), which Windows creates
//!   for it and which also holds the child's OS-forced TEMP/TMP; it is
//!   deleted with the profile on teardown. Consequence (stricter than the spec asks): *reads* are also
//!   limited to the workspace, the temp dir, and locations readable by ALL
//!   APPLICATION PACKAGES (System32, Program Files, ...). Programs installed
//!   under the user profile (e.g. %LOCALAPPDATA%) will not start.
//! - **Network.** Without the internetClient / privateNetworkClientServer
//!   capabilities, Windows' built-in AppContainer WFP filters block
//!   outbound connections, including loopback, with no admin rights.
//!   That isolation is implemented by the Windows Firewall service; when
//!   `mpssvc`/`BFE` are not running, `capabilities()` reports network deny
//!   as unavailable.
//! - **Job Object.** Kill-on-close (every descendant dies with the run),
//!   no breakaway (neither BREAKAWAY_OK nor SILENT_BREAKAWAY_OK is set),
//!   an active-process limit ([`ACTIVE_PROCESS_LIMIT`]), die-on-unhandled-
//!   exception, and all UI restrictions (desktop, clipboard, global atoms,
//!   foreign USER handles, system parameters, display settings, exit
//!   Windows).
//!
//! Residuals (stated in `provio doctor`): objects whose DACL grants ALL
//! APPLICATION PACKAGES write access remain writable; the profile folder is
//! shared by concurrent sandboxes on the same workspace (and removed when
//! this backend's last sandbox on it is torn down); the per-workspace
//! ACE stays on the workspace after teardown (remove with
//! `icacls <ws> /remove <SID>`); granting it walks and rewrites the ACLs of
//! every existing entry in the workspace once (fast afterwards: an
//! existing ACE is detected and the walk skipped).

use std::collections::BTreeMap;
use std::ffi::{c_void, OsStr};
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    LocalFree, SetHandleInformation, ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE, HANDLE,
    HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW, GetNamedSecurityInfoW, SetEntriesInAclW,
    SetNamedSecurityInfoW, EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT,
    TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
    DeriveAppContainerSidFromAppContainerName, GetAppContainerFolderPath,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, EqualSid, FreeSid, GetAce, GetAclInformation, ACCESS_ALLOWED_ACE, ACL,
    ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE,
    OBJECT_INHERIT_ACE, PSID, SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ALL_ACCESS, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicUIRestrictions,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP,
    JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, ResumeThread, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    STARTF_USESTDHANDLES, STARTUPINFOEXW,
};

use provio_core::error::{ProvioError, Result};

use crate::enforce::{Capabilities, Support};

/// Maximum simultaneously live processes in one run's job (the child and
/// all its descendants, console hosts included).
pub const ACTIVE_PROCESS_LIMIT: u32 = 64;

/// `SE_GROUP_ENABLED` (winnt.h).
const SE_GROUP_ENABLED: u32 = 0x4;
/// `ACCESS_ALLOWED_ACE_TYPE` (winnt.h).
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
/// internetClient, privateNetworkClientServer: only granted in explicit
/// best-effort mode with a non-empty allow-list (network then OPEN).
const NETWORK_CAPABILITY_SIDS: &[&str] = &["S-1-15-3-1", "S-1-15-3-3"];

pub(crate) fn sb_err(ctx: &str) -> ProvioError {
    ProvioError::Sandbox(format!(
        "{ctx}: {} (fail closed)",
        io::Error::last_os_error()
    ))
}

pub(crate) fn code_err(ctx: &str, code: u32) -> ProvioError {
    ProvioError::Sandbox(format!(
        "{ctx}: {} (fail closed)",
        io::Error::from_raw_os_error(code as i32)
    ))
}

pub(crate) fn wide(s: &OsStr) -> Result<Vec<u16>> {
    let mut v: Vec<u16> = s.encode_wide().collect();
    if v.contains(&0) {
        return Err(ProvioError::Sandbox(format!(
            "{} contains a NUL character (fail closed)",
            s.to_string_lossy()
        )));
    }
    v.push(0);
    Ok(v)
}

/// A SID allocated by the OS, freed with the matching deallocator.
pub(crate) struct Sid {
    pub(crate) ptr: PSID,
    local: bool,
}

impl Drop for Sid {
    fn drop(&mut self) {
        // SAFETY: ptr came from DeriveAppContainerSidFromAppContainerName
        // (freed with FreeSid) or ConvertStringSidToSidW (LocalFree), each
        // exactly once.
        unsafe {
            if self.local {
                LocalFree(self.ptr);
            } else {
                FreeSid(self.ptr);
            }
        }
    }
}

impl Sid {
    fn to_string_sid(&self) -> String {
        let mut s: *mut u16 = null_mut();
        // SAFETY: self.ptr is a valid SID; on success s is a LocalAlloc'd
        // NUL-terminated string that we free below.
        if unsafe { ConvertSidToStringSidW(self.ptr, &mut s) } == 0 || s.is_null() {
            return "<unprintable SID>".into();
        }
        // SAFETY: s is NUL-terminated (API contract).
        let len = (0..).take_while(|&i| unsafe { *s.add(i) } != 0).count();
        // SAFETY: s points at len valid u16s.
        let out = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(s, len) });
        // SAFETY: s was allocated by ConvertSidToStringSidW.
        unsafe { LocalFree(s as *mut c_void) };
        out
    }
}

fn derive_sid(name: &str) -> Result<Sid> {
    let w = wide(OsStr::new(name))?;
    let mut sid: PSID = null_mut();
    // SAFETY: w is NUL-terminated; sid is a valid out-pointer.
    let hr = unsafe { DeriveAppContainerSidFromAppContainerName(w.as_ptr(), &mut sid) };
    if hr < 0 || sid.is_null() {
        return Err(ProvioError::Sandbox(format!(
            "DeriveAppContainerSidFromAppContainerName failed: HRESULT {hr:#010x} (fail closed)"
        )));
    }
    Ok(Sid {
        ptr: sid,
        local: false,
    })
}

pub(crate) fn string_sid(s: &str) -> Result<Sid> {
    let w = wide(OsStr::new(s))?;
    let mut sid: PSID = null_mut();
    // SAFETY: w is NUL-terminated; sid is a valid out-pointer.
    if unsafe { ConvertStringSidToSidW(w.as_ptr(), &mut sid) } == 0 {
        return Err(sb_err("ConvertStringSidToSidW"));
    }
    Ok(Sid {
        ptr: sid,
        local: true,
    })
}

/// Stable AppContainer name for a canonical workspace path, so the one-time
/// ACL grant is reused by every sandbox on the same workspace.
pub(crate) fn container_name(workspace: &Path) -> String {
    // FNV-1a 64 over the case-folded path (NTFS paths are case-insensitive).
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in workspace.to_string_lossy().to_lowercase().bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("provio.ws.{h:016x}")
}

fn service_running(name: &str) -> bool {
    let Ok(w) = wide(OsStr::new(name)) else {
        return false;
    };
    // SAFETY: null machine/database = local SCM; the handles are closed
    // below; status is a valid out-pointer.
    unsafe {
        let scm = OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return false;
        }
        let svc = OpenServiceW(scm, w.as_ptr(), SERVICE_QUERY_STATUS);
        let mut running = false;
        if !svc.is_null() {
            let mut status: SERVICE_STATUS = std::mem::zeroed();
            running = QueryServiceStatus(svc, &mut status) != 0
                && status.dwCurrentState == SERVICE_RUNNING;
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
        running
    }
}

pub(crate) fn capabilities() -> Capabilities {
    let filesystem = match derive_sid("provio.probe") {
        Ok(_) => Support::Full,
        Err(e) => Support::Unavailable(format!("AppContainer tokens are unavailable: {e}")),
    };
    let network_deny = if !filesystem.is_full() {
        Support::Unavailable("AppContainer tokens are unavailable".into())
    } else if !(service_running("BFE") && service_running("mpssvc")) {
        Support::Unavailable(
            "the Base Filtering Engine (BFE) or Windows Defender Firewall (mpssvc) service \
             is not running; AppContainer network isolation is enforced through them"
                .into(),
        )
    } else {
        Support::Full
    };
    Capabilities {
        filesystem,
        network_deny,
        mechanism: format!(
            "AppContainer token (Low IL, no capabilities) + Job Object (kill-on-close, \
             no breakaway, active-process limit {ACTIVE_PROCESS_LIMIT})"
        ),
    }
}

/// Whether `acl` already holds an inheritable allow ACE granting `sid`
/// full file access.
fn acl_grants(acl: *const ACL, sid: PSID) -> bool {
    if acl.is_null() {
        return false;
    }
    // SAFETY: acl is a valid ACL from GetNamedSecurityInfoW; info is a
    // correctly sized out-struct; each ACE pointer from GetAce is valid for
    // the lifetime of the ACL and is read as the header-compatible
    // ACCESS_ALLOWED_ACE only after checking its type.
    unsafe {
        let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
        if GetAclInformation(
            acl,
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        ) == 0
        {
            return false;
        }
        let inherit = (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8;
        for i in 0..info.AceCount {
            let mut ace: *mut c_void = null_mut();
            if GetAce(acl, i, &mut ace) == 0 || ace.is_null() {
                continue;
            }
            let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
            if allowed.Header.AceType == ACCESS_ALLOWED_ACE_TYPE
                && allowed.Header.AceFlags & inherit == inherit
                && allowed.Header.AceFlags & INHERIT_ONLY_ACE as u8 == 0
                && allowed.Mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS
                && EqualSid(&allowed.SidStart as *const u32 as PSID, sid) != 0
            {
                return true;
            }
        }
        false
    }
}

/// Add an inheritable full-access ACE for `sid` to `path` (propagated to
/// existing children by SetNamedSecurityInfoW). No-op when already present.
fn grant_full_access(path: &Path, sid: &Sid) -> Result<()> {
    let wpath = wide(path.as_os_str())?;
    let mut dacl: *mut ACL = null_mut();
    let mut sd: *mut c_void = null_mut();
    // SAFETY: wpath is NUL-terminated; out-pointers are valid; sd is freed
    // with LocalFree below (dacl points into sd).
    let rc = unsafe {
        GetNamedSecurityInfoW(
            wpath.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(code_err(
            &format!("reading the DACL of {}", path.display()),
            rc,
        ));
    }
    let result = (|| {
        if acl_grants(dacl, sid.ptr) {
            return Ok(());
        }
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_ALL_ACCESS,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: sid.ptr as *mut u16,
            },
        };
        let mut new_acl: *mut ACL = null_mut();
        // SAFETY: ea is fully initialized with a valid SID; dacl is the
        // current DACL (or null); new_acl is freed with LocalFree.
        let rc = unsafe { SetEntriesInAclW(1, &ea, dacl, &mut new_acl) };
        if rc != ERROR_SUCCESS {
            return Err(code_err("SetEntriesInAclW", rc));
        }
        // SAFETY: wpath is NUL-terminated and new_acl a valid ACL.
        let rc = unsafe {
            SetNamedSecurityInfoW(
                wpath.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                new_acl,
                null(),
            )
        };
        // SAFETY: new_acl was allocated by SetEntriesInAclW.
        unsafe { LocalFree(new_acl as *mut c_void) };
        if rc != ERROR_SUCCESS {
            return Err(code_err(
                &format!("granting the sandbox access to {}", path.display()),
                rc,
            ));
        }
        Ok(())
    })();
    // SAFETY: sd was allocated by GetNamedSecurityInfoW.
    unsafe { LocalFree(sd) };
    result
}

/// `HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)`.
const HR_ALREADY_EXISTS: i32 = 0x8007_00B7_u32 as i32;

/// Register the AppContainer profile `name` (CreateProcessW refuses an
/// AppContainer SID without one: ERROR_FILE_NOT_FOUND). Idempotent.
fn ensure_profile(name: &str) -> Result<()> {
    let w = wide(OsStr::new(name))?;
    let desc = wide(OsStr::new("provio local-os sandbox (per-workspace)"))?;
    let mut sid: PSID = null_mut();
    // SAFETY: NUL-terminated strings, no capabilities, valid out-pointer;
    // the returned SID is freed with FreeSid.
    let hr = unsafe {
        CreateAppContainerProfile(w.as_ptr(), w.as_ptr(), desc.as_ptr(), null(), 0, &mut sid)
    };
    if hr >= 0 {
        drop(Sid {
            ptr: sid,
            local: false,
        });
        return Ok(());
    }
    if hr == HR_ALREADY_EXISTS {
        return Ok(());
    }
    Err(ProvioError::Sandbox(format!(
        "CreateAppContainerProfile({name}) failed: HRESULT {hr:#010x} (fail closed)"
    )))
}

/// Remove the AppContainer profile `name` (best effort). The workspace ACE
/// stays valid: the SID is derived from the name, not stored in the profile.
pub(crate) fn delete_profile(name: &str) {
    if let Ok(w) = wide(OsStr::new(name)) {
        // SAFETY: NUL-terminated string.
        unsafe { DeleteAppContainerProfile(w.as_ptr()) };
    }
}

/// The AppContainer's own profile folder (`%LOCALAPPDATA%\Packages\<name>\AC`).
fn container_folder(sid_string: &str) -> Result<PathBuf> {
    let w = wide(OsStr::new(sid_string))?;
    let mut out: *mut u16 = null_mut();
    // SAFETY: w is NUL-terminated; out receives a CoTaskMemAlloc'd string
    // that is freed below.
    let hr = unsafe { GetAppContainerFolderPath(w.as_ptr(), &mut out) };
    if hr < 0 || out.is_null() {
        return Err(ProvioError::Sandbox(format!(
            "GetAppContainerFolderPath failed: HRESULT {hr:#010x} (fail closed)"
        )));
    }
    // SAFETY: out is NUL-terminated (API contract).
    let len = (0..).take_while(|&i| unsafe { *out.add(i) } != 0).count();
    // SAFETY: out points at len valid u16s.
    let path = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(out, len) });
    // SAFETY: out was allocated by GetAppContainerFolderPath.
    unsafe { CoTaskMemFree(out as *const c_void) };
    Ok(PathBuf::from(path))
}

/// Register the workspace's AppContainer profile and grant its SID full
/// access to the workspace. Returns the SID string (for the enforcement
/// report) and the container's temp dir: CreateProcessW points an
/// AppContainer child's TEMP/TMP there, inside the container's own profile
/// folder, which only that container (and the user) can write.
pub(crate) fn prepare_container(container: &str, workspace: &Path) -> Result<(String, PathBuf)> {
    ensure_profile(container)?;
    let sid = derive_sid(container)?;
    grant_full_access(workspace, &sid)?;
    let sid_string = sid.to_string_sid();
    let temp = container_folder(&sid_string)?.join("Temp");
    std::fs::create_dir_all(&temp)?;
    Ok((sid_string, temp))
}

pub(crate) fn owned(h: HANDLE) -> OwnedHandle {
    // SAFETY: callers pass a freshly created, valid handle they own.
    unsafe { OwnedHandle::from_raw_handle(h) }
}

/// Create the run's Job Object with every limit applied.
pub(crate) fn create_job() -> Result<OwnedHandle> {
    // SAFETY: null attributes/name create an unnamed job.
    let h = unsafe { CreateJobObjectW(null(), null()) };
    if h.is_null() {
        return Err(sb_err("CreateJobObjectW"));
    }
    let job = owned(h);
    // SAFETY: plain-old-data struct; zero is a valid initial state.
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    limits.BasicLimitInformation.ActiveProcessLimit = ACTIVE_PROCESS_LIMIT;
    // SAFETY: job is valid; the buffer and its size match the info class.
    if unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            &limits as *const _ as *const c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err(sb_err("setting Job Object limits"));
    }
    let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: JOB_OBJECT_UILIMIT_DESKTOP
            | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
            | JOB_OBJECT_UILIMIT_EXITWINDOWS
            | JOB_OBJECT_UILIMIT_GLOBALATOMS
            | JOB_OBJECT_UILIMIT_HANDLES
            | JOB_OBJECT_UILIMIT_READCLIPBOARD
            | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
            | JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    };
    // SAFETY: as above.
    if unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectBasicUIRestrictions,
            &ui as *const _ as *const c_void,
            std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
        )
    } == 0
    {
        return Err(sb_err("setting Job Object UI restrictions"));
    }
    Ok(job)
}

/// Resolve `program` the way a shell would, but only against the child's
/// PATH (never the parent's cwd): `.exe`/`.com` are tried when no extension
/// is given. Batch files are refused (their argument quoting is unsafe).
fn resolve_program(program: &str, cwd: &Path, path_var: Option<&str>) -> Result<PathBuf> {
    let p = Path::new(program);
    let candidates = |base: PathBuf| -> Vec<PathBuf> {
        if base.extension().is_some() {
            vec![
                base.clone(),
                PathBuf::from(format!("{}.exe", base.display())),
            ]
        } else {
            vec![base.with_extension("exe"), base.with_extension("com")]
        }
    };
    let found = if p.is_absolute() || program.contains(['\\', '/']) {
        let base = if p.is_absolute() {
            p.to_path_buf()
        } else {
            cwd.join(p)
        };
        candidates(base).into_iter().find(|c| c.is_file())
    } else {
        path_var.and_then(|pv| {
            std::env::split_paths(pv)
                .flat_map(|dir| candidates(dir.join(p)))
                .find(|c| c.is_file())
        })
    };
    let exe = found.ok_or_else(|| {
        ProvioError::Sandbox(format!("program {program} not found on the sandbox PATH"))
    })?;
    let ext = exe
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase());
    if matches!(ext.as_deref(), Some("bat") | Some("cmd")) {
        return Err(ProvioError::Sandbox(format!(
            "{} is a batch file; run it explicitly via `cmd /c` (fail closed)",
            exe.display()
        )));
    }
    Ok(exe)
}

/// MSVCRT argument quoting (the rules `CommandLineToArgvW` inverts).
fn append_arg(cmd: &mut Vec<u16>, arg: &OsStr, force_quotes: bool) {
    let quote = force_quotes
        || arg.is_empty()
        || arg
            .encode_wide()
            .any(|c| c == u16::from(b' ') || c == u16::from(b'\t'));
    if quote {
        cmd.push(u16::from(b'"'));
    }
    let mut backslashes = 0usize;
    for c in arg.encode_wide() {
        if c == u16::from(b'\\') {
            backslashes += 1;
        } else {
            if c == u16::from(b'"') {
                cmd.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes + 1));
            }
            backslashes = 0;
        }
        cmd.push(c);
    }
    if quote {
        cmd.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
        cmd.push(u16::from(b'"'));
    }
}

pub(crate) fn command_line(exe: &Path, args: &[String]) -> Result<Vec<u16>> {
    if exe.as_os_str().encode_wide().any(|c| c == u16::from(b'"')) {
        return Err(ProvioError::Sandbox(
            "program path contains '\"' (fail closed)".into(),
        ));
    }
    let mut cmd = Vec::new();
    append_arg(&mut cmd, exe.as_os_str(), true);
    for a in args {
        cmd.push(u16::from(b' '));
        append_arg(&mut cmd, OsStr::new(a), false);
    }
    if cmd.contains(&0) {
        return Err(ProvioError::Sandbox(
            "argument contains NUL (fail closed)".into(),
        ));
    }
    cmd.push(0);
    Ok(cmd)
}

/// Case-insensitive environment merge (later entries win), as a sorted
/// Unicode environment block.
pub(crate) fn env_block(vars: &[(String, String)]) -> Result<(Vec<u16>, Option<String>)> {
    let mut merged: BTreeMap<String, (String, String)> = BTreeMap::new();
    for (k, v) in vars {
        if k.is_empty() || k.contains('=') || k.contains('\0') || v.contains('\0') {
            return Err(ProvioError::Sandbox(format!(
                "invalid environment variable {k:?} (fail closed)"
            )));
        }
        merged.insert(k.to_uppercase(), (k.clone(), v.clone()));
    }
    let path = merged.get("PATH").map(|(_, v)| v.clone());
    let mut block = Vec::new();
    for (k, v) in merged.values() {
        block.extend(OsStr::new(&format!("{k}={v}")).encode_wide());
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok((block, path))
}

fn inheritable_pipe() -> Result<(OwnedHandle, OwnedHandle)> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let (mut r, mut w): (HANDLE, HANDLE) = (null_mut(), null_mut());
    // SAFETY: out-pointers are valid; sa is initialized.
    if unsafe { CreatePipe(&mut r, &mut w, &sa, 0) } == 0 {
        return Err(sb_err("CreatePipe"));
    }
    let (r, w) = (owned(r), owned(w));
    // The parent's read end must not leak into the child.
    // SAFETY: r is a valid handle we own.
    if unsafe { SetHandleInformation(r.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(sb_err("SetHandleInformation"));
    }
    Ok((r, w))
}

fn inheritable_nul() -> Result<OwnedHandle> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let name = wide(OsStr::new("NUL"))?;
    // SAFETY: name is NUL-terminated; sa is initialized.
    let h = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &sa,
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(sb_err("opening NUL for stdin"));
    }
    Ok(owned(h))
}

/// A proc-thread attribute list backed by an 8-byte-aligned buffer.
pub(crate) struct AttrList {
    buf: Vec<u64>,
}

impl AttrList {
    pub(crate) fn new(count: u32) -> Result<Self> {
        let mut size = 0usize;
        // SAFETY: size query: a null list with a valid size out-pointer
        // (returns FALSE with ERROR_INSUFFICIENT_BUFFER by contract).
        unsafe { InitializeProcThreadAttributeList(null_mut(), count, 0, &mut size) };
        if size == 0 {
            return Err(sb_err("InitializeProcThreadAttributeList (size)"));
        }
        let mut list = AttrList {
            buf: vec![0u64; size.div_ceil(8)],
        };
        // SAFETY: buf holds at least `size` bytes, suitably aligned.
        if unsafe { InitializeProcThreadAttributeList(list.ptr(), count, 0, &mut size) } == 0 {
            list.buf.clear(); // not initialized: Drop must not delete it
            return Err(sb_err("InitializeProcThreadAttributeList"));
        }
        Ok(list)
    }

    pub(crate) fn ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST
    }

    /// # Safety
    /// `value` must point at `size` bytes that stay valid and unmoved until
    /// the list is dropped (the list stores the pointer, not a copy).
    pub(crate) unsafe fn set(
        &mut self,
        attribute: usize,
        value: *const c_void,
        size: usize,
    ) -> Result<()> {
        // SAFETY: list is initialized; the caller guarantees value/size.
        if unsafe {
            UpdateProcThreadAttribute(self.ptr(), 0, attribute, value, size, null_mut(), null())
        } == 0
        {
            return Err(sb_err("UpdateProcThreadAttribute"));
        }
        Ok(())
    }
}

impl Drop for AttrList {
    fn drop(&mut self) {
        if !self.buf.is_empty() {
            // SAFETY: the list was initialized by InitializeProcThreadAttributeList.
            unsafe { DeleteProcThreadAttributeList(self.ptr()) };
        }
    }
}

/// A running sandboxed child: its process handle and its job.
pub(crate) struct Child {
    process: OwnedHandle,
    job: OwnedHandle,
}

impl Child {
    /// Wait up to `ms` for exit. `Ok(None)` on timeout.
    pub(crate) fn wait_timeout(&self, ms: u64) -> Result<Option<i32>> {
        let ms = u32::try_from(ms).unwrap_or(u32::MAX - 1).min(u32::MAX - 1);
        // SAFETY: process is a valid process handle.
        match unsafe { WaitForSingleObject(self.process.as_raw_handle(), ms) } {
            WAIT_OBJECT_0 => {
                let mut code = 0u32;
                // SAFETY: valid handle and out-pointer.
                if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) } == 0 {
                    return Err(sb_err("GetExitCodeProcess"));
                }
                Ok(Some(code as i32))
            }
            WAIT_TIMEOUT => Ok(None),
            _ => Err(sb_err("WaitForSingleObject")),
        }
    }

    /// Kill the child and every descendant (the whole job).
    pub(crate) fn kill_tree(&self) {
        // SAFETY: job is a valid job handle.
        unsafe { TerminateJobObject(self.job.as_raw_handle(), 1) };
    }

    /// End the run: kill any descendant still alive (so the output pipes
    /// reach EOF) and release the job.
    pub(crate) fn finish(self) {
        self.kill_tree();
    }
}

/// Everything `spawn` needs about the confinement.
pub(crate) struct Confinement<'a> {
    /// AppContainer name (see [`container_name`]); `None` runs with the
    /// caller's token (best-effort mode without AppContainer support).
    pub(crate) container: Option<&'a str>,
    /// Grant internetClient + privateNetworkClientServer (network OPEN).
    pub(crate) allow_network: bool,
}

/// Spawn `program args` confined by `conf`, inside a fresh Job Object.
/// Returns the child and the parent ends of its stdout and stderr pipes.
pub(crate) fn spawn(
    conf: &Confinement<'_>,
    program: &str,
    args: &[String],
    cwd: &Path,
    env: &[(String, String)],
) -> Result<(Child, File, File)> {
    let (env_block, path_var) = env_block(env)?;
    let exe = resolve_program(program, cwd, path_var.as_deref())?;
    let wexe = wide(exe.as_os_str())?;
    let mut cmdline = command_line(&exe, args)?;
    let wcwd = wide(cwd.as_os_str())?;

    let (out_r, out_w) = inheritable_pipe()?;
    let (err_r, err_w) = inheritable_pipe()?;
    let nul = inheritable_nul()?;
    let job = create_job()?;

    // Keep SIDs and the capability array alive until CreateProcessW returns.
    let container_sid = conf.container.map(derive_sid).transpose()?;
    let cap_sids: Vec<Sid> = if conf.allow_network {
        NETWORK_CAPABILITY_SIDS
            .iter()
            .map(|s| string_sid(s))
            .collect::<Result<_>>()?
    } else {
        Vec::new()
    };
    let mut caps: Vec<SID_AND_ATTRIBUTES> = cap_sids
        .iter()
        .map(|s| SID_AND_ATTRIBUTES {
            Sid: s.ptr,
            Attributes: SE_GROUP_ENABLED,
        })
        .collect();
    let sec_caps = container_sid.as_ref().map(|sid| SECURITY_CAPABILITIES {
        AppContainerSid: sid.ptr,
        Capabilities: if caps.is_empty() {
            null_mut()
        } else {
            caps.as_mut_ptr()
        },
        CapabilityCount: caps.len() as u32,
        Reserved: 0,
    });
    // Only these three handles are inherited, whatever else the parent has
    // marked inheritable (concurrent spawns must not leak pipe ends).
    let inherit: [HANDLE; 3] = [
        nul.as_raw_handle(),
        out_w.as_raw_handle(),
        err_w.as_raw_handle(),
    ];

    let mut attrs = AttrList::new(if sec_caps.is_some() { 2 } else { 1 })?;
    // SAFETY: `inherit` and `sec_caps` live on this stack frame until after
    // CreateProcessW; the list is dropped at the end of this function.
    unsafe {
        attrs.set(
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            inherit.as_ptr() as *const c_void,
            std::mem::size_of_val(&inherit),
        )?;
        if let Some(sc) = sec_caps.as_ref() {
            attrs.set(
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                sc as *const SECURITY_CAPABILITIES as *const c_void,
                std::mem::size_of::<SECURITY_CAPABILITIES>(),
            )?;
        }
    }

    // SAFETY: plain-old-data struct; zero is a valid initial state.
    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = nul.as_raw_handle();
    si.StartupInfo.hStdOutput = out_w.as_raw_handle();
    si.StartupInfo.hStdError = err_w.as_raw_handle();
    si.lpAttributeList = attrs.ptr();

    // SAFETY: plain-old-data out-struct.
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: every pointer is valid for the call: NUL-terminated wexe and
    // wcwd, mutable NUL-terminated cmdline, a double-NUL-terminated Unicode
    // env block, an initialized STARTUPINFOEXW whose attribute list refers
    // to live data, and a valid PROCESS_INFORMATION out-pointer.
    let ok = unsafe {
        CreateProcessW(
            wexe.as_ptr(),
            cmdline.as_mut_ptr(),
            null(),
            null(),
            1,
            CREATE_SUSPENDED
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT
                | CREATE_NO_WINDOW,
            env_block.as_ptr() as *const c_void,
            wcwd.as_ptr(),
            &si.StartupInfo,
            &mut pi,
        )
    };
    if ok == 0 {
        let e = io::Error::last_os_error();
        let hint = if e.raw_os_error() == Some(5) && conf.container.is_some() {
            " — the AppContainer can only execute programs readable by ALL APPLICATION \
             PACKAGES (System32, Program Files, ...) or located in the workspace"
        } else {
            ""
        };
        return Err(ProvioError::Sandbox(format!(
            "spawn {} failed: {e}{hint}",
            exe.display()
        )));
    }
    let process = owned(pi.hProcess);
    let thread = owned(pi.hThread);

    // SAFETY: job and process are valid handles.
    if unsafe { AssignProcessToJobObject(job.as_raw_handle(), process.as_raw_handle()) } == 0 {
        let e = sb_err("AssignProcessToJobObject");
        // SAFETY: the suspended process never ran; kill it.
        unsafe { TerminateProcess(process.as_raw_handle(), 1) };
        return Err(e);
    }
    // SAFETY: thread is the child's suspended main thread.
    if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
        let e = sb_err("ResumeThread");
        // SAFETY: job is valid; kills the suspended child.
        unsafe { TerminateJobObject(job.as_raw_handle(), 1) };
        return Err(e);
    }
    drop(thread);
    // Parent copies of the child's ends: closing them lets readers see EOF.
    drop((out_w, err_w, nul));

    Ok((Child { process, job }, File::from(out_r), File::from(err_r)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::JobObjects::{
        QueryInformationJobObject, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
        JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
    };

    #[test]
    fn job_has_kill_on_close_no_breakaway_and_process_limit() {
        let job = create_job().unwrap();
        // SAFETY: plain-old-data out-struct.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: valid job handle; buffer matches the info class.
        let ok = unsafe {
            QueryInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                &mut info as *mut _ as *mut c_void,
                std::mem::size_of_val(&info) as u32,
                null_mut(),
            )
        };
        assert_ne!(ok, 0);
        let flags = info.BasicLimitInformation.LimitFlags;
        assert_ne!(flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, 0);
        assert_ne!(flags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS, 0);
        assert_eq!(
            flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK),
            0
        );
        assert_eq!(
            info.BasicLimitInformation.ActiveProcessLimit,
            ACTIVE_PROCESS_LIMIT
        );
    }

    #[test]
    fn quoting_matches_msvcrt_rules() {
        let cl = command_line(
            Path::new(r"C:\Windows\System32\cmd.exe"),
            &[
                "/c".into(),
                "echo hi".into(),
                r#"a"b"#.into(),
                r"x\".into(),
                String::new(),
            ],
        )
        .unwrap();
        let s = String::from_utf16(&cl[..cl.len() - 1]).unwrap();
        assert_eq!(
            s,
            r#""C:\Windows\System32\cmd.exe" /c "echo hi" a\"b x\ """#
        );
    }

    #[test]
    fn env_merge_is_case_insensitive_last_wins() {
        let (block, path) = env_block(&[
            ("Path".into(), "a".into()),
            ("PATH".into(), "b".into()),
            ("X".into(), "1".into()),
        ])
        .unwrap();
        assert_eq!(path.as_deref(), Some("b"));
        let s = String::from_utf16(&block).unwrap();
        assert_eq!(s, "PATH=b\0X=1\0\0");
    }

    #[test]
    fn container_name_is_stable_and_case_insensitive() {
        let a = container_name(Path::new(r"C:\Work\Repo"));
        assert_eq!(a, container_name(Path::new(r"c:\work\repo")));
        assert_ne!(a, container_name(Path::new(r"C:\Work\Other")));
        assert!(a.len() <= 64);
    }
}
