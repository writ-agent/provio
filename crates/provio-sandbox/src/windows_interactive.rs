//! Windows kernel boundary for *interactive* runs (`provio run -- <agent>`):
//! a restricted Low integrity token, mandatory labels on the writable set,
//! and a Job Object.
//!
//! Why not the AppContainer used by the batch backend (`windows.rs`)? An
//! AppContainer also restricts *reads* to what ALL APPLICATION PACKAGES can
//! read, so node, git and every agent installed under the user profile
//! (`%APPDATA%\npm\...`) cannot even start, and it needs capability SIDs for
//! any network access. Interactive agents must read toolchains anywhere and
//! reach their model API.
//!
//! Mechanism:
//! - **Token.** `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` of provio's
//!   own token (every privilege but SeChangeNotify removed; BUILTIN\
//!   Administrators made deny-only, as in UAC's filtered token, so an
//!   elevated provio does not hand its admin group to the agent), then its
//!   integrity level is lowered to Low (S-1-16-4096). Windows' mandatory
//!   integrity policy (NO_WRITE_UP, on every securable object by default)
//!   then denies write access to any object whose label is above Low — and
//!   an object without an explicit label counts as Medium. Reads and
//!   execute are unaffected (no NO_READ_UP by default).
//! - **Writable set.** Each path the run may write (workspace, private
//!   temp, agent-profile dirs, `--allow-write`) gets an explicit Low
//!   mandatory label, inheritable for directories (propagated to existing
//!   children by `SetNamedSecurityInfoW`). The label PERSISTS after the run:
//!   any Low integrity process of this user can then write those paths.
//!   Labelling is idempotent (an existing Low label skips the tree walk).
//! - **Job Object.** Kill-on-close (the agent's whole process tree dies
//!   with the run), no breakaway, die-on-unhandled-exception, a generous
//!   active-process limit, and desktop / display-settings / exit-Windows /
//!   system-parameters / global-atom UI restrictions. Clipboard and USER
//!   handles are left open (agents paste images); UIPI already stops a Low
//!   process from sending messages to higher-integrity windows.
//! - **Console.** The child inherits provio's standard handles (console or
//!   pipes) and shares its console; provio swallows Ctrl-C / Ctrl-Break while
//!   the agent runs so the agent alone decides what they mean.
//!
//! Not enforced: network (a Low token does not restrict sockets; WFP
//! filters need administrator rights), so `--net none` is refused in
//! Required mode. Residuals are listed in `docs/THREAT_MODEL.md`.

use std::ffi::{c_void, OsStr};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    DuplicateHandle, LocalFree, DUPLICATE_SAME_ACCESS, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, AddMandatoryAce, CreateRestrictedToken, EqualSid, GetAce,
    GetAclInformation, GetLengthSid, InitializeAcl, SetTokenInformation, TokenIntegrityLevel,
    ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE,
    DISABLE_MAX_PRIVILEGE, INHERIT_ONLY_ACE, LABEL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
    SID_AND_ATTRIBUTES, SYSTEM_MANDATORY_LABEL_ACE, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetVolumeInformationByHandleW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_C_EVENT, STD_ERROR_HANDLE,
    STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicUIRestrictions,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP,
    JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, CreateProcessW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken,
    ResumeThread, TerminateProcess, WaitForSingleObject, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, INFINITE, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW,
};

use provio_core::error::{ProvioError, Result};

use crate::enforce::{Capabilities, Support};
use crate::windows::{
    code_err, command_line, env_block, owned, sb_err, string_sid, wide, AttrList, Sid,
};

/// Maximum simultaneously live processes in an interactive run's job.
/// Agents run test suites and build tools with many workers, so this is a
/// fork-bomb backstop, not a tight limit.
pub const INTERACTIVE_PROCESS_LIMIT: u32 = 1024;

/// Low mandatory level (winnt.h `SECURITY_MANDATORY_LOW_RID`).
const LOW_IL_SID: &str = "S-1-16-4096";
/// `SE_GROUP_INTEGRITY` (winnt.h).
const SE_GROUP_INTEGRITY: u32 = 0x20;
/// `SYSTEM_MANDATORY_LABEL_ACE_TYPE` (winnt.h).
const MANDATORY_LABEL_ACE_TYPE: u8 = 0x11;
/// `FILE_PERSISTENT_ACLS` (winnt.h): the volume stores ACLs.
const FILE_PERSISTENT_ACLS: u32 = 0x8;
/// `SYSTEM_MANDATORY_LABEL_NO_WRITE_UP` (winnt.h).
const NO_WRITE_UP: u32 = 0x1;

const MECHANISM: &str = "Low integrity restricted token (no privileges) + Low mandatory labels \
                         on the writable paths + Job Object (kill-on-close, no breakaway)";

fn process_token() -> Result<OwnedHandle> {
    let mut h: HANDLE = null_mut();
    // SAFETY: GetCurrentProcess is a pseudo-handle; h is a valid out-pointer.
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
            &mut h,
        )
    } == 0
    {
        return Err(sb_err("OpenProcessToken"));
    }
    Ok(owned(h))
}

/// BUILTIN\Administrators: made deny-only in the child token (ignored when
/// the token does not carry it).
const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

/// A primary token for the child: provio's own token with every privilege
/// removed, the Administrators group deny-only, and its integrity level
/// lowered to Low.
fn low_token() -> Result<OwnedHandle> {
    let own = process_token()?;
    let admins = string_sid(ADMINISTRATORS_SID)?;
    let disable = [SID_AND_ATTRIBUTES {
        Sid: admins.ptr,
        Attributes: 0,
    }];
    let mut h: HANDLE = null_mut();
    // SAFETY: own is a valid token opened with TOKEN_DUPLICATE; `disable`
    // holds one valid SID that outlives the call; h is a valid out-pointer.
    if unsafe {
        CreateRestrictedToken(
            own.as_raw_handle(),
            DISABLE_MAX_PRIVILEGE,
            1,
            disable.as_ptr(),
            0,
            null(),
            0,
            null(),
            &mut h,
        )
    } == 0
    {
        return Err(sb_err("CreateRestrictedToken"));
    }
    let token = owned(h);
    let low = string_sid(LOW_IL_SID)?;
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: low.ptr,
            Attributes: SE_GROUP_INTEGRITY,
        },
    };
    // SAFETY: low.ptr is a valid SID.
    let sid_len = unsafe { GetLengthSid(low.ptr) };
    // SAFETY: token is valid with TOKEN_ADJUST_DEFAULT; label points at a
    // live TOKEN_MANDATORY_LABEL whose SID outlives the call.
    if unsafe {
        SetTokenInformation(
            token.as_raw_handle(),
            TokenIntegrityLevel,
            &label as *const _ as *const c_void,
            std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32 + sid_len,
        )
    } == 0
    {
        return Err(sb_err("lowering the token's integrity level"));
    }
    Ok(token)
}

pub(crate) fn capabilities() -> Capabilities {
    let filesystem = match low_token() {
        Ok(_) => Support::Full,
        Err(e) => Support::Unavailable(format!("cannot create a Low integrity token: {e}")),
    };
    Capabilities {
        filesystem,
        network_deny: Support::Unavailable(
            "a Low integrity token does not restrict network access, and per-process \
             network filters (WFP) need administrator rights"
                .into(),
        ),
        mechanism: MECHANISM.into(),
    }
}

// ---- mandatory labels ----------------------------------------------------

/// Whether the volume holding `path` stores ACLs (NTFS, ReFS). FAT/exFAT
/// volumes have no labels at all: every file on them is writable by a Low
/// process, and a label cannot be applied.
fn volume_has_acls(path: &Path) -> Result<bool> {
    let w = wide(path.as_os_str())?;
    // SAFETY: w is NUL-terminated; zero access is enough to query the
    // volume; BACKUP_SEMANTICS allows opening directories.
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(sb_err(&format!("opening {}", path.display())));
    }
    let h = owned(h);
    let mut flags = 0u32;
    // SAFETY: valid handle; only the flags out-pointer is requested.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            h.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &mut flags,
            null_mut(),
            0,
        )
    };
    if ok == 0 {
        return Err(sb_err(&format!(
            "querying the volume of {}",
            path.display()
        )));
    }
    Ok(flags & FILE_PERSISTENT_ACLS != 0)
}

/// Whether `sacl` already carries a Low (or lower-reaching, i.e. same SID)
/// NO_WRITE_UP label that applies to the object itself and, for
/// directories, is inherited by files and subdirectories.
fn has_low_label(sacl: *const ACL, low: &Sid, dir: bool) -> bool {
    if sacl.is_null() {
        return false;
    }
    // SAFETY: sacl is a valid ACL from GetNamedSecurityInfoW; each ACE
    // pointer returned by GetAce is valid for the ACL's lifetime and is
    // read as SYSTEM_MANDATORY_LABEL_ACE only after checking its type.
    unsafe {
        let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
        if GetAclInformation(
            sacl,
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
            if GetAce(sacl, i, &mut ace) == 0 || ace.is_null() {
                continue;
            }
            let header = &*(ace as *const ACE_HEADER);
            if header.AceType != MANDATORY_LABEL_ACE_TYPE {
                continue;
            }
            let label = &*(ace as *const SYSTEM_MANDATORY_LABEL_ACE);
            return label.Header.AceFlags & INHERIT_ONLY_ACE as u8 == 0
                && (!dir || label.Header.AceFlags & inherit == inherit)
                && label.Mask & NO_WRITE_UP != 0
                && EqualSid(&label.SidStart as *const u32 as *mut c_void, low.ptr) != 0;
        }
        false
    }
}

/// Whether `path` already carries the Low label the boundary needs.
fn is_low_labelled(path: &Path, low: &Sid) -> Result<bool> {
    let wpath = wide(path.as_os_str())?;
    let mut sacl: *mut ACL = null_mut();
    let mut sd: *mut c_void = null_mut();
    // SAFETY: wpath is NUL-terminated; out-pointers are valid; sd is freed
    // below (sacl points into it). Reading the label needs READ_CONTROL
    // only, not SeSecurityPrivilege.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            wpath.as_ptr(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sacl,
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(code_err(
            &format!("reading the integrity label of {}", path.display()),
            rc,
        ));
    }
    let present = has_low_label(sacl, low, path.is_dir());
    // SAFETY: sd was allocated by GetNamedSecurityInfoW.
    unsafe { LocalFree(sd) };
    Ok(present)
}

/// Give `path` a Low NO_WRITE_UP mandatory label (inheritable when it is a
/// directory). Returns `true` when the label was added, `false` when it was
/// already present.
fn ensure_low_label(path: &Path, low: &Sid) -> Result<bool> {
    if is_low_labelled(path, low)? {
        return Ok(false);
    }
    let dir = path.is_dir();
    let wpath = wide(path.as_os_str())?;

    // SAFETY: low.ptr is a valid SID.
    let sid_len = unsafe { GetLengthSid(low.ptr) } as usize;
    let size = std::mem::size_of::<ACL>() + std::mem::size_of::<SYSTEM_MANDATORY_LABEL_ACE>()
        - std::mem::size_of::<u32>()
        + sid_len;
    let mut buf = vec![0u64; size.div_ceil(8)];
    let acl = buf.as_mut_ptr() as *mut ACL;
    let flags = if dir {
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    } else {
        0
    };
    // SAFETY: buf is 8-byte aligned and at least `size` bytes long, enough
    // for the ACL header plus one mandatory-label ACE carrying `low`.
    unsafe {
        if InitializeAcl(acl, size as u32, ACL_REVISION) == 0 {
            return Err(sb_err("InitializeAcl"));
        }
        if AddMandatoryAce(acl, ACL_REVISION, flags, NO_WRITE_UP, low.ptr) == 0 {
            return Err(sb_err("AddMandatoryAce"));
        }
    }
    // SAFETY: wpath is NUL-terminated and acl a valid ACL living in buf.
    // Setting a label at or below the caller's own integrity needs only
    // WRITE_OWNER on the object; SetNamedSecurityInfoW propagates the
    // inheritable label to existing children.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            wpath.as_ptr(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null(),
            acl,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(code_err(
            &format!(
                "labelling {} writable for the Low integrity agent",
                path.display()
            ),
            rc,
        ));
    }
    Ok(true)
}

/// Protected files beneath a Low-labelled directory cannot be protected:
/// measured, an explicit Medium label on the file blocks an in-place write,
/// but the Low agent can still delete it, rename a new file over it, or
/// create it when absent, through the parent's FILE_DELETE_CHILD /
/// FILE_ADD_FILE (the parent is Low). Keeping the parent Medium would break
/// the agent's own atomic writes and new files there. So nothing is claimed.
pub(crate) fn protection_level(
    files: &[PathBuf],
    notes: &mut Vec<String>,
) -> crate::enforce::Level {
    notes.push(format!(
        "NOT protected: integrity labels cannot keep a file unwritable inside a writable \
         directory (the agent can delete or replace it through the directory), so the agent \
         can rewrite {}",
        files
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    crate::enforce::Level::NotEnforced
}

/// Label every path of the writable set. Returns the paths whose label was
/// newly added (the caller reports them: labels persist).
/// The paths of `paths` that do not carry the Low label yet (and would get
/// one, persistently, from [`label_writable`]).
pub(crate) fn unlabelled(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let low = string_sid(LOW_IL_SID)?;
    let mut out = Vec::new();
    for p in paths {
        if !is_low_labelled(p, &low)? {
            out.push(p.clone());
        }
    }
    Ok(out)
}

pub(crate) fn label_writable(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let low = string_sid(LOW_IL_SID)?;
    let mut added = Vec::new();
    for p in paths {
        if !volume_has_acls(p)? {
            return Err(ProvioError::Sandbox(format!(
                "{} is on a volume without ACL support (FAT/exFAT?): integrity labels cannot \
                 confine writes there (fail closed)",
                p.display()
            )));
        }
        if ensure_low_label(p, &low)? {
            added.push(p.clone());
        }
    }
    Ok(added)
}

// ---- program resolution ----------------------------------------------------

/// What to execute: an image and the arguments that precede the user's.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Resolved {
    pub(crate) exe: PathBuf,
    pub(crate) leading: Vec<String>,
}

fn env_get<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
    env.iter()
        .rev()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
}

/// Find `program` the way cmd.exe would: as given when it has a path, else
/// on PATH, trying PATHEXT extensions (extensionless files, e.g. npm's
/// POSIX shims, are skipped: CreateProcess cannot run them).
fn find_program(program: &str, cwd: &Path, env: &[(String, String)]) -> Option<PathBuf> {
    let exts: Vec<String> = env_get(env, "PATHEXT")
        .unwrap_or(".COM;.EXE;.BAT;.CMD")
        .split(';')
        .filter(|e| e.starts_with('.'))
        .map(str::to_ascii_lowercase)
        .collect();
    let candidates = |base: PathBuf| -> Vec<PathBuf> {
        let has_ext = base
            .extension()
            .map(|e| exts.contains(&format!(".{}", e.to_string_lossy().to_ascii_lowercase())))
            .unwrap_or(false);
        if has_ext {
            vec![base]
        } else {
            exts.iter()
                .map(|e| PathBuf::from(format!("{}{e}", base.display())))
                .collect()
        }
    };
    let p = Path::new(program);
    if p.is_absolute() || program.contains(['\\', '/']) {
        let base = if p.is_absolute() {
            p.to_path_buf()
        } else {
            cwd.join(p)
        };
        return candidates(base).into_iter().find(|c| c.is_file());
    }
    let path = env_get(env, "PATH")?;
    std::env::split_paths(path)
        .flat_map(|dir| candidates(dir.join(p)))
        .find(|c| c.is_file())
}

/// Parse an npm `cmd-shim` batch file into the image it launches. Handles
/// the two shapes npm generates: a direct `"%dp0%\...\x.exe" %*` and the
/// node form `"%_prog%" "%dp0%\...\x.js" %*`. Anything else: `None`.
pub(crate) fn parse_npm_shim(
    shim: &Path,
    text: &str,
    find_node: impl Fn() -> Option<PathBuf>,
) -> Option<Resolved> {
    let dir = shim.parent()?;
    let line = text.lines().rev().find(|l| l.contains("%*"))?;
    let head = &line[..line.find("%*")?];
    // Quoted tokens only, in order.
    let mut tokens = Vec::new();
    let mut rest = head;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        let end = after.find('"')?;
        tokens.push(after[..end].to_string());
        rest = &after[end + 1..];
    }
    let dp0 = format!("{}\\", dir.display());
    let mut out: Vec<String> = Vec::new();
    for (i, t) in tokens.iter().enumerate() {
        if i == 0 && t == "%_prog%" {
            let local = dir.join("node.exe");
            let node = if local.is_file() { local } else { find_node()? };
            out.push(node.to_string_lossy().into_owned());
            continue;
        }
        let v = t.replace("%dp0%", &dp0);
        if v.contains('%') {
            return None;
        }
        out.push(v);
    }
    let mut it = out.into_iter();
    let exe = PathBuf::from(it.next()?);
    let is_exe = exe
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("exe"));
    if !is_exe || !exe.is_file() {
        return None;
    }
    Some(Resolved {
        exe,
        leading: it.collect(),
    })
}

/// Characters cmd.exe interprets even inside a `/s /c` command line.
const CMD_META: &[char] = &['"', '%', '!', '^', '&', '|', '<', '>', '(', ')', '\n', '\r'];

pub(crate) fn resolve(
    program: &str,
    args: &[String],
    cwd: &Path,
    env: &[(String, String)],
) -> Result<(Resolved, Vec<String>)> {
    let found = find_program(program, cwd, env).ok_or_else(|| {
        ProvioError::Sandbox(format!(
            "{program}: not found on PATH (tried the PATHEXT extensions)"
        ))
    })?;
    let ext = found
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if ext != "bat" && ext != "cmd" {
        return Ok((
            Resolved {
                exe: found,
                leading: Vec::new(),
            },
            args.to_vec(),
        ));
    }
    // npm shims: launch the real image directly (no cmd.exe, exact argv).
    if let Ok(text) = std::fs::read_to_string(&found) {
        let node = || {
            find_program("node", cwd, env)
                .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe")))
        };
        if let Some(r) = parse_npm_shim(&found, &text, node) {
            return Ok((r, args.to_vec()));
        }
    }
    // Any other batch file runs through cmd.exe. Its quoting cannot be made
    // exact, so arguments carrying cmd metacharacters are refused.
    if let Some(bad) = args.iter().find(|a| a.contains(CMD_META)) {
        return Err(ProvioError::Sandbox(format!(
            "{} is a batch file and argument {bad:?} contains cmd.exe metacharacters; run the \
             underlying program directly (fail closed)",
            found.display()
        )));
    }
    let comspec = env_get(env, "ComSpec")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows\System32\cmd.exe"));
    let mut line = format!("\"{}\"", found.display());
    for a in args {
        line.push(' ');
        if a.is_empty() || a.contains([' ', '\t']) {
            line.push('"');
            line.push_str(a);
            line.push('"');
        } else {
            line.push_str(a);
        }
    }
    Ok((
        Resolved {
            exe: comspec,
            leading: vec!["/d".into(), "/s".into(), "/c".into()],
        },
        vec![format!("\"{line}\"")],
    ))
}

// ---- spawn ----------------------------------------------------------------

fn create_interactive_job() -> Result<OwnedHandle> {
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
    limits.BasicLimitInformation.ActiveProcessLimit = INTERACTIVE_PROCESS_LIMIT;
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
            | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
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

/// An inheritable duplicate of one of provio's standard handles, or `None`
/// when that handle is absent (no console, closed stream).
fn inheritable_std(which: u32) -> Result<Option<OwnedHandle>> {
    // SAFETY: GetStdHandle has no preconditions.
    let h = unsafe { GetStdHandle(which) };
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        return Ok(None);
    }
    let mut dup: HANDLE = null_mut();
    // SAFETY: h is a valid handle of this process; dup is a valid
    // out-pointer; the duplicate is owned below.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            h,
            GetCurrentProcess(),
            &mut dup,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(sb_err("duplicating a standard handle for the agent"));
    }
    Ok(Some(owned(dup)))
}

/// Swallow Ctrl-C / Ctrl-Break in provio while an interactive agent runs:
/// the agent shares the console and receives them itself. Handler routines
/// (unlike `SetConsoleCtrlHandler(NULL, TRUE)`) are not inherited.
unsafe extern "system" fn swallow_ctrl(kind: u32) -> i32 {
    i32::from(kind == CTRL_C_EVENT || kind == CTRL_BREAK_EVENT)
}

/// A running interactive agent and its job.
pub(crate) struct InteractiveChild {
    process: OwnedHandle,
    job: OwnedHandle,
    pid: u32,
}

impl InteractiveChild {
    pub(crate) fn id(&self) -> u32 {
        self.pid
    }

    /// Wait for the agent to exit; then end every descendant (kill the
    /// job). Returns the agent's exit code.
    pub(crate) fn wait(self) -> Result<i32> {
        // SAFETY: registering a valid handler routine.
        let hooked = unsafe { SetConsoleCtrlHandler(Some(swallow_ctrl), 1) } != 0;
        // SAFETY: process is a valid process handle.
        let rc = unsafe { WaitForSingleObject(self.process.as_raw_handle(), INFINITE) };
        if hooked {
            // SAFETY: removing the handler registered above.
            unsafe { SetConsoleCtrlHandler(Some(swallow_ctrl), 0) };
        }
        let result = if rc == WAIT_OBJECT_0 {
            let mut code = 0u32;
            // SAFETY: valid handle and out-pointer.
            if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) } == 0 {
                Err(sb_err("GetExitCodeProcess"))
            } else {
                Ok(code as i32)
            }
        } else {
            Err(sb_err("WaitForSingleObject"))
        };
        // SAFETY: job is a valid job handle.
        unsafe { TerminateJobObject(self.job.as_raw_handle(), 1) };
        result
    }
}

/// Launch `program args` interactively (inherited console / standard
/// handles), in a fresh Job Object, with a Low integrity restricted token
/// when `confine` is set. `env` is the complete environment.
pub(crate) fn spawn(
    program: &str,
    args: &[String],
    cwd: &Path,
    env: &[(String, String)],
    confine: bool,
) -> Result<InteractiveChild> {
    let (block, _) = env_block(env)?;
    let (resolved, rest) = resolve(program, args, cwd, env)?;
    let mut all = resolved.leading.clone();
    all.extend(rest);
    let wexe = wide(resolved.exe.as_os_str())?;
    let mut cmdline = if resolved.leading.first().map(String::as_str) == Some("/d") {
        // cmd.exe: the last argument is a pre-quoted `/s /c` line.
        let mut s: Vec<u16> = OsStr::new(&format!("\"{}\" ", resolved.exe.display()))
            .encode_wide()
            .collect();
        s.extend(OsStr::new(&all.join(" ")).encode_wide());
        if s.contains(&0) {
            return Err(ProvioError::Sandbox(
                "argument contains NUL (fail closed)".into(),
            ));
        }
        s.push(0);
        s
    } else {
        command_line(&resolved.exe, &all)?
    };
    let wcwd = wide(cwd.as_os_str())?;

    let stdin = inheritable_std(STD_INPUT_HANDLE)?;
    let stdout = inheritable_std(STD_OUTPUT_HANDLE)?;
    let stderr = inheritable_std(STD_ERROR_HANDLE)?;
    let raw = |h: &Option<OwnedHandle>| h.as_ref().map_or(null_mut(), |h| h.as_raw_handle());
    let inherit: Vec<HANDLE> = [&stdin, &stdout, &stderr]
        .iter()
        .filter_map(|h| h.as_ref().map(|h| h.as_raw_handle()))
        .collect();
    let job = create_interactive_job()?;
    let token = if confine { Some(low_token()?) } else { None };

    let mut attrs = AttrList::new(1)?;
    if !inherit.is_empty() {
        // SAFETY: `inherit` lives on this frame until after CreateProcess*;
        // the list is dropped at the end of this function.
        unsafe {
            attrs.set(
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                inherit.as_ptr() as *const c_void,
                std::mem::size_of_val(inherit.as_slice()),
            )?;
        }
    }
    // SAFETY: plain-old-data struct; zero is a valid initial state.
    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = raw(&stdin);
    si.StartupInfo.hStdOutput = raw(&stdout);
    si.StartupInfo.hStdError = raw(&stderr);
    si.lpAttributeList = attrs.ptr();
    let flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT;
    let inherit_handles = i32::from(!inherit.is_empty());

    // SAFETY: plain-old-data out-struct.
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: every pointer is valid for the call: NUL-terminated wexe and
    // wcwd, a mutable NUL-terminated cmdline, a double-NUL-terminated
    // Unicode env block, an initialized STARTUPINFOEXW whose attribute list
    // refers to live handles, and a valid PROCESS_INFORMATION out-pointer;
    // `token` is a primary token derived from our own (no
    // SeAssignPrimaryTokenPrivilege needed).
    let ok = unsafe {
        match &token {
            Some(t) => CreateProcessAsUserW(
                t.as_raw_handle(),
                wexe.as_ptr(),
                cmdline.as_mut_ptr(),
                null(),
                null(),
                inherit_handles,
                flags,
                block.as_ptr() as *const c_void,
                wcwd.as_ptr(),
                &si.StartupInfo,
                &mut pi,
            ),
            None => CreateProcessW(
                wexe.as_ptr(),
                cmdline.as_mut_ptr(),
                null(),
                null(),
                inherit_handles,
                flags,
                block.as_ptr() as *const c_void,
                wcwd.as_ptr(),
                &si.StartupInfo,
                &mut pi,
            ),
        }
    };
    if ok == 0 {
        return Err(ProvioError::Sandbox(format!(
            "spawn {} failed: {}",
            resolved.exe.display(),
            io::Error::last_os_error()
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
    Ok(InteractiveChild {
        process,
        job,
        pid: pi.dwProcessId,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_token_can_be_created() {
        low_token().unwrap();
    }

    #[test]
    fn parses_both_npm_shim_shapes() {
        let dir = std::env::temp_dir().join(format!("provio-shim-{}", std::process::id()));
        let bin = dir.join(r"node_modules\x\bin");
        std::fs::create_dir_all(&bin).unwrap();
        let exe = bin.join("tool.exe");
        std::fs::write(&exe, b"MZ").unwrap();
        let shim = dir.join("tool.cmd");
        let direct = "@ECHO off\r\nSETLOCAL\r\nCALL :find_dp0\r\n\"%dp0%\\node_modules\\x\\bin\\tool.exe\"   %*\r\n";
        let r = parse_npm_shim(&shim, direct, || None).unwrap();
        assert_eq!(
            r.exe,
            PathBuf::from(format!(
                "{}\\\\node_modules\\x\\bin\\tool.exe",
                dir.display()
            ))
        );
        assert!(r.leading.is_empty());

        let node = dir.join("node.exe");
        std::fs::write(&node, b"MZ").unwrap();
        let js = "endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & \"%_prog%\"  \"%dp0%\\node_modules\\x\\cli.js\" %*\r\n";
        let r = parse_npm_shim(&shim, js, || None).unwrap();
        assert_eq!(r.exe, node);
        assert_eq!(r.leading.len(), 1);
        assert!(r.leading[0].ends_with(r"node_modules\x\cli.js"));

        assert!(parse_npm_shim(&shim, "\"%OTHER%\\a.exe\" %*", || None).is_none());
        assert!(parse_npm_shim(&shim, "@echo hi", || None).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn batch_arguments_with_cmd_metacharacters_are_refused() {
        let dir = std::env::temp_dir().join(format!("provio-bat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("t.cmd"), "@echo %*\r\n").unwrap();
        let env = vec![
            ("PATH".to_string(), dir.display().to_string()),
            ("PATHEXT".to_string(), ".EXE;.CMD".to_string()),
        ];
        let (r, rest) = resolve("t", &["a b".into()], &dir, &env).unwrap();
        assert!(r
            .exe
            .to_string_lossy()
            .to_ascii_lowercase()
            .ends_with("cmd.exe"));
        assert_eq!(rest.len(), 1);
        assert!(rest[0].contains("\"a b\""));
        assert!(resolve("t", &["a&b".into()], &dir, &env).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
