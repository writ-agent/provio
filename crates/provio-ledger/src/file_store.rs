//! ADR-005 default store: an append-only JSONL file, one serialized
//! [`LedgerRecord`] per line (e.g. `.provio/ledger.jsonl`).
//!
//! Durability: every append is flushed and `sync_data`'d before `Ok` is
//! returned — a decision record on disk is evidence even if the process
//! dies immediately after (ADR-003).
//!
//! Crash-tolerant tail: if the process died mid-write, the final line may
//! be torn. [`FileLedgerStore::open`] stops at the last valid record in
//! that case; an unparseable line anywhere else is a hard error, because
//! mid-file corruption is evidence of tampering, not of a crash.
//!
//! # Many writers, one chain
//!
//! Several processes may append to one ledger at the same time (for example
//! one `provio check` per parallel tool call). Appends are serialized across
//! processes by an exclusive OS file lock on a sibling lock file,
//! `<ledger>.lock` (e.g. `ledger.jsonl.lock`), taken with `std`'s
//! [`File::try_lock`]. The lock file is created on demand and never
//! deleted (deleting a lock file races with its next user); the OS drops
//! the lock when its holder exits, so a crashed writer cannot wedge the
//! ledger. A writer that cannot get the lock within [`LOCK_TIMEOUT`] fails
//! closed with a `ProvioError::Ledger`.
//!
//! Under the lock, [`append`](LedgerStore::append):
//! 1. re-reads every record other writers appended since this handle last
//!    looked (link-checking each one), so the tip it checks against is the
//!    tip *on disk*, never a cached one;
//! 2. repairs a torn tail left by a writer that crashed mid-line (no other
//!    writer can be mid-line while the lock is held);
//! 3. rejects the record unless its `index` and `prev_hash` extend that tip;
//! 4. writes, flushes and `sync_data`s, then releases the lock.
//!
//! The chain therefore cannot fork. A writer that built its record on a tip
//! that has since moved gets `ProvioError::Ledger("append rejected: ...")`
//! and must rebuild the record on the new tip — exactly the SQLite store's
//! contract. [`LedgerWriter`](provio_core::ledger::LedgerWriter) reads
//! [`tip`](LedgerStore::tip) fresh from disk on every call, so retrying the
//! `record_*` call is the whole recovery; [`retry_append`] does that for
//! the pre-write rejections only (a record that may already be on disk is
//! never retried, so a retry can never duplicate a record).
//!
//! Readers take no lock. [`tip`](LedgerStore::tip), [`len`](LedgerStore::len),
//! [`get`](LedgerStore::get), [`iter`](LedgerStore::iter), `open` and
//! `verify` see records other processes appended. A writer emits
//! `record\n` in a single write, so any state of an in-progress append that
//! a reader can observe is a prefix of that line: an unterminated,
//! unparseable final chunk. Readers classify a line from its own bytes
//! only — unterminated and unparseable is "not committed yet" (or crash
//! debris awaiting repair), never corruption — and never read ahead to
//! decide, because the writer may finish its line in between. A
//! `\n`-terminated line that does not parse cannot be a write in progress
//! and is always reported (mid-file corruption on `open`, a break at its
//! index in `verify`); the one exception kept for crash-tolerance is such
//! a line as the very last content of the file at `open`, which is
//! truncated under the lock.

use std::cell::RefCell;
use std::ffi::OsString;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use provio_core::error::{ProvioError, Result};
use provio_core::ledger::{LedgerRecord, LedgerStore, GENESIS_HASH};

/// How long an append waits for another writer's lock before failing.
pub const LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// Pre-write rejections [`retry_append`] retries before giving up.
pub const APPEND_RETRIES: u32 = 64;

/// What this handle has read of the file so far.
#[derive(Debug, Clone)]
struct ChainState {
    /// Byte offset just past the last record consumed.
    offset: u64,
    len: u64,
    tip_hash: String,
    tip_record: Option<LedgerRecord>,
}

impl ChainState {
    fn empty() -> Self {
        ChainState {
            offset: 0,
            len: 0,
            tip_hash: GENESIS_HASH.to_string(),
            tip_record: None,
        }
    }
}

/// Append-only JSONL ledger, safe for concurrent writers in any number of
/// processes (see the [module docs](self)).
#[derive(Debug)]
pub struct FileLedgerStore {
    path: PathBuf,
    lock_path: PathBuf,
    state: RefCell<ChainState>,
}

/// Holds the exclusive ledger lock; released when dropped.
struct LockGuard(File);

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

impl FileLedgerStore {
    /// Open (creating file and parent dirs if absent) and link-check every
    /// existing line. A torn final line is truncated (under the writer
    /// lock); any other corruption is a `ProvioError::Ledger`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        // Ensure the file exists without truncating it.
        OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)?;
        let mut lock_path = OsString::from(path.as_os_str());
        lock_path.push(".lock");
        let store = FileLedgerStore {
            path,
            lock_path: PathBuf::from(lock_path),
            state: RefCell::new(ChainState::empty()),
        };
        if store.refresh()? {
            // Torn tail: repair it under the lock so a concurrent writer's
            // in-progress line is never mistaken for crash debris.
            let _guard = store.lock()?;
            store.refresh()?;
            store.repair_tail()?;
        }
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The sibling lock file that serializes appends across processes.
    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    fn lock(&self) -> Result<LockGuard> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.lock_path)?;
        match file.try_lock() {
            Ok(()) => return Ok(LockGuard(file)),
            Err(TryLockError::WouldBlock) => {}
            Err(TryLockError::Error(e)) => return Err(e.into()),
        }
        // Contended: wait in the OS lock queue instead of polling. Polling
        // `try_lock` is unfair — under sustained contention one writer can
        // keep losing the race until it times out — while a blocking lock
        // is granted to waiters by the kernel. The wait happens on a helper
        // thread so it stays bounded by LOCK_TIMEOUT; if the caller gives
        // up first, the thread releases the lock the moment it gets it.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || match file.lock() {
            Ok(()) => {
                if let Err(std::sync::mpsc::SendError(Ok(file))) = tx.send(Ok(file)) {
                    let _ = file.unlock();
                }
            }
            Err(e) => {
                let _ = tx.send(Err(e));
            }
        });
        match rx.recv_timeout(LOCK_TIMEOUT) {
            Ok(Ok(file)) => Ok(LockGuard(file)),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(ProvioError::Ledger(format!(
                "ledger {:?}: another writer held {:?} for more than {:?} (fail closed)",
                self.path, self.lock_path, LOCK_TIMEOUT
            ))),
        }
    }

    /// Consume records appended since the last refresh, link-checking each.
    /// Returns `true` if unparseable bytes follow the last record (a torn
    /// tail, or — without the lock — possibly a write in progress).
    fn refresh(&self) -> Result<bool> {
        let mut st = self.state.borrow_mut();
        let mut file = File::open(&self.path)?;
        let file_len = file.metadata()?.len();
        if file_len < st.offset {
            return Err(ProvioError::Ledger(format!(
                "ledger {:?} shrank below its last committed record (truncated or rewritten)",
                self.path
            )));
        }
        file.seek(SeekFrom::Start(st.offset))?;
        let mut reader = BufReader::new(file);
        let mut line = Vec::new();
        loop {
            line.clear();
            let n = reader.read_until(b'\n', &mut line)? as u64;
            if n == 0 {
                return Ok(false); // EOF
            }
            let trimmed = trim_ascii(&line);
            if trimmed.is_empty() {
                st.offset += n; // tolerate stray blank lines
                continue;
            }
            match serde_json::from_slice::<LedgerRecord>(trimmed) {
                Ok(rec) => {
                    if rec.index != st.len {
                        return Err(ProvioError::Ledger(format!(
                            "ledger {:?}: record index {} out of sequence (expected {})",
                            self.path, rec.index, st.len
                        )));
                    }
                    if rec.prev_hash != st.tip_hash {
                        return Err(ProvioError::Ledger(format!(
                            "ledger {:?}: record {} prev_hash does not match the chain tip",
                            self.path, rec.index
                        )));
                    }
                    st.offset += n;
                    st.len += 1;
                    st.tip_hash = rec.record_hash.clone();
                    st.tip_record = Some(rec);
                }
                Err(e) => {
                    // `read_until` returns a chunk without '\n' only at EOF.
                    // A writer emits `record\n` in one write, so every state
                    // a concurrent write can be seen in is a prefix of that
                    // line: an unterminated chunk is a write in progress (or
                    // crash debris). Decide from the chunk alone — reading
                    // ahead would race with the writer finishing its line
                    // and misreport it as mid-file corruption.
                    if !line.ends_with(b"\n") {
                        return Ok(true);
                    }
                    // A terminated line can never be a write in progress.
                    // Tolerated only as final debris (nothing but
                    // whitespace after it); anywhere else it is corruption.
                    let mut rest = Vec::new();
                    reader.read_to_end(&mut rest)?;
                    if trim_ascii(&rest).is_empty() {
                        return Ok(true);
                    }
                    return Err(ProvioError::Ledger(format!(
                        "ledger {:?}: corrupt record at index {} (mid-file corruption): {}",
                        self.path, st.len, e
                    )));
                }
            }
        }
    }

    /// With the lock held and state refreshed: drop any bytes past the last
    /// record (crash debris or blank lines — never a record, since
    /// `refresh` consumed every parseable one) and make sure the file ends
    /// in a newline. Returns the file length afterwards.
    fn repair_tail(&self) -> Result<u64> {
        let offset = self.state.borrow().offset;
        let mut file = OpenOptions::new().read(true).write(true).open(&self.path)?;
        if file.metadata()?.len() > offset {
            file.set_len(offset)?;
        }
        let mut end = offset;
        if offset > 0 {
            let mut last = [0u8; 1];
            file.seek(SeekFrom::Start(offset - 1))?;
            file.read_exact(&mut last)?;
            if last[0] != b'\n' {
                // A final record written without its newline: complete it
                // so the next line starts on its own.
                file.seek(SeekFrom::Start(offset))?;
                file.write_all(b"\n")?;
                end += 1;
            }
        }
        file.sync_data()?;
        self.state.borrow_mut().offset = end;
        Ok(end)
    }
}

fn trim_ascii(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|c| !c.is_ascii_whitespace());
    match start {
        None => &[],
        Some(s) => {
            let end = b
                .iter()
                .rposition(|c| !c.is_ascii_whitespace())
                .unwrap_or(s);
            &b[s..=end]
        }
    }
}

impl LedgerStore for FileLedgerStore {
    fn append(&mut self, record: &LedgerRecord) -> Result<()> {
        // Content check needs no lock: a record whose hash is not its own
        // would verify as broken the moment it landed.
        if record.compute_hash()? != record.record_hash {
            return Err(ProvioError::Ledger(format!(
                "append rejected: record {} record_hash does not match its contents",
                record.index
            )));
        }
        let mut line = serde_json::to_string(record)?;
        line.push('\n');

        let _guard = self.lock()?;
        // The tip on disk, not this handle's memory: other processes may
        // have appended since we last looked.
        self.refresh()?;
        let (len, tip_hash) = {
            let st = self.state.borrow();
            (st.len, st.tip_hash.clone())
        };
        if record.index != len {
            return Err(ProvioError::Ledger(format!(
                "append rejected: record index {} but ledger length is {} \
                 (records are append-only and sequential)",
                record.index, len
            )));
        }
        if record.prev_hash != tip_hash {
            return Err(ProvioError::Ledger(format!(
                "append rejected: record {} prev_hash does not match the ledger tip",
                record.index
            )));
        }
        let end = self.repair_tail()?;
        let mut file = OpenOptions::new().append(true).open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.flush()?;
        // Durability before Ok: the record must survive a power loss.
        file.sync_data()?;
        let mut st = self.state.borrow_mut();
        st.offset = end + line.len() as u64;
        st.len += 1;
        st.tip_hash = record.record_hash.clone();
        st.tip_record = Some(record.clone());
        Ok(())
    }

    fn tip(&self) -> Result<Option<LedgerRecord>> {
        self.refresh()?;
        Ok(self.state.borrow().tip_record.clone())
    }

    fn get(&self, index: u64) -> Result<Option<LedgerRecord>> {
        for item in record_iter(File::open(&self.path)?) {
            let rec = item?;
            if rec.index == index {
                return Ok(Some(rec));
            }
            if rec.index > index {
                break;
            }
        }
        Ok(None)
    }

    /// Records on disk now (including other writers' appends). Falls back
    /// to the last observed length only if the file cannot be read; `append`
    /// re-checks under the lock.
    fn len(&self) -> u64 {
        let _ = self.refresh();
        self.state.borrow().len
    }

    fn iter(&self) -> Box<dyn Iterator<Item = Result<LedgerRecord>> + '_> {
        match File::open(&self.path) {
            Ok(f) => Box::new(record_iter(f)),
            Err(e) => Box::new(std::iter::once(Err(ProvioError::Io(e)))),
        }
    }
}

/// Lazy line-by-line parse; never loads the whole file into memory. Used by
/// the store's `iter`/`get`, by `verify` and by the query helpers.
///
/// - Blank lines are skipped; each other `\n`-terminated line is one record,
///   and one that does not parse is an `Err` (tampering or corruption —
///   `verify` reports its position) and the scan continues.
/// - The final chunk without a `\n` is the only place a write in progress
///   (or a crashed writer's torn tail) can be seen, because every visible
///   state of a concurrent append is a prefix of `record\n`. If it parses it
///   is a complete record whose newline has not landed yet and is yielded;
///   otherwise it ends the stream silently. It is never reported as
///   corruption and nothing is read past it, so a reader running alongside
///   writers cannot misclassify their lines.
pub(crate) fn record_iter(file: File) -> impl Iterator<Item = Result<LedgerRecord>> {
    let mut reader = BufReader::new(file);
    let mut done = false;
    let mut line = Vec::new();
    std::iter::from_fn(move || loop {
        if done {
            return None;
        }
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Err(e) => {
                done = true;
                return Some(Err(ProvioError::Io(e)));
            }
            Ok(0) => return None,
            Ok(_) => {}
        }
        let trimmed = trim_ascii(&line);
        if trimmed.is_empty() {
            continue;
        }
        let terminated = line.ends_with(b"\n");
        match serde_json::from_slice::<LedgerRecord>(trimmed) {
            Ok(rec) => return Some(Ok(rec)),
            Err(_) if !terminated => {
                done = true; // write in progress / torn tail: not a record
                return None;
            }
            Err(e) => return Some(Err(ProvioError::from(e))),
        }
    })
}

/// Whether `e` is a pre-write append rejection caused by another writer
/// moving the tip (wrong `index` / `prev_hash`). Such a record never reached
/// the ledger, so rebuilding it on the new tip and appending again is safe.
/// Both stores word these rejections identically.
pub fn is_append_race(e: &ProvioError) -> bool {
    match e {
        ProvioError::Ledger(m) => {
            m.starts_with("append rejected")
                && (m.contains("but ledger length is")
                    || m.contains("prev_hash does not match the ledger tip"))
        }
        _ => false,
    }
}

/// How long [`retry_append`] keeps rebuilding a record that lost the race
/// to other writers (after at least [`APPEND_RETRIES`] attempts).
pub const APPEND_RETRY_DEADLINE: Duration = Duration::from_secs(30);

/// Run `f` (typically one `LedgerWriter::record_*` call, which rebuilds its
/// record on the current tip) until it succeeds, fails with anything other
/// than [`is_append_race`], or it has lost [`APPEND_RETRIES`] races and
/// [`APPEND_RETRY_DEADLINE`] has passed.
///
/// The backoff is jittered: writers that lose a race at the same moment
/// would otherwise retry in lockstep and the slowest could lose every time.
pub fn retry_append<T>(mut f: impl FnMut() -> Result<T>) -> Result<T> {
    let start = std::time::Instant::now();
    let mut attempt = 0u32;
    let mut seed = u64::from(std::process::id())
        ^ std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
    loop {
        match f() {
            Err(e)
                if is_append_race(&e)
                    && (attempt < APPEND_RETRIES || start.elapsed() < APPEND_RETRY_DEADLINE) =>
            {
                attempt += 1;
                // xorshift64: cheap jitter without a dependency.
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let cap = u64::from(attempt.min(25)) * 2; // up to 50 ms
                std::thread::sleep(Duration::from_millis(1 + seed % cap.max(1)));
            }
            other => return other,
        }
    }
}
