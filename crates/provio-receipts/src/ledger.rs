//! Building a checkpoint from a ledger, and checking a checkpoint against
//! the ledger as it stands now.
//!
//! Both work on any record stream (`LedgerStore::iter`, or [`read_records`]
//! for a path). An item that is `Err` is a record that could not be read or
//! parsed; it is reported at its position, never skipped.

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use provio_core::ledger::{LedgerRecord, GENESIS_HASH};
use provio_ledger::StoreKind;

use crate::merkle::{self, Hash};
use crate::receipt::{Checkpoint, SessionScope};
use crate::{hex32, Error, Result};

/// One ledger item: a parsed record, or why the record at this position
/// could not be read.
pub type RecordItem = std::result::Result<LedgerRecord, String>;

/// Stream the ledger at `path` without creating, locking or repairing it.
/// JSONL is read line by line (a torn, unterminated final line — a write in
/// progress — ends the stream, as in the store itself); other stores are
/// read through `provio_ledger::open_store`.
pub fn read_records(path: &Path) -> Result<Box<dyn Iterator<Item = RecordItem>>> {
    if !path.exists() {
        return Err(Error::Ledger(format!("no ledger at {}", path.display())));
    }
    let kind = provio_ledger::detect_store_kind(path).map_err(|e| Error::Ledger(e.to_string()))?;
    if kind == StoreKind::Jsonl {
        return Ok(Box::new(jsonl_iter(File::open(path)?)));
    }
    let store = provio_ledger::open_store(path).map_err(|e| Error::Ledger(e.to_string()))?;
    let items: Vec<RecordItem> = store.iter().map(|r| r.map_err(|e| e.to_string())).collect();
    Ok(Box::new(items.into_iter()))
}

fn jsonl_iter(file: File) -> impl Iterator<Item = RecordItem> {
    let mut reader = BufReader::new(file);
    let mut done = false;
    std::iter::from_fn(move || loop {
        if done {
            return None;
        }
        let mut line = Vec::new();
        match reader.read_until(b'\n', &mut line) {
            Err(e) => {
                done = true;
                return Some(Err(format!("read error: {e}")));
            }
            Ok(0) => return None,
            Ok(_) => {}
        }
        let text = String::from_utf8_lossy(&line);
        let trimmed = text.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<LedgerRecord>(trimmed) {
            Ok(rec) => return Some(Ok(rec)),
            Err(e) => {
                let terminated = line.ends_with(b"\n");
                let mut rest = Vec::new();
                let rest_empty = reader
                    .read_to_end(&mut rest)
                    .map(|_| rest.iter().all(|b| b.is_ascii_whitespace()))
                    .unwrap_or(false);
                done = true;
                if !terminated && rest_empty {
                    return None; // torn tail / write in progress
                }
                return Some(Err(format!("not a valid ledger record: {e}")));
            }
        }
    })
}

/// Why record `index` does not continue the chain, if it does not.
fn link_problem(rec: &LedgerRecord, index: u64, prev: &str) -> Option<String> {
    if rec.index != index {
        return Some(format!(
            "its index field is {} where {} was expected (a record was inserted, deleted or reordered)",
            rec.index, index
        ));
    }
    match rec.compute_hash() {
        Ok(h) if h == rec.record_hash => {}
        _ => {
            return Some(
                "its record_hash does not match its contents (the record was edited)".into(),
            )
        }
    }
    if rec.prev_hash != prev {
        return Some(format!(
            "its prev_hash does not link to record {} (a record at or before {} was altered)",
            index.wrapping_sub(1),
            index
        ));
    }
    None
}

fn leaf_of(rec: &LedgerRecord) -> Result<Hash> {
    Ok(merkle::leaf_hash(&hex32(&rec.record_hash, "record_hash")?))
}

/// The ledger facts a new receipt signs (`created_at` / `signer` left for
/// the caller). Refuses a ledger whose chain is broken: signing a broken
/// ledger would certify the damage.
pub fn build_checkpoint(
    records: impl Iterator<Item = RecordItem>,
    session: Option<&str>,
) -> Result<Checkpoint> {
    let mut prev = GENESIS_HASH.to_string();
    let mut leaves = Vec::new();
    let mut session_leaves = Vec::new();
    let mut ledger_id = None;
    for (i, item) in records.enumerate() {
        let i = i as u64;
        let rec = item.map_err(|e| {
            Error::Ledger(format!("record {i} cannot be read ({e}); refusing to sign"))
        })?;
        if let Some(why) = link_problem(&rec, i, &prev) {
            return Err(Error::Ledger(format!(
                "chain broken at record {i}: {why}; refusing to sign (run `provio verify`)"
            )));
        }
        let leaf = leaf_of(&rec)?;
        leaves.push(leaf);
        if session == Some(rec.session_id.as_str()) {
            session_leaves.push(leaf);
        }
        if i == 0 {
            ledger_id = Some(rec.record_hash.clone());
        }
        prev = rec.record_hash;
    }
    let Some(ledger_id) = ledger_id else {
        return Err(Error::Ledger(
            "the ledger is empty; there is nothing to sign".into(),
        ));
    };
    let session = match session {
        None => None,
        Some(id) if session_leaves.is_empty() => {
            return Err(Error::Ledger(format!(
                "session {id:?} has no records in this ledger"
            )))
        }
        Some(id) => Some(SessionScope {
            id: id.to_string(),
            records: session_leaves.len() as u64,
            merkle_root: hex::encode(merkle::root(&session_leaves)),
        }),
    };
    let n = leaves.len() as u64;
    Ok(Checkpoint {
        ledger_id,
        records: n,
        tip_index: n - 1,
        tip_hash: prev,
        merkle_root: hex::encode(merkle::root(&leaves)),
        session,
        created_at: provio_core::time::Timestamp::now().to_rfc3339(),
        signer: String::new(),
    })
}

/// A checkpoint that still holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointStatus {
    /// Records appended after the checkpoint (allowed).
    pub appended_after: u64,
    /// First record after the checkpoint that does not continue the chain,
    /// with the reason. The checkpoint itself still holds; the ledger
    /// after it does not.
    pub broken_after: Option<(u64, String)>,
    /// Leaf hashes of records 0..=tip (for inclusion proofs).
    pub leaves: Vec<Hash>,
}

/// Recompute the checkpoint from the ledger: records 0..=tip must be
/// exactly the records that were signed. Nothing about the checkpoint is
/// trusted before the signature is checked; call this after
/// [`crate::Receipt::verify_signature`].
pub fn check_checkpoint(
    cp: &Checkpoint,
    records: impl Iterator<Item = RecordItem>,
) -> Result<CheckpointStatus> {
    cp.validate()?;
    let fail = |msg: String| Err(Error::Verify(format!("checkpoint: {msg}")));
    let mut prev = GENESIS_HASH.to_string();
    let mut leaves = Vec::with_capacity(cp.records.min(1 << 20) as usize);
    let mut session_leaves = Vec::new();
    let mut appended_after = 0u64;
    let mut broken_after = None;
    let mut seen = 0u64;
    for (i, item) in records.enumerate() {
        let i = i as u64;
        seen = i + 1;
        let rec = match item {
            Ok(r) => r,
            Err(e) if i <= cp.tip_index => {
                return fail(format!(
                    "record {i} is covered by the receipt but cannot be read: {e}"
                ))
            }
            Err(e) => {
                broken_after = Some((i, format!("it cannot be read: {e}")));
                break;
            }
        };
        if let Some(why) = link_problem(&rec, i, &prev) {
            if i <= cp.tip_index {
                return fail(format!("record {i} was altered: {why}"));
            }
            broken_after = Some((i, why));
            break;
        }
        if i <= cp.tip_index {
            if i == 0 && rec.record_hash != cp.ledger_id {
                return fail(format!(
                    "record 0 has hash {}, the receipt's ledger_id is {}: this is a different \
                     ledger, or it was rewritten from the start",
                    rec.record_hash, cp.ledger_id
                ));
            }
            let leaf = leaf_of(&rec)?;
            leaves.push(leaf);
            if let Some(s) = &cp.session {
                if rec.session_id == s.id {
                    session_leaves.push(leaf);
                }
            }
            if i == cp.tip_index && rec.record_hash != cp.tip_hash {
                return fail(format!(
                    "record {i} (the checkpoint tip) has hash {}, the receipt says {}: the chain \
                     is internally consistent but was rewritten at or before record {i}",
                    rec.record_hash, cp.tip_hash
                ));
            }
        } else {
            appended_after += 1;
        }
        prev = rec.record_hash;
    }
    if seen < cp.records {
        return fail(format!(
            "the ledger was truncated: it has {seen} records, the receipt covers {} (records {}..={} are gone)",
            cp.records, seen, cp.tip_index
        ));
    }
    let root = hex::encode(merkle::root(&leaves));
    if root != cp.merkle_root {
        return fail(format!(
            "Merkle root over records 0..={} is {root}, the receipt says {}",
            cp.tip_index, cp.merkle_root
        ));
    }
    if let Some(s) = &cp.session {
        let sroot = hex::encode(merkle::root(&session_leaves));
        if session_leaves.len() as u64 != s.records || sroot != s.merkle_root {
            return fail(format!(
                "session {:?}: the ledger has {} of its records in 0..={} with root {sroot}, \
                 the receipt says {} with root {}",
                s.id,
                session_leaves.len(),
                cp.tip_index,
                s.records,
                s.merkle_root
            ));
        }
    }
    Ok(CheckpointStatus {
        appended_after,
        broken_after,
        leaves,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items(text: &str) -> Vec<RecordItem> {
        let dir = std::env::temp_dir().join(format!(
            "provio-receipts-jsonl-{}-{}",
            std::process::id(),
            text.len()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("l.jsonl");
        std::fs::write(&p, text).unwrap();
        let v: Vec<RecordItem> = jsonl_iter(File::open(&p).unwrap()).collect();
        let _ = std::fs::remove_dir_all(&dir);
        v
    }

    #[test]
    fn jsonl_torn_tail_ends_stream_but_mid_file_garbage_is_reported() {
        // Unterminated unparseable last line: a write in progress.
        assert!(items("{\"torn").is_empty());
        // Terminated garbage is a record that cannot be read.
        let v = items("{\"torn\n");
        assert_eq!(v.len(), 1);
        assert!(v[0].is_err());
        // Garbage followed by more content is reported too.
        let v = items("garbage\n{}\n");
        assert_eq!(v.len(), 1);
        assert!(v[0].is_err());
        // Blank lines are skipped.
        assert!(items("\n\n  \n").is_empty());
    }

    #[test]
    fn empty_ledger_cannot_be_signed() {
        let e = build_checkpoint(std::iter::empty(), None).unwrap_err();
        assert!(e.to_string().contains("empty"), "{e}");
    }
}
