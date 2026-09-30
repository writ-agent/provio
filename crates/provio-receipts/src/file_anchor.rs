//! Offline anchor: one JSON line per receipt appended to an anchor log.
//!
//! This needs no network and gives no guarantee by itself: the log is only
//! a witness if you copy it somewhere the host that writes the ledger cannot
//! rewrite — a git remote with protected history, WORM / object-lock
//! storage, another machine. `verify` checks that the receipt's line is
//! present, unmodified, in whichever copy you point it at.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

use crate::receipt::Receipt;
use crate::{invalid, verify_err, Result};

pub const ANCHOR_LINE_FORMAT: &str = "writ.anchor-line/v1";

/// Stored in the receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileAnchor {
    /// Where the line was appended (as given at anchor time).
    pub path: String,
    /// SHA-256 (hex) of the line's bytes, without the trailing newline.
    pub line_sha256: String,
    pub anchored_at: String,
}

/// One line of the anchor log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorLine {
    pub format: String,
    pub anchored_at: String,
    pub ledger_id: String,
    pub records: u64,
    pub tip_hash: String,
    pub merkle_root: String,
    pub signer: String,
    /// SHA-512 (hex) of the canonical checkpoint bytes.
    pub checkpoint_sha512: String,
    /// The receipt signature (base64).
    pub signature: String,
}

fn line_for(receipt: &Receipt, anchored_at: &str) -> Result<AnchorLine> {
    let cp = &receipt.checkpoint;
    Ok(AnchorLine {
        format: ANCHOR_LINE_FORMAT.into(),
        anchored_at: anchored_at.into(),
        ledger_id: cp.ledger_id.clone(),
        records: cp.records,
        tip_hash: cp.tip_hash.clone(),
        merkle_root: cp.merkle_root.clone(),
        signer: cp.signer.clone(),
        checkpoint_sha512: hex::encode(Sha512::digest(cp.canonical_bytes()?)),
        signature: receipt.signature.value.clone(),
    })
}

/// Append the receipt's line to `log` (created if absent) and fsync it.
pub fn append(receipt: &Receipt, log: &Path) -> Result<FileAnchor> {
    let anchored_at = provio_core::time::Timestamp::now().to_rfc3339();
    let line = serde_json::to_string(&line_for(receipt, &anchored_at)?)?;
    if let Some(parent) = log.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut f = OpenOptions::new().create(true).append(true).open(log)?;
    f.write_all(format!("{line}\n").as_bytes())?;
    f.sync_data()?;
    Ok(FileAnchor {
        path: log.display().to_string(),
        line_sha256: hex::encode(Sha256::digest(line.as_bytes())),
        anchored_at,
    })
}

/// Find the anchor's line in `log` and check it describes this receipt.
pub fn verify(anchor: &FileAnchor, receipt: &Receipt, log: &Path) -> Result<()> {
    let text = std::fs::read_to_string(log).map_err(|e| {
        invalid(format!(
            "file anchor: cannot read anchor log {}: {e}",
            log.display()
        ))
    })?;
    let line = text
        .lines()
        .find(|l| hex::encode(Sha256::digest(l.as_bytes())) == anchor.line_sha256)
        .ok_or_else(|| {
            verify_err(format!(
                "file anchor: no line with sha256 {} in {} (the anchor log was rewritten, or \
                 this is not the copy the receipt was anchored to)",
                anchor.line_sha256,
                log.display()
            ))
        })?;
    let parsed: AnchorLine = serde_json::from_str(line)
        .map_err(|e| verify_err(format!("file anchor: line does not parse: {e}")))?;
    let expect = line_for(receipt, &parsed.anchored_at)?;
    if parsed != expect {
        return Err(verify_err(
            "file anchor: the anchor line describes a different checkpoint or signature",
        ));
    }
    Ok(())
}
