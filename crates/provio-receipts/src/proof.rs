//! Inclusion proofs: show that one call's records are among those a receipt
//! covers, without shipping the ledger.
//!
//! A proof file (`writ.inclusion-proof/v1`) embeds the receipt, the full
//! ledger records for the call (normally its decision and its execution),
//! and for each an RFC 6962 audit path to `checkpoint.merkle_root`. A
//! verifier recomputes each record's `record_hash` from its contents, then
//! the leaf hash, then the root. Holding the proof and the signer's public
//! key is enough; the ledger itself is not needed.

use provio_core::ledger::LedgerRecord;
use serde::{Deserialize, Serialize};

use crate::ledger::{check_checkpoint, RecordItem};
use crate::merkle::{self, Hash};
use crate::receipt::Receipt;
use crate::{hex32, invalid, verify_err, Result};

pub const PROOF_FORMAT: &str = "writ.inclusion-proof/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofEntry {
    /// The ledger record, exactly as stored.
    pub record: LedgerRecord,
    /// Its position: equals `record.index`.
    pub leaf_index: u64,
    /// Equals `checkpoint.records`.
    pub tree_size: u64,
    /// Sibling hashes, leaf to root, lowercase hex.
    pub audit_path: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    pub format: String,
    pub call_id: String,
    pub receipt: Receipt,
    pub entries: Vec<ProofEntry>,
}

/// Build a proof for `call_id` from the ledger. The ledger must still match
/// the receipt's checkpoint.
pub fn prove(
    receipt: &Receipt,
    records: impl Iterator<Item = RecordItem>,
    call_id: &str,
) -> Result<InclusionProof> {
    let cp = &receipt.checkpoint;
    let mut matched = Vec::new();
    let tip = cp.tip_index;
    let mut collect = |item: &RecordItem, i: u64| {
        if let Ok(rec) = item {
            if i <= tip && rec.call_id == call_id {
                matched.push(rec.clone());
            }
        }
    };
    let mut i = 0u64;
    let tee = records.inspect(|item| {
        collect(item, i);
        i += 1;
    });
    let status = check_checkpoint(cp, tee)?;
    if matched.is_empty() {
        return Err(invalid(format!(
            "call id {call_id:?} has no record among the {} records this receipt covers",
            cp.records
        )));
    }
    let entries = matched
        .into_iter()
        .map(|record| {
            let idx = record.index as usize;
            let path = merkle::inclusion_path(&status.leaves, idx)
                .ok_or_else(|| invalid("record index outside the checkpoint"))?;
            Ok(ProofEntry {
                leaf_index: record.index,
                tree_size: cp.records,
                audit_path: path.iter().map(hex::encode).collect(),
                record,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(InclusionProof {
        format: PROOF_FORMAT.to_string(),
        call_id: call_id.to_string(),
        receipt: receipt.clone(),
        entries,
    })
}

impl InclusionProof {
    pub fn from_json(text: &str) -> Result<InclusionProof> {
        let p: InclusionProof = serde_json::from_str(text)
            .map_err(|e| invalid(format!("not a provio inclusion proof: {e}")))?;
        if p.format != PROOF_FORMAT {
            return Err(invalid(format!(
                "unsupported proof format {:?} (this provio reads {PROOF_FORMAT})",
                p.format
            )));
        }
        Ok(p)
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)? + "\n")
    }

    /// Check every entry against the embedded receipt's Merkle root. The
    /// receipt's signature is checked separately (the caller pins the key).
    pub fn verify_entries(&self) -> Result<()> {
        let cp = &self.receipt.checkpoint;
        let root = hex32(&cp.merkle_root, "checkpoint.merkle_root")?;
        if self.entries.is_empty() {
            return Err(invalid("proof has no entries"));
        }
        for e in &self.entries {
            let r = &e.record;
            let at = format!("proof entry for record {}", e.leaf_index);
            if r.call_id != self.call_id {
                return Err(verify_err(format!(
                    "{at}: record is for call {:?}, the proof is for {:?}",
                    r.call_id, self.call_id
                )));
            }
            if r.index != e.leaf_index || e.tree_size != cp.records {
                return Err(verify_err(format!(
                    "{at}: leaf_index/tree_size ({}/{}) do not match the record index {} and \
                     the receipt's {} records",
                    e.leaf_index, e.tree_size, r.index, cp.records
                )));
            }
            match r.compute_hash() {
                Ok(h) if h == r.record_hash => {}
                _ => {
                    return Err(verify_err(format!(
                        "{at}: record_hash does not match the record's contents (record edited)"
                    )))
                }
            }
            let leaf = merkle::leaf_hash(&hex32(&r.record_hash, "record_hash")?);
            let path = e
                .audit_path
                .iter()
                .map(|h| hex32(h, "audit_path entry"))
                .collect::<Result<Vec<Hash>>>()?;
            if !merkle::verify_inclusion(&leaf, e.leaf_index, e.tree_size, &path, &root) {
                return Err(verify_err(format!(
                    "{at}: inclusion proof does not lead to the receipt's Merkle root"
                )));
            }
        }
        Ok(())
    }
}
