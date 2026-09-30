//! provio-receipts: signed receipts over the provio ledger, inclusion proofs,
//! and external anchoring (docs/receipts.md, "Contract 7 — Receipts").
//!
//! The ledger (Contract 3) is tamper-evident: `provio verify` catches an
//! edited record or a broken link, but anyone who can write the file can
//! rewrite all of it and recompute the chain. A receipt pins a checkpoint
//! of the ledger (its identity, record count, tip hash and an RFC 6962
//! Merkle root over every record hash) under an Ed25519 signature, so a
//! later rewrite, truncation or edit of any record at or before the
//! checkpoint is detected by anyone holding the receipt and the public key.
//! An anchor (Sigstore Rekor, or an append-only file you ship elsewhere)
//! adds an external, timestamped witness that the receipt existed.
//!
//! Modules:
//! - [`merkle`]: RFC 6962 / RFC 9162 Merkle tree hashing and inclusion proofs.
//! - [`keys`]: Ed25519 key generation and PEM (PKCS#8 / SPKI) files.
//! - [`receipt`]: the receipt format, its canonical bytes and signature.
//! - [`ledger`]: building a checkpoint from, and checking it against, a ledger.
//! - [`proof`]: inclusion proofs for one call's records.
//! - [`rekor`]: `hashedrekord` submission to Rekor and offline verification.
//! - [`file_anchor`]: the append-only anchor log alternative.

#![forbid(unsafe_code)]

pub mod file_anchor;
pub mod keys;
pub mod ledger;
pub mod merkle;
pub mod proof;
pub mod receipt;
pub mod rekor;

pub use receipt::{Anchor, Checkpoint, Receipt, ReceiptSignature, SessionScope};

/// Errors from receipt operations. Every message names what broke.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Malformed input: a receipt, key, proof or anchor that does not parse
    /// or violates the format.
    #[error("{0}")]
    Invalid(String),
    /// A verification check failed.
    #[error("{0}")]
    Verify(String),
    /// The ledger could not be read or is not in a signable state.
    #[error("ledger: {0}")]
    Ledger(String),
    /// Talking to a transparency log failed.
    #[error("rekor: {0}")]
    Rekor(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn invalid(msg: impl Into<String>) -> Error {
    Error::Invalid(msg.into())
}

pub(crate) fn verify_err(msg: impl Into<String>) -> Error {
    Error::Verify(msg.into())
}

/// Lowercase-hex SHA-256 digest.
pub(crate) fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Decode a lowercase 64-char hex string into 32 bytes.
pub(crate) fn hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    if !is_hex64(s) {
        return Err(invalid(format!(
            "{what} must be 64 lowercase hex characters, got {s:?}"
        )));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).map_err(|e| invalid(format!("{what}: {e}")))?;
    Ok(out)
}

pub(crate) fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}
