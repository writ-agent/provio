//! The receipt format (`writ.receipt/v1`) and its signature.
//!
//! The signed object is the [`Checkpoint`]. It is never signed as JSON: it
//! is first rendered to [`Checkpoint::canonical_bytes`], a fixed
//! line-oriented ASCII text whose first line is the domain-separation
//! string [`CHECKPOINT_CONTEXT`]. The signature is Ed25519ph (RFC 8032
//! §5.1: SHA-512 prehash, empty context) over those bytes — the variant
//! Rekor's `hashedrekord` type accepts for Ed25519 keys, so the very same
//! signature can be anchored without the private key.
//!
//! Every checkpoint field is validated against a strict pattern before
//! rendering, so each receipt has exactly one canonical encoding.

use base64::Engine as _;
use ed25519_dalek::{Digest, Sha512, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::file_anchor::FileAnchor;
use crate::keys::{key_id, parse_public_pem, public_pem};
use crate::rekor::RekorAnchor;
use crate::{b64, invalid, is_hex64, verify_err, Result};

/// `format` of a receipt file.
pub const RECEIPT_FORMAT: &str = "writ.receipt/v1";
/// First line of the canonical checkpoint bytes (domain separation).
pub const CHECKPOINT_CONTEXT: &str = "writ.receipt.checkpoint.v1";
/// `signature.alg`.
pub const SIGNATURE_ALG: &str = "ed25519ph";

/// A signed statement about the ledger as it stood at `tip_index`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    /// `record_hash` of record 0: stable for the life of the ledger.
    pub ledger_id: String,
    /// Records covered: `tip_index + 1`.
    pub records: u64,
    pub tip_index: u64,
    /// `record_hash` of record `tip_index`.
    pub tip_hash: String,
    /// RFC 6962 root over the raw `record_hash` bytes of records 0..=tip.
    pub merkle_root: String,
    /// Optional session scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionScope>,
    /// RFC 3339 UTC, seconds precision (`2026-09-22T10:00:00Z`). The
    /// signer's clock: an anchor's time is the independent one.
    pub created_at: String,
    /// Key id of the signer (see [`crate::keys::key_id`]).
    pub signer: String,
}

/// The records of one session, among records 0..=tip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionScope {
    pub id: String,
    /// How many of the covered records belong to the session.
    pub records: u64,
    /// RFC 6962 root over those records' hashes, in ledger order.
    pub merkle_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptSignature {
    /// Always `ed25519ph`.
    pub alg: String,
    /// Signer's SPKI PEM public key (self-describing; pin it with --pubkey).
    pub public_key: String,
    /// Base64 (standard, padded) of the 64-byte signature.
    pub value: String,
}

/// External witnesses of a receipt. Not covered by the receipt signature:
/// each anchor carries its own proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Anchor {
    Rekor(RekorAnchor),
    File(FileAnchor),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub format: String,
    pub checkpoint: Checkpoint,
    pub signature: ReceiptSignature,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anchors: Vec<Anchor>,
}

fn is_rfc3339_seconds(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 20
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b'T',
            13 | 16 => *c == b':',
            19 => *c == b'Z',
            _ => c.is_ascii_digit(),
        })
}

fn check_hex(field: &str, v: &str) -> Result<()> {
    if is_hex64(v) {
        Ok(())
    } else {
        Err(invalid(format!(
            "checkpoint.{field} must be 64 lowercase hex characters, got {v:?}"
        )))
    }
}

impl Checkpoint {
    /// Reject anything that does not have exactly one canonical rendering.
    pub fn validate(&self) -> Result<()> {
        check_hex("ledger_id", &self.ledger_id)?;
        check_hex("tip_hash", &self.tip_hash)?;
        check_hex("merkle_root", &self.merkle_root)?;
        if self.records == 0 {
            return Err(invalid("checkpoint.records must be at least 1"));
        }
        if self.tip_index.checked_add(1) != Some(self.records) {
            return Err(invalid(format!(
                "checkpoint.records ({}) must equal tip_index + 1 ({} + 1)",
                self.records, self.tip_index
            )));
        }
        if self.tip_index == 0 && self.tip_hash != self.ledger_id {
            return Err(invalid(
                "checkpoint of a one-record ledger: tip_hash must equal ledger_id",
            ));
        }
        if !is_rfc3339_seconds(&self.created_at) {
            return Err(invalid(format!(
                "checkpoint.created_at must be RFC 3339 UTC with seconds precision \
                 (YYYY-MM-DDTHH:MM:SSZ), got {:?}",
                self.created_at
            )));
        }
        match self.signer.strip_prefix("ed25519:") {
            Some(h) if is_hex64(h) => {}
            _ => {
                return Err(invalid(format!(
                    "checkpoint.signer must be ed25519:<64 hex>, got {:?}",
                    self.signer
                )))
            }
        }
        if let Some(s) = &self.session {
            if s.id.is_empty() {
                return Err(invalid("checkpoint.session.id must not be empty"));
            }
            if s.records == 0 || s.records > self.records {
                return Err(invalid(format!(
                    "checkpoint.session.records must be in 1..={}, got {}",
                    self.records, s.records
                )));
            }
            check_hex("session.merkle_root", &s.merkle_root)?;
        }
        Ok(())
    }

    /// The exact bytes that are hashed and signed. LF line endings, ASCII:
    ///
    /// ```text
    /// writ.receipt.checkpoint.v1
    /// ledger_id <64 hex>
    /// records <decimal>
    /// tip_index <decimal>
    /// tip_hash <64 hex>
    /// merkle_root <64 hex>
    /// session -                                   (unscoped), or
    /// session <hex of UTF-8 id> <decimal> <64 hex> (scoped)
    /// created_at <YYYY-MM-DDTHH:MM:SSZ>
    /// signer ed25519:<64 hex>
    /// ```
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let session = match &self.session {
            None => "-".to_string(),
            Some(s) => format!(
                "{} {} {}",
                hex::encode(s.id.as_bytes()),
                s.records,
                s.merkle_root
            ),
        };
        Ok(format!(
            "{CHECKPOINT_CONTEXT}\nledger_id {}\nrecords {}\ntip_index {}\ntip_hash {}\n\
             merkle_root {}\nsession {}\ncreated_at {}\nsigner {}\n",
            self.ledger_id,
            self.records,
            self.tip_index,
            self.tip_hash,
            self.merkle_root,
            session,
            self.created_at,
            self.signer
        )
        .into_bytes())
    }
}

/// Ed25519ph prehash of `msg`.
pub(crate) fn prehash(msg: &[u8]) -> Sha512 {
    let mut h = Sha512::new();
    h.update(msg);
    h
}

impl Receipt {
    /// Sign `checkpoint` (its `signer` is overwritten with `key`'s id).
    pub fn sign(mut checkpoint: Checkpoint, key: &SigningKey) -> Result<Receipt> {
        let vk = key.verifying_key();
        checkpoint.signer = key_id(&vk);
        let bytes = checkpoint.canonical_bytes()?;
        let sig = key
            .sign_prehashed(prehash(&bytes), None)
            .map_err(|e| invalid(format!("sign: {e}")))?;
        Ok(Receipt {
            format: RECEIPT_FORMAT.to_string(),
            checkpoint,
            signature: ReceiptSignature {
                alg: SIGNATURE_ALG.to_string(),
                public_key: public_pem(&vk)?,
                value: b64().encode(sig.to_bytes()),
            },
            anchors: Vec::new(),
        })
    }

    pub fn from_json(text: &str) -> Result<Receipt> {
        let r: Receipt = serde_json::from_str(text)
            .map_err(|e| invalid(format!("not a provio receipt: {e}")))?;
        if r.format != RECEIPT_FORMAT {
            return Err(invalid(format!(
                "unsupported receipt format {:?} (this provio reads {RECEIPT_FORMAT})",
                r.format
            )));
        }
        Ok(r)
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)? + "\n")
    }

    /// The embedded public key.
    pub fn embedded_key(&self) -> Result<VerifyingKey> {
        parse_public_pem(&self.signature.public_key)
            .map_err(|e| invalid(format!("signature.public_key: {e}")))
    }

    pub fn signature_bytes(&self) -> Result<[u8; 64]> {
        let raw = b64()
            .decode(self.signature.value.trim())
            .map_err(|e| invalid(format!("signature.value is not base64: {e}")))?;
        raw.try_into()
            .map_err(|_| invalid("signature.value must decode to 64 bytes"))
    }

    /// Check the signature. With `pinned`, the receipt must have been signed
    /// by that key; without it, by its embedded key (self-consistency only).
    /// Returns the key that verified.
    pub fn verify_signature(&self, pinned: Option<&VerifyingKey>) -> Result<VerifyingKey> {
        if self.signature.alg != SIGNATURE_ALG {
            return Err(invalid(format!(
                "unsupported signature.alg {:?} (expected {SIGNATURE_ALG})",
                self.signature.alg
            )));
        }
        let embedded = self.embedded_key()?;
        let key = match pinned {
            Some(p) if *p != embedded => {
                return Err(verify_err(format!(
                    "signature: receipt was signed by {}, not by the pinned key {}",
                    key_id(&embedded),
                    key_id(p)
                )))
            }
            Some(p) => *p,
            None => embedded,
        };
        if self.checkpoint.signer != key_id(&key) {
            return Err(verify_err(format!(
                "signature: checkpoint.signer {} does not match the signing key {}",
                self.checkpoint.signer,
                key_id(&key)
            )));
        }
        let bytes = self.checkpoint.canonical_bytes()?;
        let sig = Signature::from_bytes(&self.signature_bytes()?);
        key.verify_prehashed_strict(prehash(&bytes), None, &sig)
            .map_err(|_| {
                verify_err("signature: INVALID — the checkpoint was modified after signing, or the signature is not from this key")
            })?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cp() -> Checkpoint {
        Checkpoint {
            ledger_id: "a".repeat(64),
            records: 3,
            tip_index: 2,
            tip_hash: "b".repeat(64),
            merkle_root: "c".repeat(64),
            session: None,
            created_at: "2026-09-22T10:00:00Z".into(),
            signer: String::new(),
        }
    }

    #[test]
    fn canonical_bytes_are_pinned() {
        let mut c = cp();
        c.signer = format!("ed25519:{}", "d".repeat(64));
        let text = String::from_utf8(c.canonical_bytes().unwrap()).unwrap();
        let expect = format!(
            "writ.receipt.checkpoint.v1\nledger_id {a}\nrecords 3\ntip_index 2\ntip_hash {b}\n\
             merkle_root {c}\nsession -\ncreated_at 2026-09-22T10:00:00Z\nsigner ed25519:{d}\n",
            a = "a".repeat(64),
            b = "b".repeat(64),
            c = "c".repeat(64),
            d = "d".repeat(64)
        );
        assert_eq!(text, expect);
        c.session = Some(SessionScope {
            id: "s 1\n".into(),
            records: 2,
            merkle_root: "e".repeat(64),
        });
        let text = String::from_utf8(c.canonical_bytes().unwrap()).unwrap();
        assert!(text.contains(&format!("\nsession 7320310a 2 {}\n", "e".repeat(64))));
    }

    #[test]
    fn sign_verify_and_tamper() {
        let k = crate::keys::generate().unwrap();
        let r = Receipt::sign(cp(), &k).unwrap();
        let back = Receipt::from_json(&r.to_json().unwrap()).unwrap();
        assert_eq!(back, r);
        r.verify_signature(None).unwrap();
        r.verify_signature(Some(&k.verifying_key())).unwrap();

        let other = crate::keys::generate().unwrap();
        let e = r
            .verify_signature(Some(&other.verifying_key()))
            .unwrap_err();
        assert!(e.to_string().contains("not by the pinned key"), "{e}");

        let mut t = r.clone();
        t.checkpoint.records = 4;
        t.checkpoint.tip_index = 3;
        assert!(t
            .verify_signature(None)
            .unwrap_err()
            .to_string()
            .contains("INVALID"));

        // Swapping in another key (and a matching signer) does not help.
        let mut t = r.clone();
        t.signature.public_key = public_pem(&other.verifying_key()).unwrap();
        t.checkpoint.signer = key_id(&other.verifying_key());
        assert!(t.verify_signature(None).is_err());
    }

    #[test]
    fn non_canonical_fields_rejected() {
        let mut c = cp();
        c.signer = format!("ed25519:{}", "d".repeat(64));
        for bad in [
            {
                let mut x = c.clone();
                x.tip_hash = "B".repeat(64);
                x
            },
            {
                let mut x = c.clone();
                x.records = 5;
                x
            },
            {
                let mut x = c.clone();
                x.created_at = "2026-09-22T10:00:00.000Z".into();
                x
            },
            {
                let mut x = c.clone();
                x.created_at = "2026-09-22T10:00:00Z\nsigner x".into();
                x
            },
        ] {
            assert!(bad.canonical_bytes().is_err(), "{bad:?}");
        }
        let json = r#"{"ledger_id":"x","extra":1}"#;
        assert!(serde_json::from_str::<Checkpoint>(json).is_err());
    }
}
