//! Anchoring a receipt in the Sigstore Rekor transparency log (API v1,
//! `hashedrekord` v0.0.1) and verifying the anchor offline.
//!
//! Submission (`POST {url}/api/v1/log/entries`):
//!
//! ```json
//! {"apiVersion":"0.0.1","kind":"hashedrekord","spec":{
//!   "data":{"hash":{"algorithm":"sha512","value":"<hex sha512(canonical checkpoint bytes)>"}},
//!   "signature":{"content":"<base64 Ed25519ph signature>",
//!                "publicKey":{"content":"<base64 of the SPKI PEM public key>"}}}}
//! ```
//!
//! Rekor accepts Ed25519 keys in `hashedrekord` only as Ed25519ph with a
//! SHA-512 digest (Rekor >= 1.3.6), which is why receipts are signed with
//! Ed25519ph and the entry carries SHA-512 rather than SHA-256.
//!
//! Offline verification of a stored anchor, against the log's public key
//! (pinned for `rekor.sigstore.dev`, supplied by the user otherwise):
//! 1. the entry body is a `hashedrekord` of this receipt's digest,
//!    signature and public key, and the UUID ends in its leaf hash;
//! 2. the signed entry timestamp (SET) — ECDSA P-256 over the canonical
//!    JSON `{"body","integratedTime","logID","logIndex"}` — verifies, and
//!    `logID` is the SHA-256 of the log key;
//! 3. when stored, the RFC 6962 inclusion proof leads from the entry's
//!    leaf hash to `rootHash`, and the checkpoint (a signed note) carries
//!    that root and tree size under a valid log signature.

use std::time::Duration;

use base64::Engine as _;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature as EcdsaSignature, VerifyingKey as LogKey};
use p256::pkcs8::{DecodePublicKey as _, EncodePublicKey as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

use crate::keys::parse_public_pem;
use crate::merkle::{self, Hash};
use crate::receipt::Receipt;
use crate::{b64, hex32, invalid, verify_err, Error, Result};

pub const DEFAULT_URL: &str = "https://rekor.sigstore.dev";

/// Public key of the production log at rekor.sigstore.dev (ECDSA P-256),
/// as served by `GET /api/v1/log/publicKey` and distributed through the
/// Sigstore TUF root. Its SHA-256 (the log ID) is [`PINNED_LOG_ID`].
pub const PINNED_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----
";

pub const PINNED_LOG_ID: &str = "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d";

/// Stored in the receipt: everything needed to verify the anchor offline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RekorAnchor {
    pub url: String,
    pub uuid: String,
    /// Hex SHA-256 of the log's DER public key.
    pub log_id: String,
    /// Global log index (across shards).
    pub log_index: u64,
    /// Unix seconds at which the log integrated the entry.
    pub integrated_time: i64,
    /// The canonicalized entry body, base64, exactly as the log returned it.
    pub body: String,
    /// Base64 DER ECDSA signature by the log (the SET).
    pub signed_entry_timestamp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inclusion_proof: Option<RekorInclusionProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RekorInclusionProof {
    /// Index within the (shard's) tree the proof is for.
    pub log_index: u64,
    pub root_hash: String,
    pub tree_size: u64,
    /// Hex sibling hashes, leaf to root.
    pub hashes: Vec<String>,
    /// Signed note: origin, tree size, base64 root, then signatures.
    pub checkpoint: String,
}

// ---- wire format ---------------------------------------------------------

#[derive(Deserialize)]
struct WireEntry {
    body: String,
    #[serde(rename = "integratedTime")]
    integrated_time: i64,
    #[serde(rename = "logID")]
    log_id: String,
    #[serde(rename = "logIndex")]
    log_index: u64,
    verification: Option<WireVerification>,
}

#[derive(Deserialize)]
struct WireVerification {
    #[serde(rename = "inclusionProof")]
    inclusion_proof: Option<WireProof>,
    #[serde(rename = "signedEntryTimestamp")]
    signed_entry_timestamp: Option<String>,
}

#[derive(Deserialize)]
struct WireProof {
    #[serde(rename = "logIndex")]
    log_index: u64,
    #[serde(rename = "rootHash")]
    root_hash: String,
    #[serde(rename = "treeSize")]
    tree_size: u64,
    hashes: Vec<String>,
    checkpoint: Option<String>,
}

/// SET payload; field order is the RFC 8785 (JCS) key order Rekor signs.
#[derive(Serialize)]
struct SetPayload<'a> {
    body: &'a str,
    #[serde(rename = "integratedTime")]
    integrated_time: i64,
    #[serde(rename = "logID")]
    log_id: &'a str,
    #[serde(rename = "logIndex")]
    log_index: u64,
}

/// The `hashedrekord` v0.0.1 proposed entry for `receipt`.
pub fn proposed_entry(receipt: &Receipt) -> Result<serde_json::Value> {
    let digest = hex::encode(Sha512::digest(receipt.checkpoint.canonical_bytes()?));
    Ok(serde_json::json!({
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": { "hash": { "algorithm": "sha512", "value": digest } },
            "signature": {
                "content": receipt.signature.value,
                "publicKey": { "content": b64().encode(receipt.signature.public_key.as_bytes()) }
            }
        }
    }))
}

/// Parse a `{ "<uuid>": LogEntry }` response.
pub fn parse_log_entry_response(url: &str, text: &str) -> Result<RekorAnchor> {
    let map: std::collections::BTreeMap<String, WireEntry> = serde_json::from_str(text)
        .map_err(|e| Error::Rekor(format!("unexpected log entry response: {e}")))?;
    let mut it = map.into_iter();
    let (uuid, e) = match (it.next(), it.next()) {
        (Some(x), None) => x,
        _ => {
            return Err(Error::Rekor(
                "expected exactly one log entry in the response".into(),
            ))
        }
    };
    let v = e
        .verification
        .ok_or_else(|| Error::Rekor("log entry has no verification object".into()))?;
    let set = v
        .signed_entry_timestamp
        .ok_or_else(|| Error::Rekor("log entry has no signedEntryTimestamp".into()))?;
    let inclusion_proof = match v.inclusion_proof {
        Some(p) => Some(RekorInclusionProof {
            log_index: p.log_index,
            root_hash: p.root_hash,
            tree_size: p.tree_size,
            hashes: p.hashes,
            checkpoint: p
                .checkpoint
                .ok_or_else(|| Error::Rekor("inclusion proof has no checkpoint".into()))?,
        }),
        None => None,
    };
    Ok(RekorAnchor {
        url: url.to_string(),
        uuid,
        log_id: e.log_id,
        log_index: e.log_index,
        integrated_time: e.integrated_time,
        body: e.body,
        signed_entry_timestamp: set,
        inclusion_proof,
    })
}

fn normalize(url: &str) -> &str {
    url.trim_end_matches('/')
}

pub fn parse_log_key(pem: &str) -> Result<LogKey> {
    LogKey::from_public_key_pem(pem.trim())
        .map_err(|e| invalid(format!("not an ECDSA P-256 SPKI PEM public key: {e}")))
}

/// Hex SHA-256 of the key's DER SPKI encoding (Rekor's log ID).
pub fn log_id_of(key: &LogKey) -> Result<String> {
    let der = key
        .to_public_key_der()
        .map_err(|e| invalid(format!("encode log key: {e}")))?;
    Ok(hex::encode(Sha256::digest(der.as_bytes())))
}

/// The key to trust for `url`: `override_pem` if given, the pinned key for
/// rekor.sigstore.dev, otherwise none (the caller must supply one).
pub fn trusted_log_key(url: &str, override_pem: Option<&str>) -> Result<Option<LogKey>> {
    if let Some(pem) = override_pem {
        return parse_log_key(pem).map(Some);
    }
    if normalize(url) == DEFAULT_URL {
        return parse_log_key(PINNED_PUBLIC_KEY_PEM).map(Some);
    }
    Ok(None)
}

fn agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(timeout))
        .user_agent(concat!("provio/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

fn http_err(e: ureq::Error) -> Error {
    Error::Rekor(format!("request failed: {e}"))
}

/// `GET {url}/api/v1/log/publicKey` (used only when no key is pinned).
pub fn fetch_log_key(url: &str, timeout: Duration) -> Result<LogKey> {
    let endpoint = format!("{}/api/v1/log/publicKey", normalize(url));
    let mut resp = agent(timeout).get(&endpoint).call().map_err(http_err)?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().map_err(http_err)?;
    if status != 200 {
        return Err(Error::Rekor(format!(
            "GET {endpoint}: HTTP {status}: {}",
            snippet(&text)
        )));
    }
    parse_log_key(&text)
}

fn snippet(s: &str) -> String {
    let s = s.trim();
    if s.len() > 300 {
        format!(
            "{}…",
            &s[..s.char_indices().nth(300).map(|x| x.0).unwrap_or(s.len())]
        )
    } else {
        s.to_string()
    }
}

/// Submit `receipt` and return the anchor as the log reported it. On HTTP
/// 409 (already logged) the existing entry is fetched. The anchor is not
/// yet verified; call [`verify_anchor`].
pub fn submit(url: &str, receipt: &Receipt, timeout: Duration) -> Result<RekorAnchor> {
    let base = normalize(url);
    let endpoint = format!("{base}/api/v1/log/entries");
    let body = serde_json::to_vec(&proposed_entry(receipt)?)?;
    let agent = agent(timeout);
    let mut resp = agent
        .post(&endpoint)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .send(&body[..])
        .map_err(http_err)?;
    let status = resp.status().as_u16();
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let text = resp.body_mut().read_to_string().map_err(http_err)?;
    match status {
        200 | 201 => parse_log_entry_response(base, &text),
        409 => {
            let loc = location.ok_or_else(|| {
                Error::Rekor("HTTP 409 (entry exists) without a Location header".into())
            })?;
            let get_url = if loc.starts_with("http://") || loc.starts_with("https://") {
                loc
            } else {
                format!("{base}{loc}")
            };
            let mut resp = agent.get(&get_url).call().map_err(http_err)?;
            let st = resp.status().as_u16();
            let text = resp.body_mut().read_to_string().map_err(http_err)?;
            if st != 200 {
                return Err(Error::Rekor(format!(
                    "GET {get_url}: HTTP {st}: {}",
                    snippet(&text)
                )));
            }
            parse_log_entry_response(base, &text)
        }
        _ => Err(Error::Rekor(format!(
            "POST {endpoint}: HTTP {status}: {}",
            snippet(&text)
        ))),
    }
}

/// What a verified Rekor anchor establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekorVerified {
    pub log_index: u64,
    pub integrated_time: i64,
    /// Tree size of the verified inclusion proof, if one was stored.
    pub inclusion_tree_size: Option<u64>,
}

fn ecdsa_sig(der: &[u8], what: &str) -> Result<EcdsaSignature> {
    EcdsaSignature::from_der(der)
        .map_err(|e| verify_err(format!("{what} is not a DER ECDSA signature: {e}")))
}

/// Verify a stored anchor offline against `log_key`.
pub fn verify_anchor(
    a: &RekorAnchor,
    receipt: &Receipt,
    log_key: &LogKey,
) -> Result<RekorVerified> {
    let fail = |m: String| {
        Err(verify_err(format!(
            "rekor anchor (log index {}): {m}",
            a.log_index
        )))
    };

    // 1. The entry is this receipt.
    let body_bytes = match b64().decode(a.body.trim()) {
        Ok(b) => b,
        Err(e) => return fail(format!("body is not base64: {e}")),
    };
    let body: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => return fail(format!("body is not JSON: {e}")),
    };
    if body["kind"] != "hashedrekord" || body["apiVersion"] != "0.0.1" {
        return fail(format!(
            "entry is {} {}, expected hashedrekord 0.0.1",
            body["kind"], body["apiVersion"]
        ));
    }
    let spec = &body["spec"];
    let want_digest = hex::encode(Sha512::digest(receipt.checkpoint.canonical_bytes()?));
    if spec["data"]["hash"]["algorithm"] != "sha512"
        || spec["data"]["hash"]["value"].as_str() != Some(want_digest.as_str())
    {
        return fail("the logged digest is not this receipt's checkpoint digest".into());
    }
    let logged_sig = spec["signature"]["content"]
        .as_str()
        .and_then(|s| b64().decode(s).ok());
    if logged_sig.as_deref() != Some(&receipt.signature_bytes()?[..]) {
        return fail("the logged signature is not this receipt's signature".into());
    }
    let logged_key = spec["signature"]["publicKey"]["content"]
        .as_str()
        .and_then(|s| b64().decode(s).ok())
        .and_then(|pem| String::from_utf8(pem).ok())
        .and_then(|pem| parse_public_pem(&pem).ok());
    if logged_key != Some(receipt.embedded_key()?) {
        return fail("the logged public key is not this receipt's signing key".into());
    }
    let leaf: Hash = merkle::leaf_hash(&body_bytes);
    let leaf_hex = hex::encode(leaf);
    if a.uuid.len() < 64 || !a.uuid.ends_with(&leaf_hex) {
        return fail(format!(
            "uuid {} does not end in the entry's leaf hash {leaf_hex}",
            a.uuid
        ));
    }

    // 2. The SET.
    let key_id = log_id_of(log_key)?;
    if a.log_id != key_id {
        return fail(format!(
            "logID {} is not the trusted log key's id {key_id}",
            a.log_id
        ));
    }
    let payload = serde_json::to_vec(&SetPayload {
        body: &a.body,
        integrated_time: a.integrated_time,
        log_id: &a.log_id,
        log_index: a.log_index,
    })?;
    let set = match b64().decode(a.signed_entry_timestamp.trim()) {
        Ok(s) => s,
        Err(e) => return fail(format!("signedEntryTimestamp is not base64: {e}")),
    };
    if log_key
        .verify(&payload, &ecdsa_sig(&set, "signedEntryTimestamp")?)
        .is_err()
    {
        return fail("signed entry timestamp does not verify against the log key".into());
    }

    // 3. Inclusion proof + signed checkpoint.
    let mut inclusion_tree_size = None;
    if let Some(p) = &a.inclusion_proof {
        let root = hex32(&p.root_hash, "inclusion_proof.root_hash")?;
        let path = p
            .hashes
            .iter()
            .map(|h| hex32(h, "inclusion_proof.hashes entry"))
            .collect::<Result<Vec<_>>>()?;
        if !merkle::verify_inclusion(&leaf, p.log_index, p.tree_size, &path, &root) {
            return fail("inclusion proof does not lead from the entry to the root hash".into());
        }
        if let Err(e) = verify_checkpoint_note(&p.checkpoint, log_key, &key_id, p.tree_size, &root)
        {
            return fail(e);
        }
        inclusion_tree_size = Some(p.tree_size);
    }
    Ok(RekorVerified {
        log_index: a.log_index,
        integrated_time: a.integrated_time,
        inclusion_tree_size,
    })
}

/// Verify a signed-note checkpoint: body `origin\nsize\nbase64(root)\n...`,
/// a blank line, then `— <name> base64(keyhint[4] || DER signature)` lines.
fn verify_checkpoint_note(
    note: &str,
    key: &LogKey,
    log_id_hex: &str,
    tree_size: u64,
    root: &Hash,
) -> std::result::Result<(), String> {
    let sep = note
        .find("\n\n")
        .ok_or("checkpoint is not a signed note (no blank line)")?;
    let text = &note[..sep + 1];
    let mut lines = text.lines();
    let _origin = lines.next().ok_or("checkpoint has no origin line")?;
    let size: u64 = lines
        .next()
        .and_then(|l| l.parse().ok())
        .ok_or("checkpoint tree size line is malformed")?;
    let croot = lines
        .next()
        .and_then(|l| b64().decode(l).ok())
        .ok_or("checkpoint root hash line is malformed")?;
    if size != tree_size || croot.as_slice() != root.as_slice() {
        return Err(format!(
            "checkpoint (size {size}) does not match the inclusion proof (size {tree_size}, root {})",
            hex::encode(root)
        ));
    }
    let hint = hex::decode(&log_id_hex[..8]).map_err(|e| e.to_string())?;
    for line in note[sep + 2..].lines() {
        let Some(rest) = line.strip_prefix("\u{2014} ") else {
            continue;
        };
        let Some((_name, sig_b64)) = rest.rsplit_once(' ') else {
            continue;
        };
        let Ok(raw) = b64().decode(sig_b64) else {
            continue;
        };
        if raw.len() <= 4 || raw[..4] != hint[..] {
            continue;
        }
        let Ok(sig) = EcdsaSignature::from_der(&raw[4..]) else {
            continue;
        };
        if key.verify(text.as_bytes(), &sig).is_ok() {
            return Ok(());
        }
        return Err("checkpoint signature does not verify against the log key".into());
    }
    Err("checkpoint carries no signature from the trusted log key".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_key_matches_log_id() {
        let k = parse_log_key(PINNED_PUBLIC_KEY_PEM).unwrap();
        assert_eq!(log_id_of(&k).unwrap(), PINNED_LOG_ID);
        assert!(trusted_log_key("https://rekor.sigstore.dev/", None)
            .unwrap()
            .is_some());
        assert!(trusted_log_key("http://127.0.0.1:1", None)
            .unwrap()
            .is_none());
    }

    /// A real signed tree head fetched from rekor.sigstore.dev
    /// (`GET /api/v1/log`, inactive shard, 2026-09-22) verifies against the
    /// pinned key.
    #[test]
    fn real_checkpoint_note_verifies() {
        let note = "rekor.sigstore.dev - 3904496407287907110\n4163431\nTQBqpG78tgfdUdkAsSE3VMUMySUcNAXGwlYdnWovMjk=\n\n\u{2014} rekor.sigstore.dev wNI9ajBGAiEAop05uMdCCpVj5WOxmNEVKz2ZfWXlt/NZ31Pbz39SqZ4CIQDl+0tLDgPh36mROrA27NtAloiezNoDY5oA/RxN1JLvUg==\n";
        let k = parse_log_key(PINNED_PUBLIC_KEY_PEM).unwrap();
        let root = hex32(
            "4d006aa46efcb607dd51d900b1213754c50cc9251c3405c6c2561d9d6a2f3239",
            "root",
        )
        .unwrap();
        verify_checkpoint_note(note, &k, PINNED_LOG_ID, 4163431, &root).unwrap();
        assert!(verify_checkpoint_note(note, &k, PINNED_LOG_ID, 4163432, &root).is_err());
        let forged = note.replace("4163431", "4163432");
        assert!(verify_checkpoint_note(&forged, &k, PINNED_LOG_ID, 4163432, &root).is_err());
    }
}
