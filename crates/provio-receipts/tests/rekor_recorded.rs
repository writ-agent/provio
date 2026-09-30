//! Offline verification of a real Rekor anchor.
//!
//! `fixtures/rekor-live/` was recorded on 2026-09-23 by the live test in
//! crates/provio-cli/tests/receipt_anchor.rs (`PROVIO_REKOR_LIVE=1
//! PROVIO_REKOR_RECORD_DIR=...`): a four-record ledger, the signer's public
//! key, and the receipt as anchored in rekor.sigstore.dev (log index
//! 2919361688). Everything here is checked against the pinned production
//! log key, with no network.

use std::path::PathBuf;

use provio_receipts::keys::read_public_key;
use provio_receipts::ledger::{check_checkpoint, read_records};
use provio_receipts::rekor::{self, PINNED_PUBLIC_KEY_PEM};
use provio_receipts::{Anchor, Receipt};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rekor-live")
        .join(name)
}

fn load() -> (Receipt, rekor::RekorAnchor) {
    let r = Receipt::from_json(&std::fs::read_to_string(fixture("receipt.json")).unwrap()).unwrap();
    let a = match &r.anchors[..] {
        [Anchor::Rekor(a)] => a.clone(),
        other => panic!("expected one rekor anchor, got {other:?}"),
    };
    (r, a)
}

fn log_key() -> p256::ecdsa::VerifyingKey {
    rekor::parse_log_key(PINNED_PUBLIC_KEY_PEM).unwrap()
}

#[test]
fn recorded_receipt_signature_and_checkpoint_hold() {
    let (r, _) = load();
    let signer = read_public_key(&fixture("signer.pub")).unwrap();
    r.verify_signature(Some(&signer)).unwrap();
    let status = check_checkpoint(
        &r.checkpoint,
        read_records(&fixture("ledger.jsonl")).unwrap(),
    )
    .unwrap();
    assert_eq!(status.appended_after, 0);
    assert_eq!(r.checkpoint.records, 4);
}

#[test]
fn recorded_rekor_anchor_verifies_against_pinned_key() {
    let (r, a) = load();
    assert_eq!(a.url, rekor::DEFAULT_URL);
    assert_eq!(a.log_id, rekor::PINNED_LOG_ID);
    let v = rekor::verify_anchor(&a, &r, &log_key()).unwrap();
    assert_eq!(v.log_index, 2_919_361_688);
    assert!(v.inclusion_tree_size.unwrap() > 2_797_000_000);
    // The same key is what `trusted_log_key` hands out for the default URL.
    let k = rekor::trusted_log_key(&a.url, None).unwrap().unwrap();
    assert_eq!(k, log_key());
}

#[test]
fn recorded_anchor_rejects_any_edit() {
    let (r, a) = load();
    let key = log_key();

    let mut x = a.clone();
    x.integrated_time += 1;
    assert!(rekor::verify_anchor(&x, &r, &key)
        .unwrap_err()
        .to_string()
        .contains("signed entry timestamp"));

    let mut x = a.clone();
    let p = x.inclusion_proof.as_mut().unwrap();
    p.tree_size += 1;
    assert!(rekor::verify_anchor(&x, &r, &key).is_err());

    let mut x = a.clone();
    let p = x.inclusion_proof.as_mut().unwrap();
    p.hashes.swap(0, 1);
    assert!(rekor::verify_anchor(&x, &r, &key)
        .unwrap_err()
        .to_string()
        .contains("inclusion proof"));

    // The anchor does not transfer to a different checkpoint.
    let mut other = r.clone();
    other.checkpoint.created_at = "2026-01-01T00:00:00Z".into();
    assert!(rekor::verify_anchor(&a, &other, &key)
        .unwrap_err()
        .to_string()
        .contains("digest"));

    // A key that is not Rekor's.
    let fake = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
    assert!(rekor::verify_anchor(&a, &r, fake.verifying_key())
        .unwrap_err()
        .to_string()
        .contains("logID"));
}

#[test]
fn recorded_ledger_tamper_is_detected() {
    let (r, _) = load();
    let text = std::fs::read_to_string(fixture("ledger.jsonl")).unwrap();
    let tampered = text.replacen("\"exit_status\":0", "\"exit_status\":1", 1);
    assert_ne!(tampered, text);
    let dir = std::env::temp_dir().join(format!("provio-receipts-recorded-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ledger.jsonl");
    std::fs::write(&path, tampered).unwrap();
    let err = check_checkpoint(&r.checkpoint, read_records(&path).unwrap()).unwrap_err();
    assert!(err.to_string().contains("record 1 was altered"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}
