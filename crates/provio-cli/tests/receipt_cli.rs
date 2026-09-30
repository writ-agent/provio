//! `provio receipt keygen | create | verify | prove` and file anchors,
//! driving the built binary.

mod receipt_common;

use receipt_common::{assert_fails_with, assert_ok, text, Project};
use serde_json::Value;

fn setup(
    tag: &str,
) -> (
    Project,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let p = Project::new(tag);
    p.add_calls("s-a", 3);
    p.add_calls("s-b", 2);
    let (key, pubkey) = p.keygen("signing.key");
    let r = p.create(&key, "r.json", &[]);
    (p, key, pubkey, r)
}

fn pubarg(pubkey: &std::path::Path) -> [&str; 2] {
    ["--pubkey", pubkey.to_str().unwrap()]
}

#[test]
fn keygen_writes_pem_pair_and_refuses_overwrite() {
    let p = Project::new("keygen");
    let (key, pubkey) = p.keygen("k");
    let priv_pem = std::fs::read_to_string(&key).unwrap();
    let pub_pem = std::fs::read_to_string(&pubkey).unwrap();
    assert!(priv_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(pub_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    #[cfg(windows)]
    {
        // Inherited ACEs removed; the current user has full control, and
        // nobody beyond the user, SYSTEM and Administrators (the set OpenSSH
        // accepts for private keys) has any access.
        let o = std::process::Command::new("icacls")
            .arg(&key)
            .output()
            .unwrap();
        let acl = String::from_utf8_lossy(&o.stdout);
        let user = std::env::var("USERNAME").unwrap();
        assert!(acl.contains(&format!("{user}:(F)")), "{acl}");
        assert!(!acl.contains("(I)"), "{acl}");
        for broad in ["Everyone", "Authenticated Users", "BUILTIN\\Users"] {
            assert!(!acl.contains(broad), "{broad} has access: {acl}");
        }
    }
    let again = p.provio(&["receipt", "keygen", "--out", key.to_str().unwrap()]);
    assert_fails_with(&again, "already exists");
    assert_eq!(std::fs::read_to_string(&key).unwrap(), priv_pem);
    assert_ok(&p.provio(&[
        "receipt",
        "keygen",
        "--out",
        key.to_str().unwrap(),
        "--force",
    ]));
    assert_ne!(std::fs::read_to_string(&key).unwrap(), priv_pem);
}

#[test]
fn create_and_verify_happy_path() {
    let (p, _key, pubkey, r) = setup("happy");
    let receipt: Value = serde_json::from_str(&std::fs::read_to_string(&r).unwrap()).unwrap();
    assert_eq!(receipt["format"], "writ.receipt/v1");
    assert_eq!(receipt["checkpoint"]["records"], 10);
    assert_eq!(receipt["checkpoint"]["tip_index"], 9);
    assert_eq!(receipt["signature"]["alg"], "ed25519ph");
    let recs = p.records();
    assert_eq!(
        receipt["checkpoint"]["ledger_id"],
        recs[0].record_hash.as_str()
    );
    assert_eq!(
        receipt["checkpoint"]["tip_hash"],
        recs[9].record_hash.as_str()
    );

    let o = p.verify(&r, &pubarg(&pubkey));
    assert_ok(&o);
    let out = text(&o);
    assert!(out.contains("pinned key"), "{out}");
    assert!(out.contains("records 0..=9 unchanged"), "{out}");
    assert!(out.contains("receipt OK"), "{out}");

    // Without --pubkey: passes, but says the key is not pinned.
    let o = p.verify(&r, &[]);
    assert_ok(&o);
    assert!(text(&o).contains("NOT pinned"));
}

#[test]
fn create_to_stdout() {
    let p = Project::new("stdout");
    p.add_calls("s", 1);
    let (key, _) = p.keygen("k");
    let o = p.provio(&["receipt", "create", "--key", key.to_str().unwrap()]);
    assert_ok(&o);
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["checkpoint"]["records"], 2);
}

#[test]
fn tampered_record_before_checkpoint_names_the_index() {
    let (p, _key, pubkey, r) = setup("tamper");
    let mut lines = p.lines();
    lines[4] = lines[4].replace("echo call", "rm -rf / #call");
    assert_ne!(lines[4], p.lines()[4]);
    p.write_lines(&lines);
    let o = p.verify(&r, &pubarg(&pubkey));
    assert_fails_with(&o, "record 4 was altered");
    assert!(text(&o).contains("record_hash does not match its contents"));
}

#[test]
fn rewritten_ledger_with_recomputed_chain_is_caught() {
    let (p, _key, pubkey, r) = setup("rewrite");
    // An attacker with write access edits record 2 and recomputes every
    // hash and link after it: `provio verify` passes, the receipt does not.
    let mut recs = p.records();
    recs[2].exit_status = Some(0);
    recs[2].input_hash = "0".repeat(64);
    for i in 2..recs.len() {
        if i > 0 {
            recs[i].prev_hash = recs[i - 1].record_hash.clone();
        }
        recs[i].record_hash = recs[i].compute_hash().unwrap();
    }
    p.write_records(&recs);
    assert_ok(&p.provio(&["verify"]));
    let o = p.verify(&r, &pubarg(&pubkey));
    assert_fails_with(&o, "rewritten at or before record 9");
}

#[test]
fn rewritten_from_genesis_reports_different_ledger() {
    let (p, _key, pubkey, r) = setup("genesis");
    let mut recs = p.records();
    recs[0].input_hash = "1".repeat(64);
    for i in 0..recs.len() {
        if i > 0 {
            recs[i].prev_hash = recs[i - 1].record_hash.clone();
        }
        recs[i].record_hash = recs[i].compute_hash().unwrap();
    }
    p.write_records(&recs);
    assert_fails_with(&p.verify(&r, &pubarg(&pubkey)), "different ledger");
}

#[test]
fn truncated_ledger_fails() {
    let (p, _key, pubkey, r) = setup("truncate");
    let lines = p.lines();
    p.write_lines(&lines[..7]);
    let o = p.verify(&r, &pubarg(&pubkey));
    assert_fails_with(&o, "truncated: it has 7 records, the receipt covers 10");

    // Deleting the whole ledger also fails.
    std::fs::remove_file(p.ledger()).unwrap();
    assert_fails_with(&p.verify(&r, &pubarg(&pubkey)), "no ledger");
}

#[test]
fn deleted_middle_record_fails() {
    let (p, _key, pubkey, r) = setup("delete");
    let mut lines = p.lines();
    lines.remove(3);
    p.write_lines(&lines);
    assert_fails_with(&p.verify(&r, &pubarg(&pubkey)), "record 3 was altered");
}

#[test]
fn appends_after_checkpoint_are_allowed() {
    let (p, _key, pubkey, r) = setup("append");
    p.add_calls("s-c", 2);
    let o = p.verify(&r, &pubarg(&pubkey));
    assert_ok(&o);
    assert!(text(&o).contains("4 appended since"), "{}", text(&o));
}

#[test]
fn corruption_after_checkpoint_fails_but_says_checkpoint_holds() {
    let (p, _key, pubkey, r) = setup("after");
    p.add_calls("s-c", 1);
    let mut lines = p.lines();
    lines[10] = lines[10].replace("echo call", "echo CALL");
    p.write_lines(&lines);
    let o = p.verify(&r, &pubarg(&pubkey));
    assert_fails_with(&o, "the checkpoint holds, but record 10");
    assert!(text(&o).contains("checkpoint    ok"), "{}", text(&o));
}

#[test]
fn wrong_key_fails() {
    let (p, _key, _pubkey, r) = setup("wrongkey");
    let (_k2, pub2) = p.keygen("other.key");
    assert_fails_with(&p.verify(&r, &pubarg(&pub2)), "not by the pinned key");
}

#[test]
fn modified_receipt_fails_signature() {
    let (p, _key, pubkey, r) = setup("modified");
    // Claim fewer records (as if hiding the later ones).
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&r).unwrap()).unwrap();
    let recs = p.records();
    v["checkpoint"]["records"] = 5.into();
    v["checkpoint"]["tip_index"] = 4.into();
    v["checkpoint"]["tip_hash"] = recs[4].record_hash.clone().into();
    std::fs::write(&r, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    let o = p.verify(&r, &pubarg(&pubkey));
    assert_fails_with(&o, "signature: INVALID");
    assert!(text(&o).contains("not checked"));

    // An unknown field inside the signed checkpoint is rejected outright.
    v["checkpoint"]["note"] = "x".into();
    std::fs::write(&r, serde_json::to_string(&v).unwrap()).unwrap();
    assert_fails_with(&p.verify(&r, &pubarg(&pubkey)), "unknown field");
}

#[test]
fn session_scope() {
    let (p, key, pubkey, _r) = setup("session");
    let r = p.create(&key, "rs.json", &["--session", "s-b"]);
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&r).unwrap()).unwrap();
    assert_eq!(v["checkpoint"]["session"]["id"], "s-b");
    assert_eq!(v["checkpoint"]["session"]["records"], 4);
    let o = p.verify(&r, &pubarg(&pubkey));
    assert_ok(&o);
    assert!(text(&o).contains("s-b · 4 records"), "{}", text(&o));

    let o = p.provio(&[
        "receipt",
        "create",
        "--key",
        key.to_str().unwrap(),
        "--session",
        "nope",
    ]);
    assert_fails_with(&o, "has no records");
}

#[test]
fn create_refuses_broken_or_missing_ledger() {
    let p = Project::new("refuse");
    let (key, _) = p.keygen("k");
    let o = p.provio(&["receipt", "create", "--key", key.to_str().unwrap()]);
    assert_fails_with(&o, "no ledger");
    p.add_calls("s", 2);
    let mut lines = p.lines();
    lines[1] = lines[1].replace("local-os", "docker");
    p.write_lines(&lines);
    let o = p.provio(&["receipt", "create", "--key", key.to_str().unwrap()]);
    assert_fails_with(&o, "chain broken at record 1");
}

#[test]
fn inclusion_proof_verifies_without_the_ledger() {
    let (p, _key, pubkey, r) = setup("prove");
    let call = p.records()[6].call_id.clone();
    let proof = p.file("proof.json");
    let o = p.provio(&[
        "receipt",
        "prove",
        &call,
        "--receipt",
        r.to_str().unwrap(),
        "--out",
        proof.to_str().unwrap(),
    ]);
    assert_ok(&o);
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&proof).unwrap()).unwrap();
    assert_eq!(v["format"], "writ.inclusion-proof/v1");
    assert_eq!(v["entries"].as_array().unwrap().len(), 2); // decision + execution

    std::fs::remove_file(p.ledger()).unwrap();
    let o = p.verify(&proof, &pubarg(&pubkey));
    assert_ok(&o);
    let out = text(&o);
    assert!(out.contains("record 6 (Decision) is leaf 6 of 10"), "{out}");
    assert!(
        out.contains("record 7 (Execution) is leaf 7 of 10"),
        "{out}"
    );
    assert!(out.contains("proof OK"), "{out}");

    // Edited record inside the proof.
    let mut bad = v.clone();
    bad["entries"][0]["record"]["call"]["args"]["command"] = "rm -rf /".into();
    let badp = p.file("bad1.json");
    std::fs::write(&badp, bad.to_string()).unwrap();
    assert_fails_with(&p.verify(&badp, &pubarg(&pubkey)), "record edited");

    // Record edited *and* its hash recomputed: the path no longer leads to
    // the signed root.
    let mut rec: provio_core::ledger::LedgerRecord =
        serde_json::from_value(v["entries"][0]["record"].clone()).unwrap();
    rec.rule_id = Some("forged".into());
    rec.record_hash = rec.compute_hash().unwrap();
    let mut bad = v.clone();
    bad["entries"][0]["record"] = serde_json::to_value(&rec).unwrap();
    std::fs::write(&badp, bad.to_string()).unwrap();
    assert_fails_with(
        &p.verify(&badp, &pubarg(&pubkey)),
        "does not lead to the receipt's Merkle root",
    );

    // Tampered audit path.
    let mut bad = v.clone();
    let h = bad["entries"][1]["audit_path"][0]
        .as_str()
        .unwrap()
        .to_string();
    let flipped = format!("{}{}", if h.starts_with('0') { "1" } else { "0" }, &h[1..]);
    bad["entries"][1]["audit_path"][0] = flipped.into();
    std::fs::write(&badp, bad.to_string()).unwrap();
    assert_fails_with(
        &p.verify(&badp, &pubarg(&pubkey)),
        "does not lead to the receipt's Merkle root",
    );

    // Wrong signer key.
    let (_k2, pub2) = p.keygen("other.key");
    assert_fails_with(&p.verify(&proof, &pubarg(&pub2)), "not by the pinned key");
}

#[test]
fn prove_unknown_call_or_changed_ledger_fails() {
    let (p, _key, _pubkey, r) = setup("prove-bad");
    let o = p.provio(&[
        "receipt",
        "prove",
        "no-such-call",
        "--receipt",
        r.to_str().unwrap(),
    ]);
    assert_fails_with(&o, "has no record among the 10 records");
    // A call appended after the checkpoint is not covered.
    let late = p.add_calls("s-late", 1).remove(0);
    let o = p.provio(&["receipt", "prove", &late, "--receipt", r.to_str().unwrap()]);
    assert_fails_with(&o, "has no record among the 10 records");
    // A changed ledger cannot be proved against.
    let mut lines = p.lines();
    lines[0] = lines[0].replace("echo call", "echo CALL");
    p.write_lines(&lines);
    let call = p.records()[2].call_id.clone();
    let o = p.provio(&["receipt", "prove", &call, "--receipt", r.to_str().unwrap()]);
    assert_fails_with(&o, "record 0 was altered");
}

#[test]
fn file_anchor_round_trip_and_rewrite() {
    let (p, _key, pubkey, r) = setup("fileanchor");
    let log = p.file("anchors.log");
    let o = p.provio(&[
        "receipt",
        "anchor",
        r.to_str().unwrap(),
        "--to",
        "file",
        "--anchor-log",
        log.to_str().unwrap(),
    ]);
    assert_ok(&o);
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&r).unwrap()).unwrap();
    assert_eq!(v["anchors"][0]["type"], "file");
    let o = p.verify(&r, &pubarg(&pubkey));
    assert_ok(&o);
    assert!(text(&o).contains("anchor file   ok"), "{}", text(&o));

    // A second receipt appends a second line; the first still verifies.
    let (key2, _) = p.keygen("k2");
    let r2 = p.create(&key2, "r2.json", &[]);
    assert_ok(&p.provio(&[
        "receipt",
        "anchor",
        r2.to_str().unwrap(),
        "--to",
        "file",
        "--anchor-log",
        log.to_str().unwrap(),
    ]));
    assert_eq!(std::fs::read_to_string(&log).unwrap().lines().count(), 2);
    assert_ok(&p.verify(&r, &pubarg(&pubkey)));

    // Rewriting the anchor log is detected.
    let t = std::fs::read_to_string(&log).unwrap();
    std::fs::write(&log, t.replacen("\"records\":10", "\"records\":11", 1)).unwrap();
    assert_fails_with(&p.verify(&r, &pubarg(&pubkey)), "no line with sha256");
}

#[test]
fn file_anchor_defaults_next_to_ledger() {
    let (p, _key, _pubkey, r) = setup("fileanchor-default");
    let out = p.file("anchored.json");
    assert_ok(&p.provio(&[
        "receipt",
        "anchor",
        r.to_str().unwrap(),
        "--to",
        "file",
        "--out",
        out.to_str().unwrap(),
    ]));
    assert!(p.path().join(".provio").join("anchors.log").exists());
    // --out leaves the original receipt untouched.
    let orig: Value = serde_json::from_str(&std::fs::read_to_string(&r).unwrap()).unwrap();
    assert!(orig.get("anchors").is_none());
}

#[test]
fn anchor_refuses_invalid_receipt() {
    let (p, _key, _pubkey, r) = setup("anchor-invalid");
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&r).unwrap()).unwrap();
    v["checkpoint"]["created_at"] = "2020-01-01T00:00:00Z".into();
    std::fs::write(&r, v.to_string()).unwrap();
    let o = p.provio(&["receipt", "anchor", r.to_str().unwrap(), "--to", "file"]);
    assert_fails_with(&o, "refusing to anchor");
}
