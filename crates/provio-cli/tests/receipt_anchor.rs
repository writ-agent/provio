//! `provio receipt anchor --to rekor` against a local mock Rekor (no
//! network), plus one live test against rekor.sigstore.dev gated on
//! `PROVIO_REKOR_LIVE=1`.
//!
//! The mock implements the three Rekor v1 endpoints provio uses
//! (`POST /api/v1/log/entries`, `GET /api/v1/log/entries/{uuid}`,
//! `GET /api/v1/log/publicKey`) with its own ECDSA P-256 log key: it
//! canonicalizes the proposed entry, places it in a small RFC 6962 tree,
//! signs the SET and a signed-note checkpoint exactly as Rekor does, and
//! returns the `{uuid: LogEntry}` shape Rekor returns.

mod receipt_common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{EncodePublicKey as _, LineEnding};
use provio_receipts::merkle;
use receipt_common::{assert_fails_with, assert_ok, text, Project};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Ok,
    /// First POST answers 409 + Location, as Rekor does for a duplicate.
    Conflict,
    ServerError,
    /// Returns an entry whose SET does not verify.
    BadSet,
}

struct State {
    mode: Mode,
    entries: Vec<(String, Value)>,
    posted: Vec<Value>,
}

struct MockRekor {
    url: String,
    key_pem_path: std::path::PathBuf,
    state: Arc<Mutex<State>>,
}

impl MockRekor {
    fn start(p: &Project, mode: Mode) -> MockRekor {
        let sk = SigningKey::from_slice(&Sha256::digest(b"provio mock rekor log key")).unwrap();
        let pem = sk
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let key_pem_path = p.file("mock-rekor.pub");
        std::fs::write(&key_pem_path, &pem).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State {
            mode,
            entries: Vec::new(),
            posted: Vec::new(),
        }));
        let st = Arc::clone(&state);
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { continue };
                let _ = handle(conn, &sk, &pem, &st);
            }
        });
        MockRekor {
            url,
            key_pem_path,
            state,
        }
    }

    fn posted(&self) -> Vec<Value> {
        self.state.lock().unwrap().posted.clone()
    }
}

fn respond(mut c: TcpStream, status: &str, extra: &str, body: &str) -> std::io::Result<()> {
    write!(
        c,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n{extra}\r\n{body}",
        body.len()
    )?;
    c.flush()
}

fn handle(c: TcpStream, sk: &SigningKey, pem: &str, st: &Mutex<State>) -> std::io::Result<()> {
    let mut r = BufReader::new(c.try_clone()?);
    let mut first = String::new();
    r.read_line(&mut first)?;
    let mut len = 0usize;
    loop {
        let mut h = String::new();
        r.read_line(&mut h)?;
        if h.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                len = v.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    let mut parts = first.split_whitespace();
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let mut s = st.lock().unwrap();
    match (method, path) {
        ("GET", "/api/v1/log/publicKey") => {
            drop(s);
            let mut c = c;
            write!(
                c,
                "HTTP/1.1 200 OK\r\nContent-Type: application/x-pem-file\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{pem}",
                pem.len()
            )?;
            c.flush()
        }
        ("POST", "/api/v1/log/entries") => {
            let proposed: Value = serde_json::from_slice(&body).unwrap();
            s.posted.push(proposed.clone());
            match s.mode {
                Mode::ServerError => respond(
                    c,
                    "500 Internal Server Error",
                    "",
                    r#"{"code":500,"message":"error processing entry"}"#,
                ),
                mode => {
                    let (uuid, entry) = make_entry(sk, &proposed, mode == Mode::BadSet);
                    s.entries.push((uuid.clone(), entry.clone()));
                    if mode == Mode::Conflict {
                        s.mode = Mode::Ok;
                        respond(
                            c,
                            "409 Conflict",
                            &format!("Location: /api/v1/log/entries/{uuid}\r\n"),
                            r#"{"code":409,"message":"an equivalent entry already exists"}"#,
                        )
                    } else {
                        respond(c, "201 Created", "", &entry.to_string())
                    }
                }
            }
        }
        ("GET", p) if p.starts_with("/api/v1/log/entries/") => {
            let uuid = &p["/api/v1/log/entries/".len()..];
            match s.entries.iter().find(|(u, _)| u == uuid) {
                Some((_, e)) => respond(c, "200 OK", "", &e.to_string()),
                None => respond(c, "404 Not Found", "", r#"{"code":404}"#),
            }
        }
        _ => respond(c, "404 Not Found", "", r#"{"code":404}"#),
    }
}

/// A Rekor-shaped `{uuid: LogEntry}` for `proposed`, at shard index 5 of a
/// 6-leaf tree, global log index 777.
fn make_entry(sk: &SigningKey, proposed: &Value, bad_set: bool) -> (String, Value) {
    let body_bytes = serde_json::to_vec(proposed).unwrap();
    let body = b64(&body_bytes);
    let leaf = merkle::leaf_hash(&body_bytes);
    let mut leaves: Vec<merkle::Hash> = (0u8..5).map(|i| merkle::leaf_hash(&[i])).collect();
    leaves.push(leaf);
    let root = merkle::root(&leaves);
    let path = merkle::inclusion_path(&leaves, 5).unwrap();
    let der = sk.verifying_key().to_public_key_der().unwrap();
    let key_hash = Sha256::digest(der.as_bytes());
    let log_id = hex::encode(key_hash);
    let integrated = 1_790_000_000i64;
    let payload = format!(
        r#"{{"body":"{body}","integratedTime":{integrated},"logID":"{log_id}","logIndex":777}}"#
    );
    let sig: Signature = sk.sign(payload.as_bytes());
    let mut set = sig.to_der().as_bytes().to_vec();
    if bad_set {
        let n = set.len();
        set[n - 1] ^= 1;
    }
    let note = format!("mock.rekor - 42\n6\n{}\n", b64(&root));
    let nsig: Signature = sk.sign(note.as_bytes());
    let mut hinted = key_hash[..4].to_vec();
    hinted.extend_from_slice(nsig.to_der().as_bytes());
    let checkpoint = format!("{note}\n\u{2014} mock.rekor {}\n", b64(&hinted));
    let uuid = format!("24296fb24b8ad77a{}", hex::encode(leaf));
    let entry = serde_json::json!({
        uuid.clone(): {
            "body": body,
            "integratedTime": integrated,
            "logID": log_id,
            "logIndex": 777,
            "verification": {
                "inclusionProof": {
                    "checkpoint": checkpoint,
                    "hashes": path.iter().map(hex::encode).collect::<Vec<_>>(),
                    "logIndex": 5,
                    "rootHash": hex::encode(root),
                    "treeSize": 6
                },
                "signedEntryTimestamp": b64(&set)
            }
        }
    });
    (uuid, entry)
}

fn setup(tag: &str) -> (Project, std::path::PathBuf, std::path::PathBuf) {
    let p = Project::new(tag);
    p.add_calls("s", 2);
    let (key, pubkey) = p.keygen("k");
    let r = p.create(&key, "r.json", &[]);
    (p, pubkey, r)
}

fn anchor(p: &Project, r: &std::path::Path, m: &MockRekor, with_key: bool) -> std::process::Output {
    let mut args = vec![
        "receipt".to_string(),
        "anchor".into(),
        r.display().to_string(),
        "--to".into(),
        "rekor".into(),
        "--url".into(),
        m.url.clone(),
    ];
    if with_key {
        args.push("--rekor-pubkey".into());
        args.push(m.key_pem_path.display().to_string());
    }
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    p.provio(&a)
}

fn verify_args<'a>(pubkey: &'a std::path::Path, m: &'a MockRekor) -> Vec<&'a str> {
    vec![
        "--pubkey",
        pubkey.to_str().unwrap(),
        "--rekor-pubkey",
        m.key_pem_path.to_str().unwrap(),
    ]
}

fn read(r: &std::path::Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(r).unwrap()).unwrap()
}

#[test]
fn anchor_submits_hashedrekord_and_verifies_offline() {
    let (p, pubkey, r) = setup("rekor-ok");
    let m = MockRekor::start(&p, Mode::Ok);
    let o = anchor(&p, &r, &m, true);
    assert_ok(&o);
    assert!(text(&o).contains("log index 777"), "{}", text(&o));

    // What was submitted: hashedrekord v0.0.1, SHA-512 of the canonical
    // checkpoint, the receipt's own signature and SPKI PEM key.
    let posted = m.posted();
    assert_eq!(posted.len(), 1);
    let e = &posted[0];
    assert_eq!(e["kind"], "hashedrekord");
    assert_eq!(e["apiVersion"], "0.0.1");
    assert_eq!(e["spec"]["data"]["hash"]["algorithm"], "sha512");
    let rec = read(&r);
    assert_eq!(e["spec"]["signature"]["content"], rec["signature"]["value"]);
    let pem = base64::engine::general_purpose::STANDARD
        .decode(
            e["spec"]["signature"]["publicKey"]["content"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    assert_eq!(
        String::from_utf8(pem).unwrap(),
        rec["signature"]["public_key"]
    );
    let receipt =
        provio_receipts::Receipt::from_json(&std::fs::read_to_string(&r).unwrap()).unwrap();
    let digest = hex::encode(Sha512::digest(
        receipt.checkpoint.canonical_bytes().unwrap(),
    ));
    assert_eq!(e["spec"]["data"]["hash"]["value"], digest.as_str());

    // Stored anchor.
    let a = &rec["anchors"][0];
    assert_eq!(a["type"], "rekor");
    assert_eq!(a["log_index"], 777);
    assert_eq!(a["inclusion_proof"]["tree_size"], 6);

    // Offline verification (the mock can go away).
    drop(m);
    let m2 = MockRekor::start(&p, Mode::ServerError);
    let o = p.verify(&r, &verify_args(&pubkey, &m2));
    assert_ok(&o);
    let out = text(&o);
    assert!(out.contains("anchor rekor  ok"), "{out}");
    assert!(out.contains("SET ok"), "{out}");
    assert!(out.contains("inclusion proof ok (tree size 6)"), "{out}");
    assert!(m2.posted().is_empty(), "verify must not talk to the log");

    // A custom log URL has no pinned key: verify says so.
    assert_fails_with(
        &p.verify(&r, &["--pubkey", pubkey.to_str().unwrap()]),
        "no trusted key",
    );
}

#[test]
fn verify_rejects_other_log_key_and_tampered_anchor() {
    let (p, pubkey, r) = setup("rekor-tamper");
    let m = MockRekor::start(&p, Mode::Ok);
    assert_ok(&anchor(&p, &r, &m, true));
    let good = read(&r);

    // The real Rekor key is not the key that signed this anchor.
    let real = p.file("real-rekor.pub");
    std::fs::write(&real, provio_receipts::rekor::PINNED_PUBLIC_KEY_PEM).unwrap();
    let o = p.verify(
        &r,
        &[
            "--pubkey",
            pubkey.to_str().unwrap(),
            "--rekor-pubkey",
            real.to_str().unwrap(),
        ],
    );
    assert_fails_with(&o, "is not the trusted log key's id");

    type Mutation = Box<dyn Fn(&mut Value)>;
    let cases: Vec<(&str, Mutation, &str)> = vec![
        (
            "integrated_time",
            Box::new(|v: &mut Value| v["anchors"][0]["integrated_time"] = 1.into()),
            "signed entry timestamp does not verify",
        ),
        (
            "log_index",
            Box::new(|v: &mut Value| v["anchors"][0]["log_index"] = 778.into()),
            "signed entry timestamp does not verify",
        ),
        (
            "inclusion hash",
            Box::new(|v: &mut Value| {
                let h = v["anchors"][0]["inclusion_proof"]["hashes"][0]
                    .as_str()
                    .unwrap()
                    .to_string();
                let f = format!("{}{}", if h.starts_with('0') { "1" } else { "0" }, &h[1..]);
                v["anchors"][0]["inclusion_proof"]["hashes"][0] = f.into();
            }),
            "inclusion proof does not lead",
        ),
        (
            "checkpoint",
            Box::new(|v: &mut Value| {
                let c = v["anchors"][0]["inclusion_proof"]["checkpoint"]
                    .as_str()
                    .unwrap()
                    .replacen("mock.rekor - 42", "mock.rekor - 43", 1);
                v["anchors"][0]["inclusion_proof"]["checkpoint"] = c.into();
            }),
            "checkpoint signature does not verify",
        ),
        (
            "uuid",
            Box::new(|v: &mut Value| v["anchors"][0]["uuid"] = "24296fb24b8ad77a00".into()),
            "does not end in the entry's leaf hash",
        ),
    ];
    for (name, mutate, needle) in cases {
        let mut v = good.clone();
        mutate(&mut v);
        std::fs::write(&r, v.to_string()).unwrap();
        let o = p.verify(&r, &verify_args(&pubkey, &m));
        assert_eq!(o.status.code(), Some(1), "{name}: {}", text(&o));
        assert!(text(&o).contains(needle), "{name}: {}", text(&o));
    }
}

#[test]
fn anchor_from_one_receipt_does_not_fit_another() {
    let (p, pubkey, r) = setup("rekor-transplant");
    let m = MockRekor::start(&p, Mode::Ok);
    assert_ok(&anchor(&p, &r, &m, true));
    p.add_calls("s", 1);
    let r2 = p.create(&p.file("k"), "r2.json", &[]);
    let mut v2 = read(&r2);
    v2["anchors"] = read(&r)["anchors"].clone();
    std::fs::write(&r2, v2.to_string()).unwrap();
    assert_fails_with(
        &p.verify(&r2, &verify_args(&pubkey, &m)),
        "not this receipt's checkpoint digest",
    );
}

#[test]
fn conflict_fetches_existing_entry() {
    let (p, pubkey, r) = setup("rekor-409");
    let m = MockRekor::start(&p, Mode::Conflict);
    assert_ok(&anchor(&p, &r, &m, true));
    assert_ok(&p.verify(&r, &verify_args(&pubkey, &m)));
}

#[test]
fn log_errors_leave_receipt_untouched() {
    let (p, _pubkey, r) = setup("rekor-500");
    let before = std::fs::read_to_string(&r).unwrap();
    let m = MockRekor::start(&p, Mode::ServerError);
    assert_fails_with(&anchor(&p, &r, &m, true), "HTTP 500");
    assert_eq!(std::fs::read_to_string(&r).unwrap(), before);

    let m = MockRekor::start(&p, Mode::BadSet);
    assert_fails_with(&anchor(&p, &r, &m, true), "does not verify");
    assert_eq!(std::fs::read_to_string(&r).unwrap(), before);

    // Nothing listening.
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", l.local_addr().unwrap())
    };
    let o = p.provio(&[
        "receipt",
        "anchor",
        r.to_str().unwrap(),
        "--to",
        "rekor",
        "--url",
        &dead,
    ]);
    assert_fails_with(&o, "request failed");
    assert_eq!(std::fs::read_to_string(&r).unwrap(), before);
}

#[test]
fn unpinned_log_key_is_fetched_with_a_warning() {
    let (p, pubkey, r) = setup("rekor-fetch");
    let m = MockRekor::start(&p, Mode::Ok);
    let o = anchor(&p, &r, &m, false);
    assert_ok(&o);
    assert!(text(&o).contains("no pinned key"), "{}", text(&o));
    assert_ok(&p.verify(&r, &verify_args(&pubkey, &m)));
}

/// Live: submit to rekor.sigstore.dev and verify against the pinned key.
/// Run with `PROVIO_REKOR_LIVE=1`. With `PROVIO_REKOR_RECORD_DIR=<dir>` the
/// ledger, public key and anchored receipt are copied there (this is how
/// crates/provio-receipts/tests/fixtures/rekor-live was recorded).
#[test]
fn live_rekor_anchor() {
    if std::env::var("PROVIO_REKOR_LIVE").ok().as_deref() != Some("1") {
        eprintln!("skipped: set PROVIO_REKOR_LIVE=1 to anchor in rekor.sigstore.dev");
        return;
    }
    let (p, pubkey, r) = setup("rekor-live");
    let o = p.provio(&["receipt", "anchor", r.to_str().unwrap(), "--to", "rekor"]);
    assert_ok(&o);
    eprintln!("{}", text(&o));
    let o = p.verify(&r, &["--pubkey", pubkey.to_str().unwrap()]);
    eprintln!("{}", text(&o));
    assert_ok(&o);
    assert!(text(&o).contains("anchor rekor  ok"));
    if let Ok(dir) = std::env::var("PROVIO_REKOR_RECORD_DIR") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::copy(p.ledger(), dir.join("ledger.jsonl")).unwrap();
        std::fs::copy(&pubkey, dir.join("signer.pub")).unwrap();
        std::fs::copy(&r, dir.join("receipt.json")).unwrap();
    }
}
