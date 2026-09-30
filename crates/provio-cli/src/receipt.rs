//! `provio receipt`: signed receipts over the ledger, inclusion proofs, and
//! external anchoring (docs/receipts.md, Contract 7).
//!
//! Every failing check is printed on its own line naming what broke, and the
//! command exits 1; exit 0 means every check that was run passed.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use provio_receipts::keys::{self, VerifyingKey};
use provio_receipts::proof::{self, InclusionProof, PROOF_FORMAT};
use provio_receipts::{file_anchor, ledger, rekor, Anchor, Receipt};

const REKOR_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum AnchorTarget {
    /// Sigstore Rekor transparency log (hashedrekord entry).
    Rekor,
    /// Append a line to a local anchor log you ship to storage you trust.
    File,
}

#[derive(Clone, Debug, clap::Subcommand)]
pub enum ReceiptCmd {
    /// Create an Ed25519 signing key pair (PKCS#8 PEM + `<out>.pub` SPKI PEM).
    Keygen {
        /// Where to write the private key (the public key goes to `<out>.pub`).
        #[arg(long)]
        out: PathBuf,
        /// Overwrite existing key files.
        #[arg(long)]
        force: bool,
    },
    /// Sign a receipt over the ledger (optionally scoped to one session) as
    /// it stands now.
    Create {
        /// Private key from `provio receipt keygen`.
        #[arg(long)]
        key: PathBuf,
        /// Also commit to this session's records.
        #[arg(long)]
        session: Option<String>,
        /// Write the receipt here (default: stdout).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify a receipt (or an inclusion proof from `provio receipt prove`)
    /// against the ledger, the signer's public key and its anchors.
    Verify {
        /// Receipt or proof file.
        receipt: PathBuf,
        /// Signer's public key. Without it only self-consistency is checked.
        #[arg(long)]
        pubkey: Option<PathBuf>,
        /// Log public key (PEM) for a Rekor instance other than
        /// rekor.sigstore.dev, whose key is pinned in provio.
        #[arg(long)]
        rekor_pubkey: Option<PathBuf>,
        /// Copy of the anchor log to check file anchors against (default:
        /// the path recorded in the anchor).
        #[arg(long)]
        anchor_log: Option<PathBuf>,
    },
    /// Anchor a receipt externally and record the proof in the receipt.
    Anchor {
        receipt: PathBuf,
        #[arg(long, value_enum)]
        to: AnchorTarget,
        /// Rekor base URL.
        #[arg(long, default_value = rekor::DEFAULT_URL)]
        url: String,
        /// Log public key (PEM) for a Rekor instance other than rekor.sigstore.dev.
        #[arg(long)]
        rekor_pubkey: Option<PathBuf>,
        /// Anchor log for `--to file` (default: `anchors.log` next to the ledger).
        #[arg(long)]
        anchor_log: Option<PathBuf>,
        /// Write the anchored receipt here (default: update it in place).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Prove that one call's records are covered by a receipt, without
    /// shipping the ledger.
    Prove {
        call_id: String,
        /// The receipt to prove against.
        #[arg(long)]
        receipt: PathBuf,
        /// Write the proof here (default: stdout).
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

pub fn run(_policy: &Path, ledger: &Path, sub: &ReceiptCmd) -> Result<()> {
    match sub {
        ReceiptCmd::Keygen { out, force } => keygen(out, *force),
        ReceiptCmd::Create { key, session, out } => {
            create(ledger, key, session.as_deref(), out.as_deref())
        }
        ReceiptCmd::Verify {
            receipt,
            pubkey,
            rekor_pubkey,
            anchor_log,
        } => verify(
            ledger,
            receipt,
            pubkey.as_deref(),
            rekor_pubkey.as_deref(),
            anchor_log.as_deref(),
        ),
        ReceiptCmd::Anchor {
            receipt,
            to,
            url,
            rekor_pubkey,
            anchor_log,
            out,
        } => anchor(
            ledger,
            receipt,
            *to,
            url,
            rekor_pubkey.as_deref(),
            anchor_log.as_deref(),
            out.as_deref(),
        ),
        ReceiptCmd::Prove {
            call_id,
            receipt,
            out,
        } => prove(ledger, call_id, receipt, out.as_deref()),
    }
}

fn e(err: provio_receipts::Error) -> anyhow::Error {
    anyhow!(err.to_string())
}

fn keygen(out: &Path, force: bool) -> Result<()> {
    let key = keys::generate().map_err(e)?;
    let w = keys::write_keypair(&key, out, force).map_err(e)?;
    println!("private key  {}", w.private.display());
    println!("public key   {}", w.public.display());
    println!("key id       {}", w.key_id);
    match w.permission_warning {
        Some(warn) => eprintln!(
            "warning: {warn}. Restrict {} to your user yourself.",
            w.private.display()
        ),
        None if cfg!(windows) => {
            println!("permissions  private key ACL: current user only (icacls)")
        }
        None => println!("permissions  private key mode 0600"),
    }
    Ok(())
}

/// Write to `path` atomically (temp file in the same directory, then rename).
fn write_atomic(path: &Path, text: &str) -> Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".tmp{}", std::process::id()));
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, text).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

fn emit(out: Option<&Path>, text: &str) -> Result<()> {
    match out {
        Some(p) => {
            if let Some(parent) = p.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            write_atomic(p, text)
        }
        None => {
            print!("{text}");
            Ok(())
        }
    }
}

/// Sign a receipt over the ledger as it stands now (optionally committing
/// to one session's records).
pub(crate) fn sign_receipt(
    ledger_path: &Path,
    key: &Path,
    session: Option<&str>,
) -> Result<Receipt> {
    let key = keys::read_private_key(key).map_err(e)?;
    let records = ledger::read_records(ledger_path).map_err(e)?;
    let cp = ledger::build_checkpoint(records, session).map_err(e)?;
    Receipt::sign(cp, &key).map_err(e)
}

fn create(ledger_path: &Path, key: &Path, session: Option<&str>, out: Option<&Path>) -> Result<()> {
    let receipt = sign_receipt(ledger_path, key, session)?;
    emit(out, &receipt.to_json().map_err(e)?)?;
    let c = &receipt.checkpoint;
    eprintln!(
        "receipt signed · records 0..={} · tip {} · signer {}{}",
        c.tip_index,
        short(&c.tip_hash),
        c.signer,
        c.session
            .as_ref()
            .map(|s| format!(" · session {} ({} records)", s.id, s.records))
            .unwrap_or_default()
    );
    Ok(())
}

fn short(h: &str) -> &str {
    &h[..h.len().min(12)]
}

fn read_receipt(path: &Path) -> Result<Receipt> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Receipt::from_json(&text).map_err(|err| anyhow!("{}: {err}", path.display()))
}

/// Collects check results; prints each as it is recorded.
#[derive(Default)]
struct Checks {
    failures: Vec<String>,
}

impl Checks {
    fn ok(&self, what: &str, detail: impl AsRef<str>) {
        println!("  {what:<13} ok · {}", detail.as_ref());
    }
    fn note(&self, what: &str, detail: impl AsRef<str>) {
        println!("  {what:<13} {}", detail.as_ref());
    }
    fn fail(&mut self, what: &str, detail: impl Into<String>) {
        let d = detail.into();
        println!("  {what:<13} FAILED · {d}");
        self.failures.push(d);
    }
    fn finish(self, noun: &str) -> Result<()> {
        if self.failures.is_empty() {
            println!("{noun} OK");
            Ok(())
        } else {
            bail!("{noun} verification FAILED: {}", self.failures.join("; "))
        }
    }
}

fn verify(
    ledger_path: &Path,
    file: &Path,
    pubkey: Option<&Path>,
    rekor_pubkey: Option<&Path>,
    anchor_log: Option<&Path>,
) -> Result<()> {
    let text = std::fs::read_to_string(file).with_context(|| format!("read {}", file.display()))?;
    let format = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v["format"].as_str().map(str::to_string));
    let pinned = pubkey.map(keys::read_public_key).transpose().map_err(e)?;
    let rekor_pem = rekor_pubkey
        .map(|p| std::fs::read_to_string(p).with_context(|| format!("read {}", p.display())))
        .transpose()?;
    let mut checks = Checks::default();

    if format.as_deref() == Some(PROOF_FORMAT) {
        let p = InclusionProof::from_json(&text).map_err(e)?;
        println!("inclusion proof {} · call {}", file.display(), p.call_id);
        check_signature(&mut checks, &p.receipt, pinned.as_ref());
        match p.verify_entries() {
            Ok(()) => {
                for en in &p.entries {
                    checks.ok(
                        "inclusion",
                        format!(
                            "record {} ({:?}) is leaf {} of {} under the signed Merkle root",
                            en.record.index, en.record.kind, en.leaf_index, en.tree_size
                        ),
                    );
                }
            }
            Err(err) => checks.fail("inclusion", err.to_string()),
        }
        check_anchors(&mut checks, &p.receipt, rekor_pem.as_deref(), anchor_log);
        return checks.finish("proof");
    }

    let receipt = Receipt::from_json(&text).map_err(|err| anyhow!("{}: {err}", file.display()))?;
    println!("receipt {} · {}", file.display(), receipt.format);
    let sig_ok = check_signature(&mut checks, &receipt, pinned.as_ref());
    if sig_ok {
        let cp = &receipt.checkpoint;
        match ledger::read_records(ledger_path)
            .and_then(|records| ledger::check_checkpoint(cp, records))
        {
            Ok(status) => {
                checks.ok(
                    "checkpoint",
                    format!(
                        "records 0..={} unchanged in {} · {} appended since",
                        cp.tip_index,
                        ledger_path.display(),
                        status.appended_after
                    ),
                );
                if let Some(s) = &cp.session {
                    checks.ok(
                        "session",
                        format!("{} · {} records · Merkle root matches", s.id, s.records),
                    );
                }
                if let Some((i, why)) = status.broken_after {
                    checks.fail(
                        "after tip",
                        format!(
                            "the checkpoint holds, but record {i} (after it) does not continue \
                             the chain: {why}; run `provio verify`"
                        ),
                    );
                }
            }
            Err(err) => checks.fail("checkpoint", err.to_string()),
        }
    } else {
        checks.note(
            "checkpoint",
            "not checked: the signature did not verify, so the checkpoint cannot be trusted",
        );
    }
    check_anchors(&mut checks, &receipt, rekor_pem.as_deref(), anchor_log);
    checks.finish("receipt")
}

fn check_signature(checks: &mut Checks, receipt: &Receipt, pinned: Option<&VerifyingKey>) -> bool {
    match receipt.verify_signature(pinned) {
        Ok(k) => {
            let who = keys::key_id(&k);
            if pinned.is_some() {
                checks.ok(
                    "signature",
                    format!("ed25519ph · signer {who} (pinned key)"),
                );
            } else {
                checks.ok(
                    "signature",
                    format!(
                        "ed25519ph · signer {who} (embedded key, NOT pinned: pass --pubkey to \
                         check who signed)"
                    ),
                );
            }
            true
        }
        Err(err) => {
            checks.fail("signature", err.to_string());
            false
        }
    }
}

fn check_anchors(
    checks: &mut Checks,
    receipt: &Receipt,
    rekor_pem: Option<&str>,
    anchor_log: Option<&Path>,
) {
    if receipt.anchors.is_empty() {
        checks.note(
            "anchors",
            "none (the receipt is not externally witnessed; see `provio receipt anchor`)",
        );
    }
    for a in &receipt.anchors {
        match a {
            Anchor::Rekor(r) => {
                let key = match rekor::trusted_log_key(&r.url, rekor_pem) {
                    Ok(Some(k)) => k,
                    Ok(None) => {
                        checks.fail(
                            "anchor rekor",
                            format!(
                                "no trusted key for {}: pass --rekor-pubkey (only \
                                 rekor.sigstore.dev's key is pinned)",
                                r.url
                            ),
                        );
                        continue;
                    }
                    Err(err) => {
                        checks.fail("anchor rekor", format!("--rekor-pubkey: {err}"));
                        continue;
                    }
                };
                match rekor::verify_anchor(r, receipt, &key) {
                    Ok(v) => checks.ok(
                        "anchor rekor",
                        format!(
                            "{} · log index {} · integrated {} · SET ok · {}",
                            r.url,
                            v.log_index,
                            rfc3339(v.integrated_time),
                            match v.inclusion_tree_size {
                                Some(n) => format!("inclusion proof ok (tree size {n})"),
                                None => "no inclusion proof stored".into(),
                            }
                        ),
                    ),
                    Err(err) => checks.fail("anchor rekor", err.to_string()),
                }
            }
            Anchor::File(f) => {
                let log = anchor_log
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from(&f.path));
                match file_anchor::verify(f, receipt, &log) {
                    Ok(()) => checks.ok(
                        "anchor file",
                        format!(
                            "line present in {} (anchored {}); only as strong as where that \
                             copy is kept",
                            log.display(),
                            f.anchored_at
                        ),
                    ),
                    Err(err) => checks.fail("anchor file", err.to_string()),
                }
            }
        }
    }
}

fn rfc3339(unix_secs: i64) -> String {
    provio_core::Timestamp::from_epoch_ms(unix_secs.saturating_mul(1000)).to_rfc3339()
}

fn anchor(
    ledger_path: &Path,
    receipt_path: &Path,
    to: AnchorTarget,
    url: &str,
    rekor_pubkey: Option<&Path>,
    anchor_log: Option<&Path>,
    out: Option<&Path>,
) -> Result<()> {
    let mut receipt = read_receipt(receipt_path)?;
    receipt
        .verify_signature(None)
        .map_err(|err| anyhow!("refusing to anchor: {err}"))?;
    match to {
        AnchorTarget::Rekor => {
            let pem = rekor_pubkey
                .map(|p| {
                    std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))
                })
                .transpose()?;
            let a = rekor::submit(url, &receipt, REKOR_TIMEOUT).map_err(e)?;
            let key = match rekor::trusted_log_key(url, pem.as_deref()).map_err(e)? {
                Some(k) => k,
                None => {
                    eprintln!(
                        "warning: no pinned key for {url}; checking this response against the \
                         key the log serves now. `provio receipt verify` will need --rekor-pubkey."
                    );
                    rekor::fetch_log_key(url, REKOR_TIMEOUT).map_err(e)?
                }
            };
            let v = rekor::verify_anchor(&a, &receipt, &key)
                .map_err(|err| anyhow!("the log's response does not verify: {err}"))?;
            println!(
                "anchored in {} · log index {} · uuid {} · integrated {}",
                a.url,
                v.log_index,
                a.uuid,
                rfc3339(v.integrated_time)
            );
            receipt
                .anchors
                .retain(|x| !matches!(x, Anchor::Rekor(r) if r.uuid == a.uuid));
            receipt.anchors.push(Anchor::Rekor(a));
        }
        AnchorTarget::File => {
            let log = anchor_log.map(Path::to_path_buf).unwrap_or_else(|| {
                ledger_path
                    .parent()
                    .map(|p| p.join("anchors.log"))
                    .unwrap_or_else(|| PathBuf::from("anchors.log"))
            });
            let a = file_anchor::append(&receipt, &log).map_err(e)?;
            println!(
                "appended anchor line to {} · sha256 {} — copy this file to storage the \
                 ledger host cannot rewrite (git remote, WORM bucket) for it to mean anything",
                log.display(),
                short(&a.line_sha256)
            );
            receipt.anchors.push(Anchor::File(a));
        }
    }
    let text = receipt.to_json().map_err(e)?;
    write_atomic(out.unwrap_or(receipt_path), &text)?;
    Ok(())
}

fn prove(ledger_path: &Path, call_id: &str, receipt_path: &Path, out: Option<&Path>) -> Result<()> {
    let receipt = read_receipt(receipt_path)?;
    receipt
        .verify_signature(None)
        .map_err(|err| anyhow!("refusing to prove against this receipt: {err}"))?;
    let records = ledger::read_records(ledger_path).map_err(e)?;
    let p = proof::prove(&receipt, records, call_id).map_err(e)?;
    emit(out, &p.to_json().map_err(e)?)?;
    eprintln!(
        "inclusion proof for call {call_id} · {} record(s) · tree size {}",
        p.entries.len(),
        receipt.checkpoint.records
    );
    Ok(())
}
