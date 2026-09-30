//! `writ policy add <pack>` works outside a repository checkout: the packs
//! are bundled into the binary, and a local ./packs still wins.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn empty_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "writ-policy-add-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn writ(dir: &PathBuf, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_writ"))
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap()
}

#[test]
fn bundled_pack_installs_without_a_packs_directory() {
    let d = empty_dir();
    let out = writ(&d, &["policy", "add", "aws-safety"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let installed = std::fs::read_to_string(d.join(".writ/packs/aws-safety.yaml")).unwrap();
    let shipped = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../packs/aws-safety/pack.yaml"
    ))
    .unwrap();
    // Bundled packs are embedded with LF line endings, whatever the checkout has.
    assert_eq!(installed, shipped.replace("\r\n", "\n"));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn unknown_pack_lists_the_bundled_ones() {
    let d = empty_dir();
    let out = writ(&d, &["policy", "add", "no-such-pack"]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("secrets-guard"), "{err}");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_local_pack_wins_over_the_bundled_one() {
    let d = empty_dir();
    std::fs::create_dir_all(d.join("packs/aws-safety")).unwrap();
    let mine = "id: aws-safety\nversion: 1\ndescription: my fork\nrules: []\n";
    std::fs::write(d.join("packs/aws-safety/pack.yaml"), mine).unwrap();
    let out = writ(&d, &["policy", "add", "aws-safety"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(d.join(".writ/packs/aws-safety.yaml")).unwrap(),
        mine
    );
    let _ = std::fs::remove_dir_all(&d);
}
