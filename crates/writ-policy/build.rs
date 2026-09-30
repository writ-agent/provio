//! Embed the policy packs from the repository's `packs/` directory, so
//! `packs:` in writ.yaml, `writ policy add <pack>` and the `writ ui` policy
//! screen work for every install (pip, npm, release binaries, the WASM
//! playground), not only inside a checkout.
//!
//! Writes `$OUT_DIR/bundled_packs.rs`: a `&[(&str, &str)]` of
//! `(pack id, pack.yaml source)`, sorted by id. When `packs/` is absent
//! (e.g. a build from a source archive that does not ship it) the list is
//! empty and writ still builds (a policy naming a pack then fails to load).

use std::fmt::Write as _;
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let packs = manifest.join("..").join("..").join("packs");
    println!("cargo:rerun-if-changed={}", packs.display());

    let mut found: Vec<(String, PathBuf)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&packs) {
        for entry in entries.flatten() {
            let yaml = entry.path().join("pack.yaml");
            if yaml.is_file() {
                println!("cargo:rerun-if-changed={}", yaml.display());
                let id = entry.file_name().to_string_lossy().into_owned();
                found.push((id, yaml.canonicalize().unwrap_or(yaml)));
            }
        }
    }
    found.sort();

    // Embed a copy with LF line endings, so the bundled bytes (and the WASM
    // playground built from them) are identical whatever line endings the
    // checkout has (a Windows working tree may hold CRLF).
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let normalized = out_dir.join("packs");
    std::fs::create_dir_all(&normalized).unwrap();
    let mut out = String::from("&[\n");
    for (id, path) in &found {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
            .replace("\r\n", "\n");
        let copy = normalized.join(format!("{id}.yaml"));
        std::fs::write(&copy, text).unwrap();
        // `{:?}` escapes backslashes, so Windows paths are valid literals.
        let _ = writeln!(
            out,
            "    ({id:?}, include_str!({:?})),",
            copy.to_string_lossy()
        );
    }
    out.push(']');
    std::fs::write(out_dir.join("bundled_packs.rs"), out).unwrap();
}
