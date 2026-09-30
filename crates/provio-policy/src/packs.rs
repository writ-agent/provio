//! The policy packs bundled into this build (see `build.rs`). A policy
//! names them under `packs:`; `provio policy add` and `provio ui` list them.

/// `(pack id, pack.yaml source)`, sorted by id.
pub const BUNDLED: &[(&str, &str)] = include!(concat!(env!("OUT_DIR"), "/bundled_packs.rs"));

/// The bundled source of `id`, if this build ships it.
pub fn bundled(id: &str) -> Option<&'static str> {
    BUNDLED
        .iter()
        .find(|(name, _)| *name == id)
        .map(|(_, src)| *src)
}

/// The ids of every bundled pack, comma-separated (for messages).
pub fn names() -> String {
    BUNDLED
        .iter()
        .map(|(n, _)| *n)
        .collect::<Vec<_>>()
        .join(", ")
}
