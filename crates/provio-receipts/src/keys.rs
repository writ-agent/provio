//! Ed25519 signing keys for receipts.
//!
//! - Private key: PKCS#8 v2 PEM (`-----BEGIN PRIVATE KEY-----`, RFC 8410).
//! - Public key: SPKI PEM (`-----BEGIN PUBLIC KEY-----`), the same encoding
//!   Rekor's `hashedrekord` expects in `signature.publicKey.content`.
//! - Key id: `ed25519:` + lowercase hex SHA-256 of the 32-byte raw public key.
//!
//! File permissions: on Unix the private key is created `0600` with
//! `O_EXCL`. On Windows it is created, then `icacls` removes inherited ACEs,
//! grants full control to the current user, and removes the broad groups
//! (Everyone, Authenticated Users, Users). SYSTEM and Administrators entries
//! the OS may add explicitly are left, as OpenSSH accepts for private keys
//! (both can read any file regardless); if `icacls` fails the
//! key is still written and [`write_keypair`] reports the failure so the
//! caller can warn.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::spki::{DecodePublicKey, EncodePublicKey};
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
pub use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{invalid, Error, Result};

/// A fresh key from the OS CSPRNG (`getrandom`).
pub fn generate() -> Result<SigningKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| Error::Invalid(format!("OS randomness: {e}")))?;
    let key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    Ok(key)
}

/// `ed25519:<hex sha256(raw public key)>`.
pub fn key_id(key: &VerifyingKey) -> String {
    format!("ed25519:{}", hex::encode(Sha256::digest(key.as_bytes())))
}

pub fn public_pem(key: &VerifyingKey) -> Result<String> {
    key.to_public_key_pem(LineEnding::LF)
        .map_err(|e| invalid(format!("encode public key: {e}")))
}

pub fn parse_public_pem(pem: &str) -> Result<VerifyingKey> {
    VerifyingKey::from_public_key_pem(pem.trim())
        .map_err(|e| invalid(format!("not an Ed25519 SPKI PEM public key: {e}")))
}

pub fn parse_private_pem(pem: &str) -> Result<SigningKey> {
    SigningKey::from_pkcs8_pem(pem.trim())
        .map_err(|e| invalid(format!("not an Ed25519 PKCS#8 PEM private key: {e}")))
}

pub fn read_public_key(path: &Path) -> Result<VerifyingKey> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| invalid(format!("read public key {}: {e}", path.display())))?;
    parse_public_pem(&text).map_err(|e| invalid(format!("{}: {e}", path.display())))
}

pub fn read_private_key(path: &Path) -> Result<SigningKey> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| invalid(format!("read private key {}: {e}", path.display())))?;
    parse_private_pem(&text).map_err(|e| invalid(format!("{}: {e}", path.display())))
}

/// `<out>.pub`, next to the private key.
pub fn public_path_for(out: &Path) -> PathBuf {
    let mut s = out.as_os_str().to_owned();
    s.push(".pub");
    PathBuf::from(s)
}

/// What [`write_keypair`] did.
#[derive(Debug)]
pub struct Written {
    pub private: PathBuf,
    pub public: PathBuf,
    pub key_id: String,
    /// Set when restricting the private key's permissions failed (Windows
    /// `icacls`); the key was written regardless.
    pub permission_warning: Option<String>,
}

/// Write `key` to `out` (private, restricted) and `out.pub` (public).
/// Refuses to overwrite an existing file unless `force`.
pub fn write_keypair(key: &SigningKey, out: &Path, force: bool) -> Result<Written> {
    let public = public_path_for(out);
    for p in [out, public.as_path()] {
        if p.exists() && !force {
            return Err(invalid(format!(
                "{} already exists; pass --force to overwrite",
                p.display()
            )));
        }
    }
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| invalid(format!("encode private key: {e}")))?;
    if force && out.exists() {
        std::fs::remove_file(out)?;
    }
    let mut f = private_options().open(out)?;
    f.write_all(pem.as_bytes())?;
    f.sync_all()?;
    drop(f);
    let permission_warning = restrict_to_owner(out).err();

    std::fs::write(&public, public_pem(&key.verifying_key())?)?;
    Ok(Written {
        private: out.to_path_buf(),
        public,
        key_id: key_id(&key.verifying_key()),
        permission_warning,
    })
}

#[cfg(unix)]
fn private_options() -> OpenOptions {
    use std::os::unix::fs::OpenOptionsExt;
    let mut o = OpenOptions::new();
    o.write(true).create_new(true).mode(0o600);
    o
}

#[cfg(not(unix))]
fn private_options() -> OpenOptions {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    o
}

#[cfg(unix)]
fn restrict_to_owner(_path: &Path) -> std::result::Result<(), String> {
    Ok(()) // created 0600 above
}

/// Remove inherited ACEs and grant only the current user full control.
#[cfg(windows)]
fn restrict_to_owner(path: &Path) -> std::result::Result<(), String> {
    let user = match (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
        (Ok(d), Ok(u)) if !d.is_empty() => format!("{d}\\{u}"),
        (_, Ok(u)) => u,
        _ => return Err("USERNAME is not set; could not restrict the key's ACL".into()),
    };
    let out = std::process::Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{user}:F"))
        // Everyone, Authenticated Users, Users: never on a private key.
        .args(["/remove:g", "*S-1-1-0", "*S-1-5-11", "*S-1-5-32-545"])
        .output()
        .map_err(|e| format!("could not run icacls to restrict the key's ACL: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "icacls failed to restrict the key's ACL: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

#[cfg(not(any(unix, windows)))]
fn restrict_to_owner(_path: &Path) -> std::result::Result<(), String> {
    Err("file permissions are not restricted on this platform".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_round_trip_and_key_id() {
        let k = generate().unwrap();
        let back = parse_private_pem(&k.to_pkcs8_pem(LineEnding::LF).unwrap()).unwrap();
        assert_eq!(back.to_bytes(), k.to_bytes());
        let pubpem = public_pem(&k.verifying_key()).unwrap();
        assert!(pubpem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert_eq!(parse_public_pem(&pubpem).unwrap(), k.verifying_key());
        let id = key_id(&k.verifying_key());
        assert!(id.starts_with("ed25519:") && id.len() == 8 + 64);
        assert!(parse_public_pem("junk").is_err());
    }

    #[test]
    fn keys_differ() {
        assert_ne!(
            generate().unwrap().to_bytes(),
            generate().unwrap().to_bytes()
        );
    }
}
