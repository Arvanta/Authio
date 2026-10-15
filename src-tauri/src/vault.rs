//! Vault file format: a small JSON envelope holding KDF + cipher parameters and
//! a base64 AES-256-GCM payload. Documented in `docs/BACKUP-FORMAT.md`.
//!
//! Writes are atomic (temp file + replace) and a `.bak` of the last good vault is
//! kept, so a crash can never corrupt the only copy.

use crate::crypto;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const FORMAT_VERSION: u32 = 1;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "name", rename_all = "lowercase")]
pub enum Kdf {
    Argon2id {
        m: u32,
        t: u32,
        p: u32,
        salt: String, // base64
    },
    Keychain,
}

impl Kdf {
    pub fn mode_name(&self) -> &'static str {
        match self {
            Kdf::Argon2id { .. } => "password",
            Kdf::Keychain => "keychain",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Cipher {
    pub name: String, // "aes-256-gcm"
    pub nonce: String, // base64
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub app: String,    // "authio"
    pub kind: String,   // "vault" | "backup"
    pub version: u32,
    pub kdf: Kdf,
    pub cipher: Cipher,
    pub data: String, // base64 ciphertext
}

pub fn read_envelope(path: &Path) -> Result<Envelope, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let env: Envelope = serde_json::from_str(&raw).map_err(|_| "file is not a valid Authio vault/backup".to_string())?;
    if env.app != "authio" {
        return Err("not an Authio file".into());
    }
    if env.version > FORMAT_VERSION {
        return Err(format!("file version {} is newer than this app supports", env.version));
    }
    Ok(env)
}

pub fn decrypt_envelope(env: &Envelope, key: &[u8; crypto::KEY_LEN]) -> Result<Vec<u8>, String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    if env.cipher.name != "aes-256-gcm" {
        return Err(format!("unsupported cipher {}", env.cipher.name));
    }
    let nonce = STANDARD.decode(&env.cipher.nonce).map_err(|_| "corrupt header (nonce)".to_string())?;
    let data = STANDARD.decode(&env.data).map_err(|_| "corrupt payload".to_string())?;
    crypto::decrypt(key, &nonce, &data)
}

pub fn write_envelope(
    path: &Path,
    kind: &str,
    kdf: &Kdf,
    key: &[u8; crypto::KEY_LEN],
    payload: &[u8],
) -> Result<(), String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let (nonce, ct) = crypto::encrypt(key, payload)?;
    let env = Envelope {
        app: "authio".into(),
        kind: kind.into(),
        version: FORMAT_VERSION,
        kdf: kdf.clone(),
        cipher: Cipher {
            name: "aes-256-gcm".into(),
            nonce: STANDARD.encode(nonce),
        },
        data: STANDARD.encode(ct),
    };
    let json = serde_json::to_string_pretty(&env).map_err(|e| e.to_string())?;
    atomic_write(path, json.as_bytes())
}

/// Write via temp file + rename; keep previous contents as `.bak`.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let dir = path.parent().ok_or("invalid path")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let tmp: PathBuf = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|e| format!("write failed: {e}"))?;
    if path.exists() {
        let bak = path.with_extension("bak");
        let _ = std::fs::copy(path, &bak);
        // On Windows rename fails if destination exists.
        let _ = std::fs::remove_file(path);
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("replace failed: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip() {
        let dir = std::env::temp_dir().join(format!("authio-test-{}", std::process::id()));
        let path = dir.join("vault.json");
        let key = crypto::rand_bytes::<32>();
        let kdf = Kdf::Keychain;
        write_envelope(&path, "vault", &kdf, &key, b"{\"accounts\":[]}").unwrap();
        let env = read_envelope(&path).unwrap();
        assert_eq!(env.kind, "vault");
        assert_eq!(decrypt_envelope(&env, &key).unwrap(), b"{\"accounts\":[]}");
        // wrong key must fail closed
        let bad = crypto::rand_bytes::<32>();
        assert!(decrypt_envelope(&env, &bad).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
