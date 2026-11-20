//! Vault file format: a small JSON envelope holding KDF + cipher parameters and
//! a base64 AES-256-GCM payload. Documented in `docs/BACKUP-FORMAT.md`.
//!
//! Writes are atomic (temp file + replace) and a `.bak` of the last good vault is
//! kept, so a crash can never corrupt the only copy.

use crate::crypto;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

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
    /// "No security" mode: the decryption key is stored inside the vault itself
    /// (obfuscation only, NOT real protection). Explicitly user-chosen.
    None { key: String }, // base64
}

impl Kdf {
    pub fn mode_name(&self) -> &'static str {
        match self {
            Kdf::Argon2id { .. } => "password",
            Kdf::Keychain => "keychain",
            Kdf::None { .. } => "none",
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
    /// Random per-vault id (vault.json only). Names the vault's credential-store entry and
    /// lets the app notice that the file was swapped. Absent in vaults made by Authio 1.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<String>,
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

pub fn decrypt_envelope(env: &Envelope, key: &[u8; crypto::KEY_LEN]) -> Result<Zeroizing<Vec<u8>>, String> {
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
    write_envelope_id(path, kind, kdf, key, payload, None)
}

pub fn write_envelope_id(
    path: &Path,
    kind: &str,
    kdf: &Kdf,
    key: &[u8; crypto::KEY_LEN],
    payload: &[u8],
    vault_id: Option<&str>,
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
        vault_id: vault_id.map(|v| v.to_string()),
    };
    let json = serde_json::to_string_pretty(&env).map_err(|e| e.to_string())?;
    if kind == "vault" {
        write_vault_file(path, json.as_bytes())
    } else {
        // Backups go to a user-chosen location: no .bak / .tmp clutter beside it.
        write_user_file(path, json.as_bytes())
    }
}

fn is_valid_envelope(bytes: &[u8]) -> bool {
    serde_json::from_slice::<Envelope>(bytes).map(|e| e.app == "authio").unwrap_or(false)
}

/// Write `bytes` to `tmp` and flush them to disk (fsync) before returning.
fn write_synced(tmp: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut f = std::fs::File::create(tmp).map_err(|e| format!("write failed: {e}"))?;
    f.write_all(bytes).map_err(|e| format!("write failed: {e}"))?;
    f.sync_all().map_err(|e| format!("write failed (flush): {e}"))?;
    Ok(())
}

/// Replace `path` with `tmp`. `std::fs::rename` overwrites an existing destination
/// on Windows (MoveFileEx + REPLACE_EXISTING), so the old file is NEVER deleted
/// first — there is no instant at which neither copy exists.
fn replace_file(tmp: &Path, path: &Path) -> Result<(), String> {
    std::fs::rename(tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(tmp);
        format!("replace failed: {e}")
    })
}

fn generic_atomic_write(path: &Path, bytes: &[u8], keep_bak: Option<fn(&[u8]) -> bool>) -> Result<(), String> {
    let dir = path.parent().ok_or("invalid path")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let tmp: PathBuf = path.with_extension("tmp");
    write_synced(&tmp, bytes)?;
    if let Some(is_good) = keep_bak {
        // Only refresh the .bak from a file that is itself intact, so a damaged
        // vault can never overwrite the last good backup.
        if let Ok(old) = std::fs::read(path) {
            if is_good(&old) {
                let _ = std::fs::write(path.with_extension("bak"), &old);
            }
        }
    }
    replace_file(&tmp, path)
}

/// Vault write: fsync'd temp file → replace; `.bak` keeps the last good vault.
pub fn write_vault_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    generic_atomic_write(path, bytes, Some(is_valid_envelope))
}

/// Small app files (settings): atomic replace, `.bak` of any non-empty previous copy.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    generic_atomic_write(path, bytes, Some(|b: &[u8]| !b.is_empty()))
}

/// File the user picked (exports): atomic replace with no `.bak`, and a temp file
/// named after the full file name so an unrelated sibling can never be clobbered.
pub fn write_user_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let dir = path.parent().ok_or("invalid path")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let name = path.file_name().ok_or("invalid path")?.to_string_lossy().into_owned();
    let tmp = path.with_file_name(format!("{name}.authio-tmp"));
    write_synced(&tmp, bytes)?;
    replace_file(&tmp, path)
}

/// True if `dest` is the vault itself, one of its sidecar files (`.bak`, `.tmp`, `.corrupt`) or the
/// settings file — i.e. somewhere an export must never write, or a wrong pick in the save dialog
/// would replace the user's real vault with a backup. Compared case-insensitively and through
/// symlinks / `..` (the folder is canonicalized; the file itself may not exist yet).
pub fn is_protected_path(dest: &Path, vault_path: &Path, settings_path: &Path) -> bool {
    let canon_dir = |p: &Path| p.parent().and_then(|d| std::fs::canonicalize(d).ok());
    let (Some(dest_dir), Some(data_dir)) = (canon_dir(dest), canon_dir(vault_path)) else {
        return false;
    };
    if dest_dir != data_dir {
        return false;
    }
    let Some(name) = dest.file_name().map(|n| n.to_string_lossy().to_lowercase()) else {
        return false;
    };
    let vault_name = vault_path.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    let stem = vault_name.rsplit_once('.').map(|(s, _)| s.to_string()).unwrap_or(vault_name.clone());
    let settings_name = settings_path.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    name == vault_name
        || name == settings_name
        || ["bak", "tmp", "corrupt"].iter().any(|ext| name == format!("{stem}.{ext}"))
        || name.ends_with(".authio-tmp")
}

/// Drop the `.bak` (e.g. after the unlock method changed: it is still protected
/// by the OLD method — for "no security" mode that means readable by anyone).
pub fn discard_backup(path: &Path) {
    let _ = std::fs::remove_file(path.with_extension("bak"));
}

/// Startup self-heal. If `vault.json` is missing or damaged but an intact
/// `vault.tmp` (newest, interrupted write) or `vault.bak` exists, restore it.
/// Returns the name of the file restored from. A damaged vault is kept as
/// `vault.corrupt` for manual forensics rather than deleted.
pub fn recover_vault(path: &Path) -> Option<&'static str> {
    if let Ok(cur) = std::fs::read(path) {
        if is_valid_envelope(&cur) {
            return None;
        }
    }
    for (ext, label) in [("tmp", "tmp"), ("bak", "bak")] {
        let cand = path.with_extension(ext);
        let Ok(bytes) = std::fs::read(&cand) else { continue };
        if !is_valid_envelope(&bytes) {
            continue;
        }
        if path.exists() {
            let _ = std::fs::rename(path, path.with_extension("corrupt"));
        }
        if std::fs::write(path, &bytes).is_ok() {
            return Some(label);
        }
    }
    None
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
        assert_eq!(decrypt_envelope(&env, &key).unwrap().as_slice(), b"{\"accounts\":[]}");
        // wrong key must fail closed
        let bad = crypto::rand_bytes::<32>();
        assert!(decrypt_envelope(&env, &bad).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("authio-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn recovers_missing_vault_from_bak() {
        let dir = tmp_dir("rec1");
        let path = dir.join("vault.json");
        let key = crypto::rand_bytes::<32>();
        write_envelope(&path, "vault", &Kdf::Keychain, &key, b"one").unwrap();
        write_envelope(&path, "vault", &Kdf::Keychain, &key, b"two").unwrap(); // bak = "one"
        std::fs::remove_file(&path).unwrap(); // simulate crash after delete
        assert_eq!(recover_vault(&path), Some("bak"));
        let env = read_envelope(&path).unwrap();
        assert_eq!(decrypt_envelope(&env, &key).unwrap().as_slice(), b"one");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recovers_corrupt_vault_preferring_tmp_and_keeps_evidence() {
        let dir = tmp_dir("rec2");
        let path = dir.join("vault.json");
        let key = crypto::rand_bytes::<32>();
        write_envelope(&path, "vault", &Kdf::Keychain, &key, b"old").unwrap();
        write_envelope(&path, "vault", &Kdf::Keychain, &key, b"mid").unwrap();
        // interrupted write: newest intact content only in .tmp, vault.json zero-length
        std::fs::copy(&path, path.with_extension("tmp")).unwrap();
        std::fs::write(&path, b"").unwrap();
        assert_eq!(recover_vault(&path), Some("tmp"));
        assert!(path.with_extension("corrupt").exists());
        // healthy vault is left alone
        assert_eq!(recover_vault(&path), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn damaged_vault_never_overwrites_last_good_bak() {
        let dir = tmp_dir("bak");
        let path = dir.join("vault.json");
        let key = crypto::rand_bytes::<32>();
        write_envelope(&path, "vault", &Kdf::Keychain, &key, b"good1").unwrap();
        write_envelope(&path, "vault", &Kdf::Keychain, &key, b"good2").unwrap(); // bak = good1
        std::fs::write(&path, b"garbage").unwrap();
        write_envelope(&path, "vault", &Kdf::Keychain, &key, b"good3").unwrap();
        let bak = read_envelope(&path.with_extension("bak")).unwrap();
        assert_eq!(decrypt_envelope(&bak, &key).unwrap().as_slice(), b"good1");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn user_exports_leave_no_bak_or_tmp() {
        let dir = tmp_dir("exp");
        let path = dir.join("my-export.json");
        write_user_file(&path, b"OLD").unwrap();
        write_user_file(&path, b"NEW").unwrap();
        let names: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(names, vec!["my-export.json".to_string()]);
        assert_eq!(std::fs::read(&path).unwrap(), b"NEW");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn protects_vault_and_sidecars_from_being_an_export_target() {
        let d = std::env::temp_dir().join(format!("authio-prot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("sub")).unwrap();
        let v = d.join("vault.json");
        let st = d.join("settings.json");
        for n in ["vault.json", "VAULT.JSON", "vault.bak", "vault.tmp", "vault.corrupt", "settings.json", "x.authio-tmp"] {
            assert!(is_protected_path(&d.join(n), &v, &st), "{n} must be protected");
        }
        // reached through "sub/.." — still the same file
        assert!(is_protected_path(&d.join("sub").join("..").join("vault.json"), &v, &st));
        for ok in [d.join("backup.json"), d.join("sub").join("vault.json"), d.join("vault2.json")] {
            assert!(!is_protected_path(&ok, &v, &st), "{ok:?} is a fine export target");
        }
    }
}
