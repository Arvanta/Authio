//! Where vault keys (keychain mode) and the "last seen vault" record live.
//!
//! A small trait keeps the OS credential store out of the logic that decides
//! WHAT to store, so that logic (migration, rollback, key rotation) is unit-tested
//! against an in-memory store while production uses the Windows Credential Manager.

use sha2::{Digest, Sha256};
use std::path::Path;

pub const SERVICE: &str = "Authio";
/// Entry used by Authio 1.0 for EVERY vault (shared by all instances — the flaw
/// per-vault entries fix). Still read for vaults that have no id yet.
pub const LEGACY_KEY_USER: &str = "vault-key";

pub trait KeyStore: Send + Sync {
    fn set(&self, user: &str, value: &str) -> Result<(), String>;
    /// Err when the entry does not exist or cannot be read.
    fn get(&self, user: &str) -> Result<String, String>;
    fn delete(&self, user: &str);
}

/// Windows Credential Manager (or the platform equivalent).
pub struct OsKeyStore;

impl KeyStore for OsKeyStore {
    fn set(&self, user: &str, value: &str) -> Result<(), String> {
        keyring::Entry::new(SERVICE, user)
            .map_err(|e| format!("OS credential store error: {e}"))?
            .set_password(value)
            .map_err(|e| e.to_string())
    }
    fn get(&self, user: &str) -> Result<String, String> {
        keyring::Entry::new(SERVICE, user)
            .map_err(|e| format!("OS credential store error: {e}"))?
            .get_password()
            .map_err(|e| e.to_string())
    }
    fn delete(&self, user: &str) {
        if let Ok(e) = keyring::Entry::new(SERVICE, user) {
            let _ = e.delete_credential();
        }
    }
}

/// Credential-store entry holding the key of the vault with this id.
/// An empty id means "vault from Authio 1.0, no id yet" → the shared legacy entry.
pub fn key_user(vault_id: &str) -> String {
    if vault_id.is_empty() {
        LEGACY_KEY_USER.to_string()
    } else {
        format!("vault-key-{vault_id}")
    }
}

/// Entry remembering the last mode/id seen for the vault stored in this data
/// directory. Keyed by path ONLY for the tamper warning (a moved folder just
/// starts a fresh record) — never for keys, which must survive moving.
pub fn state_user(vault_path: &Path) -> String {
    let digest = Sha256::digest(vault_path.to_string_lossy().as_bytes());
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("vault-state-{hex}")
}

#[cfg(test)]
pub mod mem {
    use super::KeyStore;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory stand-in with switchable failures, for tests.
    #[derive(Default)]
    pub struct MemKeyStore {
        pub map: Mutex<HashMap<String, String>>,
        pub fail_sets: Mutex<bool>,
    }

    impl KeyStore for MemKeyStore {
        fn set(&self, user: &str, value: &str) -> Result<(), String> {
            if *self.fail_sets.lock().unwrap() {
                return Err("simulated credential store failure".into());
            }
            self.map.lock().unwrap().insert(user.into(), value.into());
            Ok(())
        }
        fn get(&self, user: &str) -> Result<String, String> {
            self.map.lock().unwrap().get(user).cloned().ok_or_else(|| "not found".into())
        }
        fn delete(&self, user: &str) {
            self.map.lock().unwrap().remove(user);
        }
    }
}
