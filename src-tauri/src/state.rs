//! Runtime state: the unlocked session lives here, guarded by a Mutex and wiped
//! on lock. Nothing secret crosses to the UI — only codes and metadata.

use crate::model::{Account, Draft, Settings};
use crate::keystore::{KeyStore, OsKeyStore};
use crate::vault::Kdf;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use zeroize::Zeroizing;

/// An open vault session. Dropping it zeroizes the master key (via `Zeroizing`)
/// and every account secret (owned `Zeroizing<Vec<u8>>` fields).
pub struct Session {
    /// "" = vault from Authio 1.0 that has no id yet (it is given one on first unlock).
    pub vault_id: String,
    pub kdf: Kdf,
    pub key: Zeroizing<[u8; 32]>,
    pub accounts: Vec<Account>,
}

/// Drafts awaiting user confirmation in the import-preview dialog.
pub struct PendingImport {
    pub drafts: Vec<Draft>,
}

pub struct AppState {
    pub vault_path: PathBuf,
    pub settings_path: PathBuf,
    pub session: Mutex<Option<Session>>,
    pub settings: Mutex<Settings>,
    pub pending: Mutex<Option<PendingImport>>,
    pub last_activity: Mutex<Instant>,
    pub last_geo_save: Mutex<Instant>,
    /// Set when startup self-heal restored the vault from `tmp`/`bak`.
    pub recovered_from: Option<&'static str>,
    /// OS credential store (keychain-mode keys, last-seen-vault record).
    pub keystore: Arc<dyn KeyStore>,
}

impl AppState {
    pub fn new(dir: PathBuf) -> Self {
        Self::with_keystore(dir, Arc::new(OsKeyStore))
    }

    pub fn with_keystore(dir: PathBuf, keystore: Arc<dyn KeyStore>) -> Self {
        let _ = std::fs::create_dir_all(&dir);
        // Self-heal an interrupted/damaged vault write BEFORE anything asks
        // whether a vault exists (a missing vault.json would offer "set up new").
        let recovered_from = crate::vault::recover_vault(&dir.join("vault.json"));
        let settings_path = dir.join("settings.json");
        let settings = std::fs::read_to_string(&settings_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self {
            vault_path: dir.join("vault.json"),
            settings_path,
            session: Mutex::new(None),
            settings: Mutex::new(settings),
            pending: Mutex::new(None),
            last_activity: Mutex::new(Instant::now()),
            last_geo_save: Mutex::new(Instant::now() - std::time::Duration::from_secs(60)),
            recovered_from,
            keystore,
        }
    }

    pub fn touch(&self) {
        if let Ok(mut t) = self.last_activity.lock() {
            *t = Instant::now();
        }
    }

    pub fn save_settings(&self) {
        if let Ok(s) = self.settings.lock() {
            if let Ok(json) = serde_json::to_string_pretty(&*s) {
                let _ = crate::vault::atomic_write(&self.settings_path, json.as_bytes());
            }
        }
    }

    /// Hard wipe: session (key + decrypted accounts) and any pending import drafts.
    pub fn do_lock(&self) {
        if let Ok(mut g) = self.session.lock() {
            *g = None; // Drop → zeroize
        }
        if let Ok(mut p) = self.pending.lock() {
            *p = None;
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.session.lock().map(|g| g.is_some()).unwrap_or(false)
    }
}
