//! Tauri commands — the only IPC surface of the app.
//!
//! Security contract:
//!  - The UI never receives raw account secrets; `reveal_secret` and exports are
//!    gated behind re-authentication (master password) or the OS session.
//!  - `get_codes` is the only command that returns OTP codes; it does not count
//!    as user activity, so polling never defeats auto-lock.

use crate::model::{now_unix, Account, Algorithm, Draft, DraftIn, Flavor, Kind, Settings};
use crate::otpauth::{b32_decode, b32_encode};
use crate::state::{AppState, PendingImport, Session};
use crate::vault::{self, Kdf};
use crate::{crypto, importers, keystore, otp, otpauth, qr};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tauri::State;
use zeroize::Zeroizing;

type Cmd<T> = Result<T, String>;

/// Move an IPC-supplied password into a wiped-on-drop container (best effort:
/// the webview/IPC layer's own copies are outside our control).
fn secret_str(s: Option<String>) -> Option<Zeroizing<String>> {
    s.map(Zeroizing::new)
}

/// Minimum length is counted in characters, not UTF-8 bytes.
fn min_chars(s: &str, n: usize) -> bool {
    s.chars().count() >= n
}

// ---------------------------------------------------------------------------
// DTOs

#[derive(Serialize, Clone)]
pub struct AccountDto {
    pub id: String,
    pub issuer: String,
    pub name: String,
    pub group: String,
    pub pinned: bool,
    pub sort: u64,
    pub kind: String,
    pub algorithm: String,
    pub digits: u32,
    pub period: u32,
    pub counter: u64,
    pub flavor: String,
}

#[derive(Serialize)]
pub struct CodeDto {
    pub id: String,
    pub code: Option<String>,
    pub remaining: u64,
    pub progress: f64,
}

#[derive(Serialize)]
pub struct StatusDto {
    pub initialized: bool,
    pub unlocked: bool,
    pub mode: Option<String>,
    /// Compile-time app version (Cargo.toml) — single source of truth.
    pub version: String,
    /// "tmp" | "bak" when the vault was auto-restored at startup (UI shows a notice once).
    pub recovered_from: Option<String>,
    /// Set when the vault file's unlock method / identity differs from what this app last saw
    /// (changed outside the app). The UI must ask the user before unlocking.
    pub integrity_warning: Option<IntegrityWarningDto>,
}

#[derive(Serialize)]
pub struct PreviewEntry {
    pub index: u32,
    pub issuer: String,
    pub name: String,
    pub kind: String,
    pub algorithm: String,
    pub digits: u32,
    pub period: u32,
    pub duplicate: bool,
}

#[derive(Serialize)]
pub struct PreviewDto {
    pub format: String,
    pub needs_password: bool,
    pub skipped: u32,
    pub entries: Vec<PreviewEntry>,
    /// Multi-image QR import only (0 otherwise): images processed / without any readable QR /
    /// accounts dropped because the same secret appeared more than once in the batch.
    pub files_total: u32,
    pub files_failed: u32,
    pub merged_duplicates: u32,
}

#[derive(Serialize)]
pub struct SecretDto {
    pub secret: String,
    pub uri: String,
}

/// Open a fixed external link in the user's default browser.
/// URLs are hardcoded allowlist constants — the frontend only passes a target
/// name, so no arbitrary URL can ever be opened from the webview.
#[tauri::command]
pub fn open_url(target: &str) -> Result<(), String> {
    const GITHUB_URL: &str = "https://github.com/Arvanta/Authio";
    const DONATE_URL: &str = "https://arvanta.github.io";
    let url = match target {
        "github" => GITHUB_URL,
        "donate" => DONATE_URL,
        other => return Err(format!("unknown link target \"{other}\"")),
    };
    #[cfg(target_os = "windows")]
    // explorer.exe opens the URL in the default browser without flashing a
    // console window (unlike `cmd /C start`).
    let spawned = std::process::Command::new("explorer").arg(url).spawn();
    #[cfg(target_os = "macos")]
    let spawned = std::process::Command::new("open").arg(url).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let spawned = std::process::Command::new("xdg-open").arg(url).spawn();
    spawned.map_err(|e| format!("cannot open the browser: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers

fn account_dto(a: &Account) -> AccountDto {
    AccountDto {
        id: a.id.clone(),
        issuer: a.issuer.clone(),
        name: a.name.clone(),
        group: a.group.clone(),
        pinned: a.pinned,
        sort: a.sort,
        kind: match a.kind {
            Kind::Totp => "totp".into(),
            Kind::Hotp { .. } => "hotp".into(),
        },
        algorithm: a.algorithm.as_str().into(),
        digits: a.digits,
        period: a.period,
        counter: match a.kind {
            Kind::Hotp { counter } => counter,
            _ => 0,
        },
        flavor: a.flavor.as_str().into(),
    }
}

fn with_session<T>(state: &AppState, f: impl FnOnce(&mut Session) -> Cmd<T>) -> Cmd<T> {
    let mut guard = state.session.lock().map_err(|_| "internal error (state lock)".to_string())?;
    let session = guard.as_mut().ok_or_else(|| "the vault is locked".to_string())?;
    f(session)
}

#[derive(Deserialize)]
struct AccountsPayload {
    accounts: Vec<Account>,
}

#[derive(Serialize)]
struct AccountsPayloadRef<'a> {
    accounts: &'a [Account],
}

fn persist_session(state: &AppState, s: &Session) -> Cmd<()> {
    let payload = Zeroizing::new(
        serde_json::to_vec(&AccountsPayloadRef { accounts: &s.accounts })
            .map_err(|e| format!("serialize failure: {e}"))?,
    );
    let id = (!s.vault_id.is_empty()).then_some(s.vault_id.as_str());
    vault::write_envelope_id(&state.vault_path, "vault", &s.kdf, &s.key, &payload, id)
}

fn persist(state: &AppState) -> Cmd<()> {
    with_session(state, |s| persist_session(state, s))
}

/// Change the account list and save it as ONE step. If the closure fails or the
/// write to disk fails (antivirus / OneDrive holding the file, disk full ...), the
/// in-memory list is put back exactly as it was, so what the user sees on screen
/// never differs from what is on disk.
fn mutate_persist<T>(state: &AppState, f: impl FnOnce(&mut Vec<Account>) -> Cmd<T>) -> Cmd<T> {
    with_session(state, |s| {
        let snapshot = s.accounts.clone();
        let out = match f(&mut s.accounts) {
            Ok(v) => v,
            Err(e) => {
                s.accounts = snapshot;
                return Err(e);
            }
        };
        if let Err(e) = persist_session(state, s) {
            s.accounts = snapshot;
            return Err(e);
        }
        Ok(out)
    })
}

fn new_id() -> String {
    crypto::rand_bytes::<16>().iter().map(|b| format!("{b:02x}")).collect()
}

fn store_key(state: &AppState, user: &str, key: &[u8; 32]) -> Cmd<()> {
    state
        .keystore
        .set(user, &STANDARD.encode(key))
        .map_err(|e| format!("could not store the vault key in the OS credential store: {e}"))
}

fn load_key(state: &AppState, user: &str) -> Cmd<Zeroizing<[u8; 32]>> {
    let encoded = Zeroizing::new(
        state
            .keystore
            .get(user)
            .map_err(|_| "vault key not found in the OS credential store".to_string())?,
    );
    let raw = Zeroizing::new(STANDARD.decode(encoded.as_bytes()).map_err(|_| "corrupt keychain entry".to_string())?);
    let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| "corrupt keychain entry (bad length)".to_string())?;
    Ok(Zeroizing::new(arr))
}

// ---- "has the vault file been swapped?" record --------------------------------------------
// The last mode + id seen for this data directory is kept in the OS credential store (not in a
// file the same attacker could edit). A mismatch means the vault changed OUTSIDE the app.

#[derive(Serialize, Deserialize)]
struct IntegrityRecord {
    id: String,
    mode: String,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct IntegrityWarningDto {
    /// "mode_changed" | "vault_replaced"
    pub kind: String,
    pub was_mode: String,
    pub now_mode: String,
}

fn record_integrity(state: &AppState, mode: &str, id: &str) {
    let rec = IntegrityRecord { id: id.to_string(), mode: mode.to_string() };
    if let Ok(json) = serde_json::to_string(&rec) {
        let _ = state.keystore.set(&keystore::state_user(&state.vault_path), &json);
    }
}

/// Trust-on-first-use: with no record yet (fresh install, upgrade from 1.0, credential store
/// unavailable) there is nothing to compare against and no warning is raised.
fn integrity_warning(state: &AppState, env: &vault::Envelope) -> Option<IntegrityWarningDto> {
    let raw = state.keystore.get(&keystore::state_user(&state.vault_path)).ok()?;
    let rec: IntegrityRecord = serde_json::from_str(&raw).ok()?;
    let now_mode = env.kdf.mode_name().to_string();
    let now_id = env.vault_id.clone().unwrap_or_default();
    let kind = if rec.mode != now_mode {
        "mode_changed"
    } else if !rec.id.is_empty() && rec.id != now_id {
        "vault_replaced"
    } else {
        return None;
    };
    Some(IntegrityWarningDto { kind: kind.into(), was_mode: rec.mode, now_mode })
}

/// Re-derive from the stored vault header and attempt decryption — proves the
/// caller knows the master password without touching the live session key.
fn verify_master_password(state: &AppState, password: &str) -> Cmd<bool> {
    let env = vault::read_envelope(&state.vault_path)?;
    let Kdf::Argon2id { m, t, p, salt } = &env.kdf else {
        return Ok(true); // keychain mode: the OS session itself is the auth factor
    };
    let salt = STANDARD.decode(salt).map_err(|_| "corrupt vault header".to_string())?;
    let key = crypto::argon2id_derive(password.as_bytes(), &salt, *m, *t, *p)?;
    Ok(vault::decrypt_envelope(&env, &key).is_ok())
}

fn vault_mode(state: &AppState) -> Cmd<String> {
    Ok(vault::read_envelope(&state.vault_path)?.kdf.mode_name().to_string())
}

fn draft_from_input(input: DraftIn) -> Cmd<Draft> {
    let flavor = match input.flavor.as_deref() {
        None | Some("") => Flavor::Standard,
        Some(f) => Flavor::parse(f).ok_or_else(|| "unknown flavor (expected standard or steam)".to_string())?,
    };
    let kind = match input.kind.as_deref().unwrap_or("totp") {
        "hotp" if flavor != Flavor::Steam => Kind::Hotp { counter: input.counter.unwrap_or(0) },
        _ => Kind::Totp,
    };
    let d = Draft {
        issuer: input.issuer.trim().to_string(),
        name: input.name.trim().to_string(),
        secret: Zeroizing::new(b32_decode(&input.secret)?),
        algorithm: if flavor == Flavor::Steam {
            Algorithm::SHA1
        } else {
            Algorithm::from_opt(input.algorithm.as_deref())?
        },
        digits: if flavor == Flavor::Steam { 5 } else { input.digits.unwrap_or(6) },
        period: if flavor == Flavor::Steam { 30 } else { input.period.unwrap_or(30) },
        kind,
        flavor,
        group: input.group.clone().unwrap_or_default().trim().to_string(),
    };
    d.validate()?;
    Ok(d)
}

fn add_draft(state: &AppState, draft: Draft) -> Cmd<AccountDto> {
    let dto = mutate_persist(state, |accounts| {
        if accounts.iter().any(|a| a.secret.as_slice() == draft.secret.as_slice()) {
            return Err("an account with this exact secret already exists".into());
        }
        let next_sort = accounts.iter().map(|a| a.sort).max().unwrap_or(0) + 1;
        let account = draft.into_account(new_id(), next_sort, now_unix());
        let dto = account_dto(&account);
        accounts.push(account);
        Ok(dto)
    })?;
    state.touch();
    Ok(dto)
}

// ---------------------------------------------------------------------------
// Vault lifecycle

#[tauri::command]
pub fn vault_status(state: State<'_, Arc<AppState>>) -> StatusDto {
    let initialized = state.vault_path.exists();
    let mode = if initialized {
        vault::read_envelope(&state.vault_path).ok().map(|e| e.kdf.mode_name().to_string())
    } else {
        None
    };
    let integrity_warning = if initialized && !state.is_unlocked() {
        vault::read_envelope(&state.vault_path).ok().and_then(|e| integrity_warning(&state, &e))
    } else {
        None
    };
    StatusDto {
        initialized,
        unlocked: state.is_unlocked(),
        mode,
        // Compile-time version with a fallback so parse-level tooling also compiles.
        version: option_env!("CARGO_PKG_VERSION").unwrap_or("1.1.0").to_string(),
        recovered_from: state.recovered_from.map(|s| s.to_string()),
        integrity_warning,
    }
}

#[tauri::command(async)]
pub fn setup_vault(state: State<'_, Arc<AppState>>, mode: String, password: Option<String>) -> Cmd<()> {
    let password = secret_str(password);
    setup_vault_inner(&state, &mode, password.as_ref().map(|p| p.as_str()))
}

fn setup_vault_inner(state: &AppState, mode: &str, password: Option<&str>) -> Cmd<()> {
    if state.vault_path.exists() {
        return Err("a vault already exists — unlock it instead".into());
    }
    let vault_id = new_id();
    let mut created_entry: Option<String> = None;
    let (kdf, key) = match mode {
        "password" => {
            let pw = password.filter(|p| !p.is_empty()).ok_or("master password required")?;
            if !min_chars(pw, 8) {
                return Err("master password must be at least 8 characters".into());
            }
            let salt = crypto::rand_bytes::<{ crypto::SALT_LEN }>();
            let key = crypto::argon2id_derive(pw.as_bytes(), &salt, crypto::ARGON2_M_KIB, crypto::ARGON2_T, crypto::ARGON2_P)?;
            (
                Kdf::Argon2id { m: crypto::ARGON2_M_KIB, t: crypto::ARGON2_T, p: crypto::ARGON2_P, salt: STANDARD.encode(salt) },
                key,
            )
        }
        "keychain" => {
            // The entry is named after THIS vault's random id, so creating a vault can never
            // overwrite the key of another vault (installed + portable copies, re-installs …).
            let key = Zeroizing::new(crypto::rand_bytes::<32>());
            let user = keystore::key_user(&vault_id);
            store_key(state, &user, &key)?;
            created_entry = Some(user);
            (Kdf::Keychain, key)
        }
        "none" => {
            let key = Zeroizing::new(crypto::rand_bytes::<32>());
            (Kdf::None { key: STANDARD.encode(&*key) }, key)
        }
        other => return Err(format!("unknown vault mode \"{other}\"")),
    };
    if let Err(e) = vault::write_envelope_id(&state.vault_path, "vault", &kdf, &key, br#"{"accounts":[]}"#, Some(&vault_id)) {
        if let Some(user) = created_entry {
            state.keystore.delete(&user); // do not leave an orphaned key behind
        }
        return Err(e);
    }
    record_integrity(state, kdf.mode_name(), &vault_id);
    let mut guard = state.session.lock().map_err(|_| "internal error (state lock)".to_string())?;
    *guard = Some(Session { vault_id, kdf, key, accounts: Vec::new() });
    state.touch();
    Ok(())
}

#[tauri::command(async)]
pub fn unlock(state: State<'_, Arc<AppState>>, password: Option<String>) -> Cmd<()> {
    let password = secret_str(password);
    unlock_inner(&state, password.as_ref().map(|p| p.as_str()))
}

fn unlock_inner(state: &AppState, password: Option<&str>) -> Cmd<()> {
    let env = vault::read_envelope(&state.vault_path)?;
    if integrity_warning(state, &env).is_some() {
        // The UI shows the warning first; this is the backstop if anything skips it.
        return Err("the vault file changed since you last opened it — review the warning first".into());
    }
    let vault_id = env.vault_id.clone().unwrap_or_default();
    let key = match &env.kdf {
        Kdf::Argon2id { m, t, p, salt } => {
            let pw = password.filter(|p| !p.is_empty()).ok_or("master password required")?;
            let salt = STANDARD.decode(salt).map_err(|_| "corrupt vault header (salt)".to_string())?;
            crypto::argon2id_derive(pw.as_bytes(), &salt, *m, *t, *p)?
        }
        // Vaults from 1.0 have no id → shared legacy entry; newer ones have their own.
        Kdf::Keychain => load_key(state, &keystore::key_user(&vault_id))?,
        Kdf::None { key } => {
            let raw = Zeroizing::new(STANDARD.decode(key).map_err(|_| "corrupt vault header (key)".to_string())?);
            let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| "corrupt vault header (key length)".to_string())?;
            Zeroizing::new(arr)
        }
    };
    let plain = vault::decrypt_envelope(&env, &key)?; // AEAD tag fails on wrong password
    let payload: AccountsPayload =
        serde_json::from_slice(&plain).map_err(|_| "vault payload is corrupted".to_string())?;
    {
        let mut guard = state.session.lock().map_err(|_| "internal error (state lock)".to_string())?;
        *guard = Some(Session { vault_id: vault_id.clone(), kdf: env.kdf.clone(), key, accounts: payload.accounts });
    }
    state.touch();
    if vault_id.is_empty() {
        upgrade_legacy_vault(state);
    }
    let (mode, id) = with_session(state, |s| Ok((s.kdf.mode_name().to_string(), s.vault_id.clone())))?;
    record_integrity(state, &mode, &id);
    Ok(())
}

/// A vault made by Authio 1.0 has no id (and, in keychain mode, shares the single legacy
/// credential entry). Give it an id; for keychain mode copy the key into the vault's OWN entry
/// FIRST, and only then write the id into the file. The legacy entry is deliberately left in
/// place: another instance may still depend on it. Best effort — any failure leaves the vault
/// exactly as it was and it simply keeps working the old way.
fn upgrade_legacy_vault(state: &AppState) {
    let _ = with_session(state, |s| {
        let id = new_id();
        if matches!(s.kdf, Kdf::Keychain) {
            store_key(state, &keystore::key_user(&id), &s.key)?;
        }
        s.vault_id = id.clone();
        Ok(())
    });
    if persist(state).is_err() {
        // File still has no id: forget it in memory so the next write retries the upgrade.
        let _ = with_session(state, |s| {
            if matches!(s.kdf, Kdf::Keychain) {
                state.keystore.delete(&keystore::key_user(&s.vault_id));
            }
            s.vault_id.clear();
            Ok(())
        });
    }
}

/// The user confirmed that the vault file in its current state is legitimate.
#[tauri::command]
pub fn trust_vault_state(state: State<'_, Arc<AppState>>) -> Cmd<()> {
    let env = vault::read_envelope(&state.vault_path)?;
    record_integrity(&state, env.kdf.mode_name(), &env.vault_id.clone().unwrap_or_default());
    Ok(())
}

#[tauri::command]
pub fn exit_app(app: tauri::AppHandle) {
    app.exit(0);
}

#[tauri::command]
pub fn lock(state: State<'_, Arc<AppState>>) {
    state.do_lock();
}

/// Switch the vault's unlock method (password ↔ keychain ↔ none) or change the
/// master password. Requires the vault to be unlocked plus, when the current
/// method is a master password, re-entering that password.
#[tauri::command(async)]
pub fn change_unlock_mode(
    state: State<'_, Arc<AppState>>,
    mode: String,
    current_password: Option<String>,
    new_password: Option<String>,
) -> Cmd<()> {
    let current_password = secret_str(current_password);
    let new_password = secret_str(new_password);
    change_unlock_mode_inner(
        &state,
        &mode,
        current_password.as_ref().map(|p| p.as_str()),
        new_password.as_ref().map(|p| p.as_str()),
    )
}

fn change_unlock_mode_inner(
    state: &AppState,
    mode: &str,
    current_password: Option<&str>,
    new_password: Option<&str>,
) -> Cmd<()> {
    state.touch();
    if vault_mode(state)? == "password" {
        let pw = current_password.filter(|p| !p.is_empty()).ok_or("enter your current master password")?;
        if !verify_master_password(state, pw)? {
            return Err("incorrect master password".into());
        }
    }

    let (was_keychain, old_id) = with_session(state, |s| Ok((matches!(s.kdf, Kdf::Keychain), s.vault_id.clone())))?;
    // Keychain mode gets a NEW id (and so a NEW credential entry) on every re-key: the old entry
    // is left untouched until the new file is safely on disk, so a crash or power loss at any
    // moment leaves a vault and a key that still belong together. Other modes keep the id
    // (a 1.0 vault gets its id here at the latest).
    let id = if mode == "keychain" || old_id.is_empty() { new_id() } else { old_id.clone() };
    let user = keystore::key_user(&id);

    // The key is ALWAYS fresh — never carried over from the previous method. Otherwise any old
    // copy of the file (cloud, USB, backup) — which holds the key in clear for "none", or can be
    // unlocked with the old password — would keep opening the new vault too.
    let (new_kdf, new_key) = match mode {
        "password" => {
            let pw = new_password
                .filter(|p| min_chars(p, 8))
                .ok_or("the new master password must be at least 8 characters")?;
            let salt = crypto::rand_bytes::<{ crypto::SALT_LEN }>();
            let key = crypto::argon2id_derive(pw.as_bytes(), &salt, crypto::ARGON2_M_KIB, crypto::ARGON2_T, crypto::ARGON2_P)?;
            (
                Kdf::Argon2id { m: crypto::ARGON2_M_KIB, t: crypto::ARGON2_T, p: crypto::ARGON2_P, salt: STANDARD.encode(salt) },
                key,
            )
        }
        "keychain" => (Kdf::Keychain, Zeroizing::new(crypto::rand_bytes::<32>())),
        "none" => {
            let key = Zeroizing::new(crypto::rand_bytes::<32>());
            (Kdf::None { key: STANDARD.encode(&*key) }, key)
        }
        other => return Err(format!("unknown unlock mode \"{other}\"")),
    };

    // Keychain: the new key goes into its own, new entry BEFORE the file that needs it is written.
    // If the write fails, that new entry is removed again; the old entry was never touched.
    if mode == "keychain" {
        store_key(state, &user, &new_key)?;
    }
    let written = with_session(state, |s| {
        let payload = Zeroizing::new(
            serde_json::to_vec(&AccountsPayloadRef { accounts: &s.accounts })
                .map_err(|e| format!("serialize failure: {e}"))?,
        );
        vault::write_envelope_id(&state.vault_path, "vault", &new_kdf, &new_key, &payload, Some(&id))?;
        s.kdf = new_kdf.clone();
        s.key = new_key;
        s.vault_id = id.clone();
        Ok(())
    });
    if let Err(e) = written {
        if mode == "keychain" {
            state.keystore.delete(&user);
        }
        return Err(e);
    }
    // The .bak still holds the vault under the PREVIOUS unlock method (for "no security" that is
    // readable by anyone) — drop it; the next write recreates it under the new method.
    vault::discard_backup(&state.vault_path);
    // Only now is the previous entry of this vault obsolete. The shared legacy entry (1.0, no id)
    // is never deleted — another instance may still rely on it.
    if was_keychain && !old_id.is_empty() {
        state.keystore.delete(&keystore::key_user(&old_id));
    }
    record_integrity(state, mode, &id);
    Ok(())
}

// ---------------------------------------------------------------------------
// Accounts: read, generate codes, mutate

#[tauri::command]
pub fn list_accounts(state: State<'_, Arc<AppState>>) -> Cmd<Vec<AccountDto>> {
    with_session(&state, |s| {
        let mut v: Vec<AccountDto> = s.accounts.iter().map(account_dto).collect();
        v.sort_by_key(|a| a.sort);
        Ok(v)
    })
}

#[tauri::command]
pub fn get_codes(state: State<'_, Arc<AppState>>) -> Cmd<Vec<CodeDto>> {
    // Read-only; intentionally does NOT touch last_activity (polls every second).
    with_session(&state, |s| {
        let now = now_unix();
        Ok(s.accounts
            .iter()
            .map(|a| match a.kind {
                Kind::Totp => {
                    let (code, remaining, progress) = if a.flavor == Flavor::Steam {
                        otp::totp_steam(&a.secret, now)
                    } else {
                        otp::totp(&a.secret, a.period, a.digits, a.algorithm, now)
                    };
                    CodeDto { id: a.id.clone(), code: Some(code), remaining, progress }
                }
                Kind::Hotp { .. } => CodeDto { id: a.id.clone(), code: None, remaining: 0, progress: 0.0 },
            })
            .collect())
    })
}

#[tauri::command]
pub fn hotp_next(state: State<'_, Arc<AppState>>, id: String) -> Cmd<CodeDto> {
    // Counter advance + save are one step: a counter value that was never saved is not burned.
    let dto = mutate_persist(&state, |accounts| {
        let a = accounts.iter_mut().find(|a| a.id == id).ok_or("account not found")?;
        match &mut a.kind {
            Kind::Hotp { counter } => {
                let code = otp::hotp(&a.secret, *counter, a.digits, a.algorithm);
                *counter += 1;
                Ok(CodeDto { id: a.id.clone(), code: Some(code), remaining: 0, progress: 0.0 })
            }
            _ => Err("not an HOTP account".into()),
        }
    })?;
    state.touch();
    Ok(dto)
}

#[tauri::command]
pub fn add_account(state: State<'_, Arc<AppState>>, draft: DraftIn) -> Cmd<AccountDto> {
    add_draft(&state, draft_from_input(draft)?)
}

#[tauri::command]
pub fn add_from_uri(state: State<'_, Arc<AppState>>, uri: String) -> Cmd<Vec<AccountDto>> {
    let trimmed = uri.trim();
    if trimmed.starts_with("otpauth-migration://") {
        return Err("Google migration codes contain multiple accounts — use Import instead".into());
    }
    let draft = otpauth::parse_otpauth(trimmed)?;
    Ok(vec![add_draft(&state, draft)?])
}

#[tauri::command]
pub fn update_account(state: State<'_, Arc<AppState>>, id: String, issuer: String, name: String, group: String) -> Cmd<()> {
    mutate_persist(&state, |accounts| {
        let a = accounts.iter_mut().find(|a| a.id == id).ok_or("account not found")?;
        if issuer.trim().is_empty() && name.trim().is_empty() {
            return Err("account needs at least an issuer or a name".into());
        }
        a.issuer = issuer.trim().to_string();
        a.name = name.trim().to_string();
        a.group = group.trim().to_string();
        Ok(())
    })?;
    state.touch();
    Ok(())
}

#[tauri::command]
pub fn delete_account(state: State<'_, Arc<AppState>>, id: String) -> Cmd<()> {
    mutate_persist(&state, |accounts| {
        let before = accounts.len();
        accounts.retain(|a| a.id != id);
        if accounts.len() == before {
            return Err("account not found".into());
        }
        Ok(())
    })?;
    state.touch();
    Ok(())
}

#[tauri::command]
pub fn set_pinned(state: State<'_, Arc<AppState>>, id: String, pinned: bool) -> Cmd<()> {
    mutate_persist(&state, |accounts| {
        let a = accounts.iter_mut().find(|a| a.id == id).ok_or("account not found")?;
        a.pinned = pinned;
        Ok(())
    })?;
    state.touch();
    Ok(())
}

#[tauri::command]
pub fn reorder(state: State<'_, Arc<AppState>>, ids: Vec<String>) -> Cmd<()> {
    mutate_persist(&state, |accounts| {
        for (i, id) in ids.iter().enumerate() {
            if let Some(a) = accounts.iter_mut().find(|a| &a.id == id) {
                a.sort = i as u64;
            }
        }
        Ok(())
    })?;
    state.touch();
    Ok(())
}

#[tauri::command(async)]
pub fn reveal_secret(state: State<'_, Arc<AppState>>, id: String, password: Option<String>) -> Cmd<SecretDto> {
    let password = secret_str(password);
    if vault_mode(&state)? == "password" {
        let pw = password.filter(|p| !p.is_empty()).ok_or("enter your master password to reveal the secret")?;
        if !verify_master_password(&state, &pw)? {
            return Err("incorrect master password".into());
        }
    }
    with_session(&state, |s| {
        let a = s.accounts.iter().find(|a| a.id == id).ok_or("account not found")?;
        let dto = SecretDto { secret: b32_encode(&a.secret), uri: otpauth::to_otpauth(a) };
        Ok(dto)
    })
    .inspect(|_| state.touch())
}

// ---------------------------------------------------------------------------
// Export

#[derive(Serialize)]
struct BackupAccountOut {
    issuer: String,
    name: String,
    group: String,
    flavor: String,
    secret: String,
    algorithm: String,
    digits: u32,
    period: u32,
    #[serde(rename = "type")]
    kind: String,
    counter: u64,
}

#[derive(Serialize)]
struct PlainBackup {
    app: String,
    kind: String,
    version: u32,
    encrypted: bool,
    accounts: Vec<BackupAccountOut>,
}

#[tauri::command(async)]
pub fn export_backup(
    state: State<'_, Arc<AppState>>,
    path: String,
    encrypted: bool,
    password: Option<String>,
    master_password: Option<String>,
) -> Cmd<String> {
    let password = secret_str(password);
    let master_password = secret_str(master_password);
    // Re-authentication gate: exporting secrets requires proving vault access again.
    if vault_mode(&state)? == "password" {
        let mp = master_password
            .filter(|p| !p.is_empty())
            .ok_or("enter your master password to export secrets")?;
        if !verify_master_password(&state, &mp)? {
            return Err("incorrect master password".into());
        }
    }

    let accounts: Vec<BackupAccountOut> = with_session(&state, |s| {
        Ok(s.accounts
            .iter()
            .map(|a| BackupAccountOut {
                issuer: a.issuer.clone(),
                name: a.name.clone(),
                group: a.group.clone(),
                flavor: a.flavor.as_str().into(),
                secret: b32_encode(&a.secret),
                algorithm: a.algorithm.as_str().into(),
                digits: a.digits,
                period: a.period,
                kind: if a.kind.is_hotp() { "hotp".into() } else { "totp".into() },
                counter: match a.kind {
                    Kind::Hotp { counter } => counter,
                    _ => 0,
                },
            })
            .collect())
    })?;
    if accounts.is_empty() {
        return Err("nothing to export".into());
    }
    let count = accounts.len();
    let backup = PlainBackup {
        app: "authio".into(),
        kind: "backup".into(),
        version: vault::FORMAT_VERSION,
        encrypted,
        accounts,
    };
    let json = Zeroizing::new(serde_json::to_vec(&backup).map_err(|e| e.to_string())?);
    let dest = Path::new(&path);
    if vault::is_protected_path(dest, &state.vault_path, &state.settings_path) {
        return Err("that is Authio's own data file — choose a different name or folder for the backup".into());
    }

    if encrypted {
        let pw = password.filter(|p| min_chars(p, 8)).ok_or("the backup passphrase must be at least 8 characters")?;
        let salt = crypto::rand_bytes::<{ crypto::SALT_LEN }>();
        let key = crypto::argon2id_derive(pw.as_bytes(), &salt, crypto::ARGON2_M_KIB, crypto::ARGON2_T, crypto::ARGON2_P)?;
        let kdf = Kdf::Argon2id {
            m: crypto::ARGON2_M_KIB,
            t: crypto::ARGON2_T,
            p: crypto::ARGON2_P,
            salt: STANDARD.encode(salt),
        };
        vault::write_envelope(dest, "backup", &kdf, &key, &json)?;
        Ok(format!("Exported {count} account(s), encrypted with your backup passphrase."))
    } else {
        let pretty = Zeroizing::new(serde_json::to_string_pretty(&backup).map_err(|e| e.to_string())?);
        vault::write_user_file(dest, pretty.as_bytes())?;
        Ok(format!("Exported {count} account(s) WITHOUT encryption — guard this file carefully."))
    }
}

// ---------------------------------------------------------------------------
// Import: start (preview) → preview confirms → apply

#[tauri::command(async)]
pub fn import_text(state: State<'_, Arc<AppState>>, text: String, password: Option<String>) -> Cmd<PreviewDto> {
    let password = secret_str(password);
    do_import(&state, &text, password.as_ref().map(|p| p.as_str()))
}

#[tauri::command(async)]
pub fn import_file(state: State<'_, Arc<AppState>>, path: String, password: Option<String>) -> Cmd<PreviewDto> {
    let password = secret_str(password);
    let bytes = std::fs::read(&path).map_err(|e| format!("cannot read file: {e}"))?;
    let text = String::from_utf8(bytes).map_err(|_| "file is not UTF-8 text (backups are JSON/text files)".to_string())?;
    do_import(&state, &text, password.as_ref().map(|p| p.as_str()))
}

/// Maximum images per batch (guards against selecting a whole photo library).
const MAX_QR_FILES: usize = 50;

/// Read every QR code from one or more images and stage ALL their accounts as a
/// single pending import (one preview, one confirmation). An image without a
/// readable QR, or with an unusable one, never aborts the rest of the batch.
#[tauri::command(async)]
pub fn import_qr_files(state: State<'_, Arc<AppState>>, paths: Vec<String>) -> Cmd<PreviewDto> {
    state.touch();
    if paths.is_empty() {
        return Err("no image selected".into());
    }
    if paths.len() > MAX_QR_FILES {
        return Err(format!("too many images selected (max {MAX_QR_FILES} at a time)"));
    }
    let mut drafts: Vec<Draft> = Vec::new();
    let mut skipped = 0u32;
    let mut files_failed = 0u32;
    let mut merged = 0u32;
    let mut first_err: Option<String> = None;
    let mut formats: Vec<String> = Vec::new();

    for path in &paths {
        let contents = match qr::decode_all_from_file(path) {
            Ok(c) => c,
            Err(e) => {
                files_failed += 1;
                first_err.get_or_insert(e);
                continue;
            }
        };
        let mut file_ok = false;
        for content in contents {
            match importers::parse_text(&content, None) {
                Ok(o) if !o.needs_password => {
                    file_ok = true;
                    skipped += o.skipped;
                    if !formats.contains(&o.format) {
                        formats.push(o.format.clone());
                    }
                    for d in o.drafts {
                        // The same account scanned twice (two screenshots, or a QR
                        // repeated in several images) is merged, not listed twice.
                        if drafts.iter().any(|x| x.secret.as_slice() == d.secret.as_slice()) {
                            merged += 1;
                        } else {
                            drafts.push(d);
                        }
                    }
                }
                Ok(_) => skipped += 1,
                Err(e) => {
                    // A QR that is not an authenticator code (a URL, Wi-Fi, …).
                    skipped += 1;
                    first_err.get_or_insert(e);
                }
            }
        }
        if !file_ok {
            files_failed += 1;
        }
    }
    if drafts.is_empty() {
        return Err(first_err.unwrap_or_else(|| "no QR code found in the selected images".into()));
    }
    let format = if formats.len() == 1 { formats.remove(0) } else { "qr".to_string() };
    build_preview(&state, format, drafts, skipped, (paths.len() as u32, files_failed, merged))
}

fn do_import(state: &AppState, text: &str, password: Option<&str>) -> Cmd<PreviewDto> {
    let outcome = importers::parse_text(text, password)?;
    if outcome.needs_password {
        return Ok(PreviewDto {
            format: outcome.format,
            needs_password: true,
            skipped: 0,
            entries: Vec::new(),
            files_total: 0,
            files_failed: 0,
            merged_duplicates: 0,
        });
    }
    build_preview(state, outcome.format, outcome.drafts, outcome.skipped, (0, 0, 0))
}

/// Stage `drafts` as the pending import and describe them for the preview dialog.
/// `batch` = (files_total, files_failed, merged_duplicates).
fn build_preview(
    state: &AppState,
    format: String,
    drafts: Vec<Draft>,
    skipped: u32,
    batch: (u32, u32, u32),
) -> Cmd<PreviewDto> {
    state.touch();
    let entries = with_session(state, |s| {
        Ok(drafts
            .iter()
            .enumerate()
            .map(|(i, d)| PreviewEntry {
                index: i as u32,
                issuer: d.issuer.clone(),
                name: d.name.clone(),
                kind: match d.kind {
                    Kind::Totp => "totp".into(),
                    Kind::Hotp { .. } => "hotp".into(),
                },
                algorithm: d.algorithm.as_str().into(),
                digits: d.digits,
                period: d.period,
                duplicate: s.accounts.iter().any(|a| a.matches_dup(d)),
            })
            .collect::<Vec<_>>())
    })?;
    let mut guard = state.pending.lock().map_err(|_| "internal error (state lock)".to_string())?;
    *guard = Some(PendingImport { drafts });
    Ok(PreviewDto {
        format,
        needs_password: false,
        skipped,
        entries,
        files_total: batch.0,
        files_failed: batch.1,
        merged_duplicates: batch.2,
    })
}

#[tauri::command]
pub fn import_apply(state: State<'_, Arc<AppState>>, indices: Vec<u32>) -> Cmd<Vec<AccountDto>> {
    state.touch();
    let pending = {
        let mut guard = state.pending.lock().map_err(|_| "internal error (state lock)".to_string())?;
        guard.take().ok_or("no pending import — start the import again")?
    };
    let added = mutate_persist(&state, |accounts| {
        let mut added = Vec::new();
        let mut next_sort = accounts.iter().map(|a| a.sort).max().unwrap_or(0);
        for idx in indices {
            let Some(draft) = pending.drafts.get(idx as usize) else { continue };
            if accounts.iter().any(|a| a.secret.as_slice() == draft.secret.as_slice()) {
                continue; // exact duplicates never get in, even if forced
            }
            next_sort += 1;
            let account = draft.clone().into_account(new_id(), next_sort, now_unix());
            added.push(account_dto(&account));
            accounts.push(account);
        }
        if added.is_empty() {
            return Err("nothing was imported (all selected accounts were duplicates)".into());
        }
        Ok(added)
    })?;
    Ok(added)
}

// ---------------------------------------------------------------------------
// Settings & activity

#[tauri::command]
pub fn get_settings(state: State<'_, Arc<AppState>>) -> Settings {
    state.settings.lock().map(|s| s.clone()).unwrap_or_default()
}

#[tauri::command]
pub fn set_settings(app: tauri::AppHandle, state: State<'_, Arc<AppState>>, mut settings: Settings) -> Cmd<()> {
    settings.font_scale = settings.font_scale.clamp(80, 140);
    settings.auto_lock_minutes = settings.auto_lock_minutes.min(240);
    let tray_enabled = settings.tray;
    {
        let mut guard = state.settings.lock().map_err(|_| "internal error (state lock)".to_string())?;
        // Never let the UI overwrite the persisted window geometry.
        settings.window = guard.window;
        *guard = settings;
    }
    // Apply the tray toggle immediately (no restart needed).
    if let Some(tray) = app.tray_by_id("authio-tray") {
        let _ = tray.set_visible(tray_enabled);
    }
    state.save_settings();
    state.touch();
    Ok(())
}

#[tauri::command]
pub fn user_activity(state: State<'_, Arc<AppState>>) {
    state.touch();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::mem::MemKeyStore;
    use crate::keystore::KeyStore;
    use std::path::PathBuf;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("authio-cmd-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn app(tag: &str, ks: &Arc<MemKeyStore>) -> AppState {
        AppState::with_keystore(dir(tag), ks.clone())
    }

    fn lock(state: &AppState) {
        *state.session.lock().unwrap() = None;
    }

    fn add_account(state: &AppState, issuer: &str) {
        let d = otpauth::parse_otpauth(&format!("otpauth://totp/{issuer}:me?secret=JBSWY3DPEHPK3PXP&issuer={issuer}")).ok().unwrap();
        with_session(state, |s| {
            s.accounts.push(d.into_account(new_id(), 1, 0));
            Ok(())
        })
        .unwrap();
        persist(state).unwrap();
    }

    fn accounts(state: &AppState) -> Vec<String> {
        with_session(state, |s| Ok(s.accounts.iter().map(|a| a.issuer.clone()).collect())).unwrap()
    }

    fn header_key(state: &AppState) -> Option<[u8; 32]> {
        match vault::read_envelope(&state.vault_path).unwrap().kdf {
            Kdf::None { key } => Some(STANDARD.decode(key).unwrap().try_into().unwrap()),
            _ => None,
        }
    }

    fn entry_keys(ks: &MemKeyStore) -> Vec<String> {
        let mut v: Vec<String> = ks.map.lock().unwrap().keys().filter(|k| k.starts_with("vault-key")).cloned().collect();
        v.sort();
        v
    }

    #[test]
    fn two_keychain_vaults_do_not_overwrite_each_others_key() {
        let ks = Arc::new(MemKeyStore::default());
        let a = app("two-a", &ks); // e.g. the installed copy
        let b = app("two-b", &ks); // e.g. a portable copy, same Windows user
        setup_vault_inner(&a, "keychain", None).unwrap();
        add_account(&a, "InA");
        setup_vault_inner(&b, "keychain", None).unwrap();
        add_account(&b, "InB");
        assert_eq!(entry_keys(&ks).len(), 2, "one credential entry per vault");
        assert!(!entry_keys(&ks).contains(&"vault-key".to_string()), "no shared entry any more");
        lock(&a);
        lock(&b);
        unlock_inner(&a, None).unwrap();
        unlock_inner(&b, None).unwrap();
        assert_eq!(accounts(&a), vec!["InA"]);
        assert_eq!(accounts(&b), vec!["InB"]);
    }

    #[test]
    fn failed_setup_leaves_no_orphaned_key() {
        let ks = Arc::new(MemKeyStore::default());
        let a = app("orphan", &ks);
        std::fs::create_dir_all(a.vault_path.with_extension("tmp")).unwrap(); // makes the write fail
        assert!(setup_vault_inner(&a, "keychain", None).is_err());
        assert!(entry_keys(&ks).is_empty());
        assert!(!a.vault_path.exists());
    }

    /// A vault exactly as Authio 1.0 wrote it: no id, key in the single shared entry.
    fn legacy_keychain_vault(tag: &str, ks: &Arc<MemKeyStore>) -> (AppState, [u8; 32]) {
        let a = app(tag, ks);
        let key = crypto::rand_bytes::<32>();
        ks.set(keystore::LEGACY_KEY_USER, &STANDARD.encode(key)).unwrap();
        let payload = br#"{"accounts":[]}"#;
        vault::write_envelope(&a.vault_path, "vault", &Kdf::Keychain, &key, payload).unwrap();
        (a, key)
    }

    #[test]
    fn vault_from_1_0_is_migrated_and_keeps_working() {
        let ks = Arc::new(MemKeyStore::default());
        let (a, key) = legacy_keychain_vault("legacy", &ks);
        unlock_inner(&a, None).unwrap();
        let env = vault::read_envelope(&a.vault_path).unwrap();
        let id = env.vault_id.clone().expect("vault got an id");
        // key copied to the vault's own entry; legacy entry untouched
        assert_eq!(ks.get(&keystore::key_user(&id)).unwrap(), STANDARD.encode(key));
        assert_eq!(ks.get(keystore::LEGACY_KEY_USER).unwrap(), STANDARD.encode(key));
        // and it no longer depends on the legacy entry
        ks.delete(keystore::LEGACY_KEY_USER);
        lock(&a);
        unlock_inner(&a, None).unwrap();
    }

    #[test]
    fn failed_migration_never_breaks_the_vault() {
        let ks = Arc::new(MemKeyStore::default());
        let (a, _key) = legacy_keychain_vault("legacy-fail", &ks);
        *ks.fail_sets.lock().unwrap() = true;
        unlock_inner(&a, None).unwrap(); // upgrade fails silently
        assert!(vault::read_envelope(&a.vault_path).unwrap().vault_id.is_none());
        lock(&a);
        unlock_inner(&a, None).unwrap(); // still opens through the legacy entry
        *ks.fail_sets.lock().unwrap() = false;
        lock(&a);
        unlock_inner(&a, None).unwrap();
        // the next successful unlock completes the upgrade
        assert!(vault::read_envelope(&a.vault_path).unwrap().vault_id.is_some());
    }

    #[test]
    fn switching_to_a_legacy_vaults_keychain_leaves_the_shared_entry_alone() {
        let ks = Arc::new(MemKeyStore::default());
        let (a, key) = legacy_keychain_vault("legacy-leave", &ks);
        unlock_inner(&a, None).unwrap();
        change_unlock_mode_inner(&a, "none", None, None).unwrap();
        // another instance may still use it
        assert_eq!(ks.get(keystore::LEGACY_KEY_USER).unwrap(), STANDARD.encode(key));
        assert_eq!(entry_keys(&ks), vec!["vault-key".to_string()]);
    }

    #[test]
    fn none_to_keychain_rotates_the_key_and_keeps_accounts() {
        let ks = Arc::new(MemKeyStore::default());
        let a = app("rot-none", &ks);
        setup_vault_inner(&a, "none", None).unwrap();
        add_account(&a, "Kept");
        let old_key = header_key(&a).unwrap();
        let old_copy = std::fs::read(&a.vault_path).unwrap(); // e.g. a copy synced to a cloud drive
        change_unlock_mode_inner(&a, "keychain", None, None).unwrap();
        let env = vault::read_envelope(&a.vault_path).unwrap();
        let new_key = load_key(&a, &keystore::key_user(env.vault_id.as_deref().unwrap())).unwrap();
        assert_ne!(*new_key, old_key, "key must be fresh");
        assert!(vault::decrypt_envelope(&env, &old_key).is_err(), "old key must not open the new vault");
        // the old copy still opens (it always will) — but it holds nothing newer
        let old_env: vault::Envelope = serde_json::from_slice(&old_copy).unwrap();
        assert!(vault::decrypt_envelope(&old_env, &old_key).is_ok());
        lock(&a);
        unlock_inner(&a, None).unwrap();
        assert_eq!(accounts(&a), vec!["Kept"]);
    }

    #[test]
    fn keychain_to_none_and_keychain_to_keychain_also_rotate() {
        let ks = Arc::new(MemKeyStore::default());
        let a = app("rot-kc", &ks);
        setup_vault_inner(&a, "keychain", None).unwrap();
        add_account(&a, "K");
        let id1 = vault::read_envelope(&a.vault_path).unwrap().vault_id.unwrap();
        let k1 = ks.get(&keystore::key_user(&id1)).unwrap();
        change_unlock_mode_inner(&a, "keychain", None, None).unwrap();
        let id2 = vault::read_envelope(&a.vault_path).unwrap().vault_id.unwrap();
        assert_ne!(id1, id2, "every keychain re-key gets its own entry");
        let k2 = ks.get(&keystore::key_user(&id2)).unwrap();
        assert_ne!(k1, k2);
        assert!(ks.get(&keystore::key_user(&id1)).is_err(), "previous entry removed once the new file is safe");
        assert_eq!(entry_keys(&ks).len(), 1);
        change_unlock_mode_inner(&a, "none", None, None).unwrap();
        let k3 = STANDARD.encode(header_key(&a).unwrap());
        assert_ne!(k2, k3);
        assert!(entry_keys(&ks).is_empty(), "own entry removed when leaving keychain mode");
        lock(&a);
        unlock_inner(&a, None).unwrap();
        assert_eq!(accounts(&a), vec!["K"]);
    }

    #[test]
    fn password_to_keychain_does_not_reuse_the_password_derived_key() {
        let ks = Arc::new(MemKeyStore::default());
        let a = app("rot-pw", &ks);
        setup_vault_inner(&a, "password", Some("correct horse battery")).unwrap();
        add_account(&a, "P");
        let old_env = vault::read_envelope(&a.vault_path).unwrap();
        let Kdf::Argon2id { m, t, p, salt } = old_env.kdf.clone() else { panic!() };
        let pw_key = crypto::argon2id_derive(b"correct horse battery", &STANDARD.decode(salt).unwrap(), m, t, p).unwrap();
        change_unlock_mode_inner(&a, "keychain", Some("correct horse battery"), None).unwrap();
        let env = vault::read_envelope(&a.vault_path).unwrap();
        assert!(vault::decrypt_envelope(&env, &pw_key).is_err(), "someone holding the old password must not open the new vault");
        lock(&a);
        unlock_inner(&a, None).unwrap();
        assert_eq!(accounts(&a), vec!["P"]);
    }

    #[test]
    fn failed_keychain_rekey_keeps_the_old_entry_and_leaves_no_new_one() {
        let ks = Arc::new(MemKeyStore::default());
        let a = app("rollback", &ks);
        setup_vault_inner(&a, "keychain", None).unwrap();
        add_account(&a, "Safe");
        let id = vault::read_envelope(&a.vault_path).unwrap().vault_id.unwrap();
        let before = ks.get(&keystore::key_user(&id)).unwrap();
        std::fs::create_dir_all(a.vault_path.with_extension("tmp")).unwrap(); // make the write fail
        assert!(change_unlock_mode_inner(&a, "keychain", None, None).is_err());
        assert_eq!(ks.get(&keystore::key_user(&id)).unwrap(), before, "old key never touched");
        assert_eq!(entry_keys(&ks).len(), 1, "the half-made new entry is removed again");
        std::fs::remove_dir_all(a.vault_path.with_extension("tmp")).unwrap();
        lock(&a);
        unlock_inner(&a, None).unwrap();
        assert_eq!(accounts(&a), vec!["Safe"]);
    }

    /// The crash the review described: the new key is already in the store, the process dies before
    /// the vault file is replaced. The file on disk must still open with the entry it points to.
    #[test]
    fn crash_between_new_key_and_new_file_loses_nothing() {
        let ks = Arc::new(MemKeyStore::default());
        let a = app("crash", &ks);
        setup_vault_inner(&a, "keychain", None).unwrap();
        add_account(&a, "Survivor");
        // what a re-key does first, then "the power goes out":
        store_key(&a, &keystore::key_user("deadbeefdeadbeefdeadbeefdeadbeef"), &[7u8; 32]).unwrap();
        lock(&a);
        unlock_inner(&a, None).unwrap();
        assert_eq!(accounts(&a), vec!["Survivor"]);
    }

    #[test]
    fn failed_save_rolls_the_account_list_back() {
        let ks = Arc::new(MemKeyStore::default());
        let a = app("memrollback", &ks);
        setup_vault_inner(&a, "none", None).unwrap();
        add_account(&a, "Existing");
        std::fs::create_dir_all(a.vault_path.with_extension("tmp")).unwrap(); // every save fails now
        let d = otpauth::parse_otpauth("otpauth://totp/New:me?secret=GEZDGNBVGY3TQOJQ&issuer=New").ok().unwrap();
        assert!(add_draft(&a, d.clone()).is_err());
        assert_eq!(accounts(&a), vec!["Existing"], "the failed add must not stay in memory");
        // delete / edit / pin / reorder fail the same way, and leave everything as it was
        let id = with_session(&a, |s| Ok(s.accounts[0].id.clone())).unwrap();
        assert!(mutate_persist(&a, |acc| { acc.retain(|x| x.id != id); Ok(()) }).is_err());
        assert_eq!(accounts(&a), vec!["Existing"], "the failed delete must not stay in memory");
        assert!(mutate_persist(&a, |acc| { acc[0].pinned = true; Ok(()) }).is_err());
        assert!(!with_session(&a, |s| Ok(s.accounts[0].pinned)).unwrap());
        // once saving works again, retrying the add succeeds (no bogus "already exists")
        std::fs::remove_dir_all(a.vault_path.with_extension("tmp")).unwrap();
        add_draft(&a, d).unwrap();
        assert_eq!(accounts(&a), vec!["Existing", "New"]);
    }

    #[test]
    fn failed_none_to_keychain_leaves_no_orphan_entry() {
        let ks = Arc::new(MemKeyStore::default());
        let a = app("rollback2", &ks);
        setup_vault_inner(&a, "none", None).unwrap();
        std::fs::create_dir_all(a.vault_path.with_extension("tmp")).unwrap();
        assert!(change_unlock_mode_inner(&a, "keychain", None, None).is_err());
        assert!(entry_keys(&ks).is_empty());
    }

    #[test]
    fn replacing_the_vault_file_is_detected_before_unlocking() {
        let ks = Arc::new(MemKeyStore::default());
        let a = app("integrity", &ks);
        setup_vault_inner(&a, "keychain", None).unwrap();
        lock(&a);
        // healthy: no warning
        let env = vault::read_envelope(&a.vault_path).unwrap();
        assert!(integrity_warning(&a, &env).is_none());
        // attacker swaps in a "no security" vault of their own
        let evil_key = crypto::rand_bytes::<32>();
        vault::write_envelope_id(
            &a.vault_path,
            "vault",
            &Kdf::None { key: STANDARD.encode(evil_key) },
            &evil_key,
            br#"{"accounts":[]}"#,
            Some("evil"),
        )
        .unwrap();
        let env = vault::read_envelope(&a.vault_path).unwrap();
        let w = integrity_warning(&a, &env).expect("warning");
        assert_eq!((w.kind.as_str(), w.was_mode.as_str(), w.now_mode.as_str()), ("mode_changed", "keychain", "none"));
        assert!(unlock_inner(&a, None).is_err(), "must not open silently");
        // the user explicitly trusts it → recorded, unlock proceeds
        let env = vault::read_envelope(&a.vault_path).unwrap();
        record_integrity(&a, env.kdf.mode_name(), env.vault_id.as_deref().unwrap_or(""));
        unlock_inner(&a, None).unwrap();
    }

    #[test]
    fn same_mode_but_different_vault_is_reported_as_replaced() {
        let ks = Arc::new(MemKeyStore::default());
        let a = app("integrity2", &ks);
        setup_vault_inner(&a, "none", None).unwrap();
        lock(&a);
        let k = crypto::rand_bytes::<32>();
        vault::write_envelope_id(&a.vault_path, "vault", &Kdf::None { key: STANDARD.encode(k) }, &k, br#"{"accounts":[]}"#, Some("other-id")).unwrap();
        let env = vault::read_envelope(&a.vault_path).unwrap();
        assert_eq!(integrity_warning(&a, &env).unwrap().kind, "vault_replaced");
    }

    #[test]
    fn no_record_means_no_warning_and_in_app_mode_changes_are_not_flagged() {
        let ks = Arc::new(MemKeyStore::default());
        let (a, _k) = legacy_keychain_vault("tofu", &ks); // upgrade from 1.0: nothing recorded yet
        let env = vault::read_envelope(&a.vault_path).unwrap();
        assert!(integrity_warning(&a, &env).is_none());
        unlock_inner(&a, None).unwrap();
        change_unlock_mode_inner(&a, "none", None, None).unwrap();
        lock(&a);
        let env = vault::read_envelope(&a.vault_path).unwrap();
        assert!(integrity_warning(&a, &env).is_none(), "a change made inside the app is expected");
        unlock_inner(&a, None).unwrap();
    }
}
