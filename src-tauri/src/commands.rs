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
use crate::{crypto, importers, otp, otpauth, qr};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tauri::State;
use zeroize::Zeroizing;

type Cmd<T> = Result<T, String>;

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

fn persist(state: &AppState) -> Cmd<()> {
    with_session(state, |s| {
        let payload = serde_json::to_vec(&AccountsPayloadRef { accounts: &s.accounts })
            .map_err(|e| format!("serialize failure: {e}"))?;
        vault::write_envelope(&state.vault_path, "vault", &s.kdf, &s.key, &payload)
    })
}

fn new_id() -> String {
    crypto::rand_bytes::<16>().iter().map(|b| format!("{b:02x}")).collect()
}

fn keyring_store(key: &[u8; 32]) -> Cmd<()> {
    let entry = keyring::Entry::new("Authio", "vault-key").map_err(|e| format!("OS credential store error: {e}"))?;
    entry
        .set_password(&STANDARD.encode(key))
        .map_err(|e| format!("could not store the vault key in the OS credential store: {e}"))
}

fn keyring_load() -> Cmd<Zeroizing<[u8; 32]>> {
    let entry = keyring::Entry::new("Authio", "vault-key").map_err(|e| format!("OS credential store error: {e}"))?;
    let encoded = entry
        .get_password()
        .map_err(|_| "vault key not found in the OS credential store".to_string())?;
    let raw = STANDARD.decode(&encoded).map_err(|_| "corrupt keychain entry".to_string())?;
    let arr: [u8; 32] = raw.try_into().map_err(|_| "corrupt keychain entry (bad length)".to_string())?;
    Ok(Zeroizing::new(arr))
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
            input.algorithm.as_deref().and_then(Algorithm::parse).unwrap_or_default()
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
    let dto = with_session(state, |s| {
        if s.accounts.iter().any(|a| a.secret.as_slice() == draft.secret.as_slice()) {
            return Err("an account with this exact secret already exists".into());
        }
        let next_sort = s.accounts.iter().map(|a| a.sort).max().unwrap_or(0) + 1;
        let account = draft.into_account(new_id(), next_sort, now_unix());
        let dto = account_dto(&account);
        s.accounts.push(account);
        Ok(dto)
    })?;
    persist(state)?;
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
    StatusDto {
        initialized,
        unlocked: state.is_unlocked(),
        mode,
        // Compile-time version with a fallback so parse-level tooling also compiles.
        version: option_env!("CARGO_PKG_VERSION").unwrap_or("1.0.0").to_string(),
    }
}

#[tauri::command]
pub fn setup_vault(state: State<'_, Arc<AppState>>, mode: String, password: Option<String>) -> Cmd<()> {
    if state.vault_path.exists() {
        return Err("a vault already exists — unlock it instead".into());
    }
    let (kdf, key) = match mode.as_str() {
        "password" => {
            let pw = password.filter(|p| !p.is_empty()).ok_or("master password required")?;
            if pw.len() < 8 {
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
            let key = crypto::rand_bytes::<32>();
            keyring_store(&key)?;
            (Kdf::Keychain, Zeroizing::new(key))
        }
        "none" => {
            let key = crypto::rand_bytes::<32>();
            (
                Kdf::None { key: STANDARD.encode(key) },
                Zeroizing::new(key),
            )
        }
        other => return Err(format!("unknown vault mode \"{other}\"")),
    };
    vault::write_envelope(&state.vault_path, "vault", &kdf, &key, br#"{"accounts":[]}"#)?;
    let mut guard = state.session.lock().map_err(|_| "internal error (state lock)".to_string())?;
    *guard = Some(Session { kdf, key, accounts: Vec::new() });
    state.touch();
    Ok(())
}

#[tauri::command]
pub fn unlock(state: State<'_, Arc<AppState>>, password: Option<String>) -> Cmd<()> {
    let env = vault::read_envelope(&state.vault_path)?;
    let key = match &env.kdf {
        Kdf::Argon2id { m, t, p, salt } => {
            let pw = password.filter(|p| !p.is_empty()).ok_or("master password required")?;
            let salt = STANDARD.decode(salt).map_err(|_| "corrupt vault header (salt)".to_string())?;
            crypto::argon2id_derive(pw.as_bytes(), &salt, *m, *t, *p)?
        }
        Kdf::Keychain => keyring_load()?,
        Kdf::None { key } => {
            let raw = STANDARD.decode(key).map_err(|_| "corrupt vault header (key)".to_string())?;
            let arr: [u8; 32] = raw.try_into().map_err(|_| "corrupt vault header (key length)".to_string())?;
            Zeroizing::new(arr)
        }
    };
    let plain = vault::decrypt_envelope(&env, &key)?; // AEAD tag fails on wrong password
    let payload: AccountsPayload =
        serde_json::from_slice(&plain).map_err(|_| "vault payload is corrupted".to_string())?;
    let mut guard = state.session.lock().map_err(|_| "internal error (state lock)".to_string())?;
    *guard = Some(Session { kdf: env.kdf, key, accounts: payload.accounts });
    state.touch();
    Ok(())
}

#[tauri::command]
pub fn lock(state: State<'_, Arc<AppState>>) {
    state.do_lock();
}

/// Switch the vault's unlock method (password ↔ keychain ↔ none) or change the
/// master password. Requires the vault to be unlocked plus, when the current
/// method is a master password, re-entering that password.
#[tauri::command]
pub fn change_unlock_mode(
    state: State<'_, Arc<AppState>>,
    mode: String,
    current_password: Option<String>,
    new_password: Option<String>,
) -> Cmd<()> {
    state.touch();
    if vault_mode(&state)? == "password" {
        let pw = current_password
            .filter(|p| !p.is_empty())
            .ok_or("enter your current master password")?;
        if !verify_master_password(&state, &pw)? {
            return Err("incorrect master password".into());
        }
    }

    // [u8; 32] is Copy — take an owned key material snapshot for the switch.
    let session_key: Zeroizing<[u8; 32]> = with_session(&state, |s| Ok(Zeroizing::new(*s.key)))?;
    let (new_kdf, new_key) = match mode.as_str() {
        "password" => {
            let pw = new_password
                .filter(|p| p.len() >= 8)
                .ok_or("the new master password must be at least 8 characters")?;
            let salt = crypto::rand_bytes::<{ crypto::SALT_LEN }>();
            let key = crypto::argon2id_derive(pw.as_bytes(), &salt, crypto::ARGON2_M_KIB, crypto::ARGON2_T, crypto::ARGON2_P)?;
            (
                Kdf::Argon2id { m: crypto::ARGON2_M_KIB, t: crypto::ARGON2_T, p: crypto::ARGON2_P, salt: STANDARD.encode(salt) },
                key,
            )
        }
        "keychain" => {
            keyring_store(&session_key)?;
            (Kdf::Keychain, session_key)
        }
        "none" => (Kdf::None { key: STANDARD.encode(&*session_key) }, session_key),
        other => return Err(format!("unknown unlock mode \"{other}\"")),
    };

    let was_keychain = with_session(&state, |s| {
        let payload = serde_json::to_vec(&AccountsPayloadRef { accounts: &s.accounts })
            .map_err(|e| format!("serialize failure: {e}"))?;
        vault::write_envelope(&state.vault_path, "vault", &new_kdf, &new_key, &payload)?;
        let was = matches!(s.kdf, Kdf::Keychain);
        s.kdf = new_kdf.clone();
        s.key = new_key;
        Ok(was)
    })?;
    if was_keychain && mode != "keychain" {
        if let Ok(entry) = keyring::Entry::new("Authio", "vault-key") {
            let _ = entry.delete_credential();
        }
    }
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
    let dto = with_session(&state, |s| {
        let a = s.accounts.iter_mut().find(|a| a.id == id).ok_or("account not found")?;
        match &mut a.kind {
            Kind::Hotp { counter } => {
                let code = otp::hotp(&a.secret, *counter, a.digits, a.algorithm);
                *counter += 1;
                Ok(CodeDto { id: a.id.clone(), code: Some(code), remaining: 0, progress: 0.0 })
            }
            _ => Err("not an HOTP account".into()),
        }
    })?;
    persist(&state)?;
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
    with_session(&state, |s| {
        let a = s.accounts.iter_mut().find(|a| a.id == id).ok_or("account not found")?;
        if issuer.trim().is_empty() && name.trim().is_empty() {
            return Err("account needs at least an issuer or a name".into());
        }
        a.issuer = issuer.trim().to_string();
        a.name = name.trim().to_string();
        a.group = group.trim().to_string();
        Ok(())
    })?;
    persist(&state)?;
    state.touch();
    Ok(())
}

#[tauri::command]
pub fn delete_account(state: State<'_, Arc<AppState>>, id: String) -> Cmd<()> {
    with_session(&state, |s| {
        let before = s.accounts.len();
        s.accounts.retain(|a| a.id != id);
        if s.accounts.len() == before {
            return Err("account not found".into());
        }
        Ok(())
    })?;
    persist(&state)?;
    state.touch();
    Ok(())
}

#[tauri::command]
pub fn set_pinned(state: State<'_, Arc<AppState>>, id: String, pinned: bool) -> Cmd<()> {
    with_session(&state, |s| {
        let a = s.accounts.iter_mut().find(|a| a.id == id).ok_or("account not found")?;
        a.pinned = pinned;
        Ok(())
    })?;
    persist(&state)?;
    state.touch();
    Ok(())
}

#[tauri::command]
pub fn reorder(state: State<'_, Arc<AppState>>, ids: Vec<String>) -> Cmd<()> {
    with_session(&state, |s| {
        for (i, id) in ids.iter().enumerate() {
            if let Some(a) = s.accounts.iter_mut().find(|a| &a.id == id) {
                a.sort = i as u64;
            }
        }
        Ok(())
    })?;
    persist(&state)?;
    state.touch();
    Ok(())
}

#[tauri::command]
pub fn reveal_secret(state: State<'_, Arc<AppState>>, id: String, password: Option<String>) -> Cmd<SecretDto> {
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

#[tauri::command]
pub fn export_backup(
    state: State<'_, Arc<AppState>>,
    path: String,
    encrypted: bool,
    password: Option<String>,
    master_password: Option<String>,
) -> Cmd<String> {
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
    let json = serde_json::to_vec(&backup).map_err(|e| e.to_string())?;
    let dest = Path::new(&path);

    if encrypted {
        let pw = password.filter(|p| p.len() >= 8).ok_or("the backup passphrase must be at least 8 characters")?;
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
        vault::atomic_write(dest, serde_json::to_string_pretty(&backup).map_err(|e| e.to_string())?.as_bytes())?;
        Ok(format!("Exported {count} account(s) WITHOUT encryption — guard this file carefully."))
    }
}

// ---------------------------------------------------------------------------
// Import: start (preview) → preview confirms → apply

#[tauri::command]
pub fn import_text(state: State<'_, Arc<AppState>>, text: String, password: Option<String>) -> Cmd<PreviewDto> {
    do_import(&state, &text, password.as_deref())
}

#[tauri::command]
pub fn import_file(state: State<'_, Arc<AppState>>, path: String, password: Option<String>) -> Cmd<PreviewDto> {
    let bytes = std::fs::read(&path).map_err(|e| format!("cannot read file: {e}"))?;
    let text = String::from_utf8(bytes).map_err(|_| "file is not UTF-8 text (backups are JSON/text files)".to_string())?;
    do_import(&state, &text, password.as_deref())
}

#[tauri::command]
pub fn import_qr(state: State<'_, Arc<AppState>>, path: String) -> Cmd<PreviewDto> {
    state.touch();
    let content = qr::decode_qr_from_file(&path)?;
    if content.trim_start().starts_with("otpauth-migration://") {
        return do_import(&state, &content, None);
    }
    // Single otpauth:// — also route through the preview for consistent UX.
    do_import(&state, &content, None)
}

fn do_import(state: &AppState, text: &str, password: Option<&str>) -> Cmd<PreviewDto> {
    let outcome = importers::parse_text(text, password)?;
    if outcome.needs_password {
        return Ok(PreviewDto { format: outcome.format, needs_password: true, skipped: 0, entries: Vec::new() });
    }
    state.touch();
    let entries = with_session(state, |s| {
        Ok(outcome
            .drafts
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
    *guard = Some(PendingImport { drafts: outcome.drafts });
    Ok(PreviewDto { format: outcome.format, needs_password: false, skipped: outcome.skipped, entries })
}

#[tauri::command]
pub fn import_apply(state: State<'_, Arc<AppState>>, indices: Vec<u32>) -> Cmd<Vec<AccountDto>> {
    state.touch();
    let pending = {
        let mut guard = state.pending.lock().map_err(|_| "internal error (state lock)".to_string())?;
        guard.take().ok_or("no pending import — start the import again")?
    };
    let mut added = Vec::new();
    with_session(&state, |s| {
        let mut next_sort = s.accounts.iter().map(|a| a.sort).max().unwrap_or(0);
        for idx in indices {
            let Some(draft) = pending.drafts.get(idx as usize) else { continue };
            if s.accounts.iter().any(|a| a.secret.as_slice() == draft.secret.as_slice()) {
                continue; // exact duplicates never get in, even if forced
            }
            next_sort += 1;
            let account = draft.clone().into_account(new_id(), next_sort, now_unix());
            added.push(account_dto(&account));
            s.accounts.push(account);
        }
        Ok(())
    })?;
    if added.is_empty() {
        return Err("nothing was imported (all selected accounts were duplicates)".into());
    }
    persist(&state)?;
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
