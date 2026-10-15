//! Import pipeline: detects the source format, decrypts if necessary, and turns
//! it into validated [`Draft`]s. Each importer is an isolated function with its
//! own tests so per-app format changes never cross-contaminate.

use crate::crypto;
use crate::migration;
use crate::model::{Algorithm, Draft, Flavor, Kind};
use crate::otpauth::{self, b32_decode};
use crate::vault::{self, Kdf};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use zeroize::Zeroizing;

pub struct ImportOutcome {
    pub format: String,
    pub needs_password: bool,
    pub drafts: Vec<Draft>,
    pub skipped: u32,
}

impl ImportOutcome {
    fn ok(format: &str, drafts: Vec<Draft>, skipped: u32) -> Self {
        Self { format: format.into(), needs_password: false, drafts, skipped }
    }
    fn needs_pw(format: &str) -> Self {
        Self { format: format.into(), needs_password: true, drafts: Vec::new(), skipped: 0 }
    }
}

/// Entry point for file contents, pasted text, and decoded QR strings.
pub fn parse_text(text: &str, password: Option<&str>) -> Result<ImportOutcome, String> {
    let t = text.trim();
    if t.is_empty() {
        return Err("nothing to import".into());
    }
    if t.starts_with("otpauth-migration://") {
        return Ok(ImportOutcome::ok(
            "google-migration",
            migration::parse_migration_payload(extract_migration_data(t)?)?,
            0,
        ));
    }
    if t.starts_with('{') || t.starts_with('[') {
        return parse_json(t, password);
    }
    if looks_like_bitwarden_csv(t) {
        return import_bitwarden_csv(t);
    }
    if t.lines().any(|l| l.trim_start().starts_with("otpauth://")) {
        let mut drafts = Vec::new();
        let mut skipped = 0;
        for line in t.lines() {
            let line = line.trim();
            if line.starts_with("otpauth://") {
                match otpauth::parse_otpauth(line) {
                    Ok(d) => drafts.push(d),
                    Err(_) => skipped += 1,
                }
            }
        }
        if drafts.is_empty() {
            return Err("found otpauth URIs but none were valid".into());
        }
        return Ok(ImportOutcome::ok("otpauth-list", drafts, skipped));
    }
    Err("unrecognized format (expected an Authio/Aegis/Authme backup, otpauth URIs, or a Google migration code)".into())
}

fn extract_migration_data(uri: &str) -> Result<&str, String> {
    uri.split("data=")
        .nth(1)
        .map(|s| s.split('&').next().unwrap_or(s))
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "migration URI has no data parameter".into())
}

// ---------------------------------------------------------------------------
// JSON dispatch

fn parse_json(t: &str, password: Option<&str>) -> Result<ImportOutcome, String> {
    let v: serde_json::Value = serde_json::from_str(t).map_err(|_| "file is not valid JSON".to_string())?;

    if v.get("app").and_then(|a| a.as_str()) == Some("authio") {
        if v.get("kdf").is_some() {
            return import_authio_encrypted(t, password);
        }
        return Ok(ImportOutcome::ok("authio-plain", parse_authio_plain(&v)?, 0));
    }
    if v.get("header").is_some() && v.get("db").is_some() {
        return import_aegis(&v, password);
    }
    if v.get("servicesEncrypted").is_some() {
        return Err("encrypted 2FAS backups are not supported — export from 2FAS without a password".into());
    }
    if let Some(s) = v.get("services") {
        if s.is_array() {
            return import_2fas(&v);
        }
    }
    if v.get("shared_secret").is_some() {
        return import_steam_mafile(&v);
    }
    if v.get("secrets").is_some() || v.is_array() {
        import_dispatch_array(&v)
    } else {
        Err("unsupported JSON format (not Authio, Aegis, Authme, 2FAS, Raivo, andOTP, or a Steam maFile)".into())
    }
}

/// Free-form JSON arrays: pick the concrete importer by the first entry's
/// field signature — Raivo ("kind"), andOTP ("label"+"type"), else Authme's
/// tolerant mapping.
fn import_dispatch_array(v: &serde_json::Value) -> Result<ImportOutcome, String> {
    let arr = if let Some(s) = v.get("secrets") {
        s.as_array().ok_or("Authme export: 'secrets' is not an array")?
    } else {
        v.as_array().ok_or("expected a JSON array of accounts")?
    };
    let first = arr.first();
    if first.is_some_and(|e| e.get("kind").is_some()) {
        return import_raivo(arr);
    }
    if first.is_some_and(|e| e.get("label").is_some() && e.get("type").is_some()) {
        return import_andotp(arr);
    }
    import_authme_entries(arr)
}

// ---------------------------------------------------------------------------
// Authio backups

#[derive(Deserialize)]
struct BackupAccount {
    #[serde(default)]
    issuer: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    flavor: Option<String>,
    secret: String,
    #[serde(default)]
    algorithm: Option<String>,
    #[serde(default)]
    digits: Option<u32>,
    #[serde(default)]
    period: Option<u32>,
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    counter: Option<u64>,
}

impl BackupAccount {
    fn to_draft(&self) -> Result<Draft, String> {
        let flavor = match self.flavor.as_deref() {
            None | Some("") => Flavor::Standard, // old backups predate the field
            Some(f) => Flavor::parse(f).ok_or_else(|| "unknown account flavor in backup".to_string())?,
        };
        let d = Draft {
            issuer: self.issuer.clone(),
            name: self.name.clone(),
            secret: Zeroizing::new(b32_decode(&self.secret)?),
            algorithm: if flavor == Flavor::Steam {
                Algorithm::SHA1
            } else {
                self.algorithm.as_deref().and_then(Algorithm::parse).unwrap_or_default()
            },
            digits: if flavor == Flavor::Steam { 5 } else { self.digits.unwrap_or(6) },
            period: if flavor == Flavor::Steam { 30 } else { self.period.unwrap_or(30) },
            kind: if self.kind.as_deref() == Some("hotp") {
                Kind::Hotp { counter: self.counter.unwrap_or(0) }
            } else {
                Kind::Totp
            },
            flavor,
            group: self.group.clone().unwrap_or_default(),
        };
        d.validate()?;
        Ok(d)
    }
}

fn parse_authio_plain(v: &serde_json::Value) -> Result<Vec<Draft>, String> {
    let accounts = v
        .get("accounts")
        .and_then(|a| a.as_array())
        .ok_or("Authio backup has no accounts array")?;
    let mut drafts = Vec::new();
    for (i, a) in accounts.iter().enumerate() {
        let acc: BackupAccount = serde_json::from_value(a.clone())
            .map_err(|_| format!("corrupt account entry #{} in backup", i + 1))?;
        drafts.push(acc.to_draft().map_err(|e| format!("account #{}: {e}", i + 1))?);
    }
    if drafts.is_empty() {
        return Err("backup contains no accounts".into());
    }
    Ok(drafts)
}

fn import_authio_encrypted(t: &str, password: Option<&str>) -> Result<ImportOutcome, String> {
    if password.is_none() {
        return Ok(ImportOutcome::needs_pw("authio-encrypted"));
    }
    let pw = password.unwrap();
    let env: vault::Envelope = serde_json::from_str(t).map_err(|_| "malformed Authio backup envelope".to_string())?;
    let Kdf::Argon2id { m, t: t_cost, p, salt } = env.kdf.clone() else {
        return Err("this file is locked to an OS keychain and is not portable; export an encrypted backup with a passphrase instead".into());
    };
    let salt = STANDARD.decode(&salt).map_err(|_| "corrupt backup header (salt)".to_string())?;
    let key = crypto::argon2id_derive(pw.as_bytes(), &salt, m, t_cost, p)?;
    let plain = vault::decrypt_envelope(&env, &key)?;
    let v: serde_json::Value = serde_json::from_slice(&plain).map_err(|_| "decrypted payload is not valid (wrong password?)".to_string())?;
    Ok(ImportOutcome::ok("authio-encrypted", parse_authio_plain(&v)?, 0))
}

// ---------------------------------------------------------------------------
// Aegis (https://getaegis.app) — plain and scrypt+AES-256-GCM vaults

#[derive(Deserialize)]
struct AegisParams {
    nonce: String,
    tag: String,
}

#[derive(Deserialize)]
struct AegisSlot {
    #[serde(rename = "type")]
    typ: u32,
    salt: String,
    key: String,
    key_params: AegisParams,
    #[serde(default = "aegis_n")]
    n: u32,
    #[serde(default = "aegis_r")]
    r: u32,
    #[serde(default = "aegis_p")]
    p: u32,
}
fn aegis_n() -> u32 {
    32_768
}
fn aegis_r() -> u32 {
    8
}
fn aegis_p() -> u32 {
    1
}

#[derive(Deserialize)]
struct AegisDb {
    #[serde(default)]
    entries: Vec<AegisEntry>,
}

#[derive(Deserialize)]
struct AegisEntry {
    #[serde(rename = "type")]
    typ: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    issuer: Option<String>,
    info: AegisInfo,
}

#[derive(Deserialize)]
struct AegisInfo {
    secret: String,
    #[serde(default)]
    algo: Option<String>,
    #[serde(default)]
    digits: Option<u32>,
    #[serde(default)]
    period: Option<u32>,
    #[serde(default)]
    counter: Option<u64>,
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid hex data in Aegis vault".into());
    }
    Ok((0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or(0))
        .collect())
}

fn import_aegis(v: &serde_json::Value, password: Option<&str>) -> Result<ImportOutcome, String> {
    let header = v.get("header").ok_or("corrupt Aegis vault (no header)")?;
    let db_val = v.get("db").ok_or("corrupt Aegis vault (no db)")?;

    if db_val.is_object() || db_val.get("entries").is_some() {
        return parse_aegis_db(db_val.clone(), "aegis-plain");
    }
    let db_b64 = db_val.as_str().ok_or("corrupt Aegis vault (db is neither object nor string)")?;

    if password.is_none() {
        return Ok(ImportOutcome::needs_pw("aegis-encrypted"));
    }
    let pw = password.unwrap();

    let slots: Vec<AegisSlot> = serde_json::from_value(
        header.get("slots").cloned().ok_or("corrupt Aegis vault (no slots)")?,
    )
    .map_err(|_| "corrupt Aegis vault (slots)".to_string())?;
    let slot = slots
        .into_iter()
        .find(|s| s.typ == 1)
        .ok_or("Aegis vault has no password-unlock slot (biometric-only vaults are unsupported)")?;
    if !slot.n.is_power_of_two() {
        return Err("unsupported scrypt N in Aegis vault".into());
    }
    let log_n = slot.n.trailing_zeros() as u8;

    let slot_salt = hex_decode(&slot.salt)?;
    let slot_key_ct = hex_decode(&slot.key)?;
    let slot_nonce = hex_decode(&slot.key_params.nonce)?;
    let slot_tag = hex_decode(&slot.key_params.tag)?;

    let enc_key = crypto::scrypt_derive(pw.as_bytes(), &slot_salt, log_n, slot.r, slot.p)?;
    let master_raw = {
        let mut ct = slot_key_ct.clone();
        ct.extend_from_slice(&slot_tag);
        crypto::decrypt(&enc_key, &slot_nonce, &ct)
            .map_err(|_| "wrong Aegis password (or tampered vault)".to_string())?
    };
    let master: &[u8; 32] = master_raw
        .as_slice()
        .try_into()
        .map_err(|_| "Aegis master key has unexpected length".to_string())?;

    let header_params: AegisParams = serde_json::from_value(
        header.get("params").cloned().ok_or("corrupt Aegis vault (no payload params)")?,
    )
    .map_err(|_| "corrupt Aegis vault (payload params)".to_string())?;
    let db_ct_raw = STANDARD.decode(db_b64).map_err(|_| "corrupt Aegis vault (db encoding)".to_string())?;
    let mut db_ct = db_ct_raw;
    db_ct.extend_from_slice(&hex_decode(&header_params.tag)?);
    let plain = crypto::decrypt(master, &hex_decode(&header_params.nonce)?, &db_ct)
        .map_err(|_| "Aegis vault payload failed integrity check".to_string())?;

    let db_val: serde_json::Value = serde_json::from_slice(&plain).map_err(|_| "decrypted Aegis db is not valid JSON".to_string())?;
    parse_aegis_db(db_val, "aegis-encrypted")
}

fn parse_aegis_db(db_val: serde_json::Value, format: &str) -> Result<ImportOutcome, String> {
    let db: AegisDb = serde_json::from_value(db_val).map_err(|_| "cannot parse Aegis entries".to_string())?;
    let mut drafts = Vec::new();
    let mut skipped = 0;
    for e in db.entries {
        let kind = match e.typ.as_str() {
            "totp" | "hotp" => e.typ.as_str(),
            _ => {
                skipped += 1; // e.g. steam/motp entries are specialized formats
                continue;
            }
        };
        let res: Result<Draft, String> = (|| {
            let d = Draft {
                issuer: e.issuer.clone().unwrap_or_default().trim().to_string(),
                name: e.name.trim().to_string(),
                secret: Zeroizing::new(b32_decode(&e.info.secret)?),
                algorithm: e.info.algo.as_deref().and_then(Algorithm::parse).unwrap_or_default(),
                digits: e.info.digits.unwrap_or(6),
                period: e.info.period.unwrap_or(30),
                kind: if kind == "hotp" {
                    Kind::Hotp { counter: e.info.counter.unwrap_or(0) }
                } else {
                    Kind::Totp
                },
                flavor: Flavor::Standard,
                group: String::new(),
            };
            d.validate()?;
            Ok(d)
        })();
        match res {
            Ok(d) => drafts.push(d),
            Err(_) => skipped += 1,
        }
    }
    if drafts.is_empty() && skipped == 0 {
        return Err("Aegis vault contains no entries".into());
    }
    Ok(ImportOutcome::ok(format, drafts, skipped))
}

// ---------------------------------------------------------------------------
// Authme (https://authme.levminer.com) — tolerant shape detection

fn import_authme_entries(arr: &[serde_json::Value]) -> Result<ImportOutcome, String> {
    let mut drafts = Vec::new();
    let mut skipped = 0;
    for e in arr {
        let str_field = |keys: &[&str]| -> Option<String> {
            keys.iter()
                .find_map(|k| e.get(*k).and_then(|x| x.as_str()).map(|s| s.to_string()))
        };
        let res: Result<Draft, String> = (|| {
            let secret = str_field(&["secret", "key"]).ok_or("missing secret")?;
            let issuer = str_field(&["issuer", "account", "service"]).unwrap_or_default();
            let name = str_field(&["name", "label"]).unwrap_or_else(|| {
                if issuer.is_empty() { "Imported account".into() } else { issuer.clone() }
            });
            let algorithm = str_field(&["algorithm", "algo"])
                .and_then(|a| Algorithm::parse(&a))
                .unwrap_or_default();
            let digits = e.get("digits").and_then(|d| d.as_u64()).map(|d| d as u32).unwrap_or(6);
            let d = Draft {
                issuer: issuer.trim().to_string(),
                name: name.trim().to_string(),
                secret: Zeroizing::new(b32_decode(&secret)?),
                algorithm,
                digits,
                period: 30,
                kind: Kind::Totp,
                flavor: Flavor::Standard,
                group: String::new(),
            };
            d.validate()?;
            Ok(d)
        })();
        match res {
            Ok(d) => drafts.push(d),
            Err(_) => skipped += 1,
        }
    }
    if drafts.is_empty() {
        return Err("no valid accounts found in Authme export".into());
    }
    Ok(ImportOutcome::ok("authme", drafts, skipped))
}

// ---------------------------------------------------------------------------
// 2FAS (https://2fas.com) — plain backup JSON (encrypted exports are rejected
// earlier with a dedicated message)

fn import_2fas(v: &serde_json::Value) -> Result<ImportOutcome, String> {
    let services = v
        .get("services")
        .and_then(|s| s.as_array())
        .ok_or("2FAS backup has no services array")?;
    let mut drafts = Vec::new();
    let mut skipped = 0;
    for svc in services {
        let res: Result<Draft, String> = (|| {
            let secret = svc.get("secret").and_then(|s| s.as_str()).ok_or("missing secret")?;
            let otp = svc.get("otp").cloned().unwrap_or(serde_json::Value::Null);
            let otp_str = |k: &str| otp.get(k).and_then(|x| x.as_str()).map(|s| s.to_string());
            let otp_num = |k: &str, d: u32| -> u32 {
                otp.get(k).and_then(|x| x.as_u64()).map(|x| x as u32).unwrap_or(d)
            };
            let svc_name = svc.get("name").and_then(|s| s.as_str()).unwrap_or("").trim().to_string();
            let is_hotp = otp_str("tokenType").map(|t| t.eq_ignore_ascii_case("hotp")).unwrap_or(false);
            let d = Draft {
                issuer: otp_str("issuer").filter(|i| !i.trim().is_empty()).unwrap_or_else(|| svc_name.clone()),
                name: otp_str("account").filter(|a| !a.trim().is_empty()).unwrap_or(svc_name),
                secret: Zeroizing::new(b32_decode(secret)?),
                algorithm: otp_str("algorithm").and_then(|a| Algorithm::parse(&a)).unwrap_or_default(),
                digits: otp_num("digits", 6),
                period: otp_num("period", 30),
                kind: if is_hotp { Kind::Hotp { counter: otp.get("counter").and_then(|c| c.as_u64()).unwrap_or(0) } } else { Kind::Totp },
                flavor: Flavor::Standard,
                group: String::new(),
            };
            d.validate()?;
            Ok(d)
        })();
        match res {
            Ok(d) => drafts.push(d),
            Err(_) => skipped += 1,
        }
    }
    if drafts.is_empty() {
        return Err("no valid accounts found in 2FAS backup".into());
    }
    Ok(ImportOutcome::ok("2fas", drafts, skipped))
}

// ---------------------------------------------------------------------------
// andOTP (https://github.com/andOTP) — plain backup: JSON array with
// { secret, issuer, label, type, algorithm, digits, period, counter }

fn import_andotp(arr: &[serde_json::Value]) -> Result<ImportOutcome, String> {
    let mut drafts = Vec::new();
    let mut skipped = 0;
    for e in arr {
        let res: Result<Draft, String> = (|| {
            let strf = |k: &str| e.get(k).and_then(|x| x.as_str()).map(|s| s.to_string());
            let num = |k: &str, d: u32| e.get(k).and_then(|x| x.as_u64()).map(|x| x as u32).unwrap_or(d);
            let is_hotp = strf("type").map(|t| t.eq_ignore_ascii_case("hotp")).unwrap_or(false);
            let d = Draft {
                issuer: strf("issuer").unwrap_or_default().trim().to_string(),
                name: strf("label").unwrap_or_default().trim().to_string(),
                secret: Zeroizing::new(b32_decode(&strf("secret").ok_or("missing secret")?)?),
                algorithm: strf("algorithm").and_then(|a| Algorithm::parse(&a)).unwrap_or_default(),
                digits: num("digits", 6),
                period: num("period", 30),
                kind: if is_hotp { Kind::Hotp { counter: e.get("counter").and_then(|c| c.as_u64()).unwrap_or(0) } } else { Kind::Totp },
                flavor: Flavor::Standard,
                group: String::new(),
            };
            d.validate()?;
            Ok(d)
        })();
        match res {
            Ok(d) => drafts.push(d),
            Err(_) => skipped += 1,
        }
    }
    if drafts.is_empty() {
        return Err("no valid accounts found in andOTP backup (encrypted andOTP exports are unsupported)".into());
    }
    Ok(ImportOutcome::ok("andotp", drafts, skipped))
}

// ---------------------------------------------------------------------------
// Raivo (iOS) — raivo-otp-export.json: array with numeric fields as STRINGS:
// { kind, account, secret, issuer, timer, digits, counter, algorithm }

fn import_raivo(arr: &[serde_json::Value]) -> Result<ImportOutcome, String> {
    // Raivo writes numbers as JSON strings — accept both forms.
    let num = |e: &serde_json::Value, k: &str, d: u64| -> u64 {
        match e.get(k) {
            Some(serde_json::Value::String(s)) => s.trim().parse().unwrap_or(d),
            Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(d),
            _ => d,
        }
    };
    let mut drafts = Vec::new();
    let mut skipped = 0;
    for e in arr {
        let res: Result<Draft, String> = (|| {
            let strf = |k: &str| e.get(k).and_then(|x| x.as_str()).map(|s| s.to_string());
            let is_hotp = strf("kind").map(|t| t.eq_ignore_ascii_case("hotp")).unwrap_or(false);
            let d = Draft {
                issuer: strf("issuer").unwrap_or_default().trim().to_string(),
                name: strf("account").unwrap_or_default().trim().to_string(),
                secret: Zeroizing::new(b32_decode(&strf("secret").ok_or("missing secret")?)?),
                algorithm: strf("algorithm").and_then(|a| Algorithm::parse(&a)).unwrap_or_default(),
                digits: num(e, "digits", 6) as u32,
                period: num(e, "timer", 30) as u32,
                kind: if is_hotp { Kind::Hotp { counter: num(e, "counter", 0) } } else { Kind::Totp },
                flavor: Flavor::Standard,
                group: String::new(),
            };
            d.validate()?;
            Ok(d)
        })();
        match res {
            Ok(d) => drafts.push(d),
            Err(_) => skipped += 1,
        }
    }
    if drafts.is_empty() {
        return Err("no valid accounts found in Raivo export".into());
    }
    Ok(ImportOutcome::ok("raivo", drafts, skipped))
}

// ---------------------------------------------------------------------------
// Steam Desktop Authenticator maFile — single JSON object with a base64
// "shared_secret" (raw 20-byte HMAC key, NOT base32) → Steam-flavored account.

fn import_steam_mafile(v: &serde_json::Value) -> Result<ImportOutcome, String> {
    let shared = v
        .get("shared_secret")
        .and_then(|s| s.as_str())
        .ok_or("maFile has no shared_secret")?;
    let raw = STANDARD.decode(shared.trim()).map_err(|_| "invalid shared_secret encoding".to_string())?;
    if raw.len() < 10 {
        return Err("maFile shared_secret is too short".into());
    }
    let name = v
        .get("account_name")
        .and_then(|s| s.as_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("Steam account")
        .trim()
        .to_string();
    let d = Draft {
        issuer: "Steam".into(),
        name,
        secret: Zeroizing::new(raw),
        algorithm: Algorithm::SHA1,
        digits: 5,
        period: 30,
        kind: Kind::Totp,
        flavor: Flavor::Steam,
        group: String::new(),
    };
    d.validate()?;
    Ok(ImportOutcome::ok("steam-mafile", vec![d], 0))
}

// ---------------------------------------------------------------------------
// Bitwarden CSV (Settings → Export vault, "File Format: .csv"): the
// `login_totp` column carries either an otpauth:// URI or a raw Base32 seed.
// Hand-rolled minimal CSV (quoted fields, "" escapes) to keep deps small.

fn csv_fields(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    cur.push('"');
                    chars.next();
                } else {
                    quoted = false;
                }
            } else {
                cur.push(c);
            }
        } else if c == '"' {
            quoted = true;
        } else if c == ',' {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    out.push(cur);
    out
}

pub fn looks_like_bitwarden_csv(t: &str) -> bool {
    let header = t.lines().find(|l| !l.trim().is_empty()).unwrap_or("").to_ascii_lowercase();
    header.contains(',') && header.split(',').any(|c| c.trim() == "login_totp" || c.trim() == "totp")
}

fn import_bitwarden_csv(t: &str) -> Result<ImportOutcome, String> {
    let mut lines = t.lines().filter(|l| !l.trim().is_empty()).peekable();
    let header = lines.next().ok_or("empty file")?.to_ascii_lowercase();
    let cols = csv_fields(&header);
    let idx_of = |names: &[&str]| cols.iter().position(|c| names.contains(&c.trim()));
    let totp_col = idx_of(&["login_totp", "totp"]).ok_or("CSV has no TOTP column")?;
    let name_col = idx_of(&["name", "item_name"]);
    let user_col = idx_of(&["login_username", "username"]);

    let mut drafts = Vec::new();
    let mut skipped = 0;
    for line in lines {
        let row = csv_fields(line.trim_end_matches('\r'));
        let cell = |i: Option<usize>| i.and_then(|i| row.get(i).cloned()).unwrap_or_default().trim().to_string();
        let totp = row.get(totp_col).map(|s| s.trim().to_string()).unwrap_or_default();
        if totp.is_empty() {
            continue; // vault rows without TOTP are not errors — just not ours
        }
        let res: Result<Draft, String> = if totp.starts_with("otpauth://") {
            otpauth::parse_otpauth(&totp)
        } else {
            (|| {
                let d = Draft {
                    issuer: cell(name_col),
                    name: cell(user_col),
                    secret: Zeroizing::new(b32_decode(&totp)?),
                    algorithm: Algorithm::SHA1,
                    digits: 6,
                    period: 30,
                    kind: Kind::Totp,
                    flavor: Flavor::Standard,
                    group: String::new(),
                };
                d.validate()?;
                Ok(d)
            })()
        };
        match res {
            Ok(d) => drafts.push(d),
            Err(_) => skipped += 1,
        }
    }
    if drafts.is_empty() && skipped == 0 {
        return Err("CSV contains no TOTP entries".into());
    }
    if drafts.is_empty() {
        return Err("CSV contains TOTP entries but none were parseable".into());
    }
    Ok(ImportOutcome::ok("bitwarden-csv", drafts, skipped))
}

// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rand_bytes;

    #[test]
    fn imports_2fas_plain_backup() {
        let json = r#"{"services":[
            {"name":"GitLab","secret":"JBSWY3DPEHPK3PXP","updatedAt":1715002704262,
             "otp":{"label":"","account":"alice@x.com","digits":6,"period":30,"algorithm":"SHA1","tokenType":"TOTP","source":"Manual"}},
            {"name":"Router","secret":"JBSWY3DPEHPK3PXP",
             "otp":{"account":"admin","digits":8,"period":60,"algorithm":"SHA256","tokenType":"HOTP","counter":7}},
            {"secret":"too-short"}
        ]}"#;
        let out = parse_text(json, None).unwrap();
        assert_eq!(out.format, "2fas");
        assert_eq!(out.drafts.len(), 2);
        assert_eq!(out.skipped, 1);
        assert_eq!(out.drafts[0].issuer, "GitLab");
        assert_eq!(out.drafts[0].name, "alice@x.com");
        assert_eq!(out.drafts[1].digits, 8);
        assert!(matches!(out.drafts[1].kind, Kind::Hotp { counter: 7 }));
    }

    #[test]
    fn rejects_encrypted_2fas_with_clear_error() {
        let json = r#"{"servicesEncrypted":"longopaqueblob","appVersionCode":100}"#;
        let err = match parse_text(json, None) {
            Ok(_) => panic!("encrypted 2FAS must be rejected"),
            Err(e) => e,
        };
        assert!(err.contains("2FAS"), "unexpected error: {err}");
    }

    #[test]
    fn imports_andotp_backup() {
        let json = r#"[
            {"secret":"JBSWY3DPEHPK3PXP","issuer":"GitHub","label":"alice@x.com","type":"TOTP","algorithm":"SHA256","digits":6,"period":30,"counter":0},
            {"secret":"JBSWY3DPEHPK3PXP","issuer":"Bank","label":"login","type":"HOTP","algorithm":"SHA1","digits":6,"period":30,"counter":3},
            {"type":"TOTP"}
        ]"#;
        let out = parse_text(json, None).unwrap();
        assert_eq!(out.format, "andotp");
        assert_eq!(out.drafts.len(), 2);
        assert_eq!(out.skipped, 1);
        assert_eq!(out.drafts[0].issuer, "GitHub");
        assert_eq!(out.drafts[0].name, "alice@x.com");
        assert!(matches!(out.drafts[1].kind, Kind::Hotp { counter: 3 }));
    }

    #[test]
    fn imports_raivo_export_with_string_numbers() {
        let json = r#"[
            {"kind":"TOTP","account":"me@example.com","secret":"JBSWY3DPEHPK3PXP","iconType":"raivo_repository","issuer":"Google","timer":"30","digits":"6","counter":"0","algorithm":"SHA1","iconValue":"google.png"},
            {"kind":"HOTP","account":"root","secret":"JBSWY3DPEHPK3PXP","issuer":"NAS","timer":"30","digits":"8","counter":"12","algorithm":"SHA512"}
        ]"#;
        let out = parse_text(json, None).unwrap();
        assert_eq!(out.format, "raivo");
        assert_eq!(out.drafts.len(), 2);
        assert_eq!(out.drafts[0].issuer, "Google");
        assert_eq!(out.drafts[0].period, 30);
        assert!(matches!(out.drafts[1].kind, Kind::Hotp { counter: 12 }));
        assert_eq!(out.drafts[1].digits, 8);
    }

    #[test]
    fn imports_steam_mafile_as_steam_flavor() {
        // base64 of 20 bytes — the shape of a real maFile shared_secret.
        let json = format!(
            r#"{{"shared_secret":"{}","account_name":"gaben_w","serial_number":"112233"}}"#,
            STANDARD.encode([9u8; 20])
        );
        let out = parse_text(&json, None).unwrap();
        assert_eq!(out.format, "steam-mafile");
        assert_eq!(out.drafts.len(), 1);
        let d = &out.drafts[0];
        assert_eq!(d.issuer, "Steam");
        assert_eq!(d.name, "gaben_w");
        assert_eq!(d.flavor, Flavor::Steam);
        assert_eq!(d.digits, 5);
        assert_eq!(d.secret.as_slice(), &[9u8; 20]);
    }

    #[test]
    fn imports_bitwarden_csv_totp_column() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                   ,,login,Amazon,,,0,,\"alice@bitwarden.com\",,otpauth://totp/Amazon:alice@bitwarden.com?secret=JBSWY3DPEHPK3PXP&issuer=Amazon&algorithm=SHA1&digits=6&period=30\n\
                   ,,login,\"Quoted, Name\",,,0,,bob,,JBSWY3DPEHPK3PXP\n\
                   ,,login,NoTotp,,,0,,carol,,\n\
                   ,,login,BrokenSeed,,,0,,dave,,NOT!BASE32\n";
        assert!(looks_like_bitwarden_csv(csv));
        let out = parse_text(csv, None).unwrap();
        assert_eq!(out.format, "bitwarden-csv");
        assert_eq!(out.drafts.len(), 2);
        assert_eq!(out.skipped, 1);
        assert_eq!(out.drafts[0].issuer, "Amazon");
        assert_eq!(out.drafts[0].name, "alice@bitwarden.com");
        assert_eq!(out.drafts[1].issuer, "Quoted, Name");
        assert_eq!(out.drafts[1].name, "bob");
    }

    #[test]
    fn otpauth_uri_with_steam_issuer_becomes_steam_flavor() {
        let d = otpauth::parse_otpauth("otpauth://totp/Steam:gaben_w?secret=JBSWY3DPEHPK3PXP&issuer=Steam").unwrap();
        assert_eq!(d.flavor, Flavor::Steam);
        assert_eq!(d.digits, 5);
        assert!(matches!(d.algorithm, Algorithm::SHA1));
    }

    #[test]
    fn imports_otpauth_lines_and_skips_bad_ones() {
        let text = "otpauth://totp/A:a?secret=JBSWY3DPEHPK3PXP\nnot-a-uri\notpauth://totp/B:b?secret=JBSWY3DPEHPK3PXP&digits=8";
        let out = parse_text(text, None).unwrap();
        assert_eq!(out.format, "otpauth-list");
        assert_eq!(out.drafts.len(), 2);
    }

    #[test]
    fn authio_encrypted_backup_roundtrip() {
        let pw = "backup-pass-123";
        let salt = rand_bytes::<16>();
        let kdf = Kdf::Argon2id {
            m: crypto::ARGON2_M_KIB,
            t: crypto::ARGON2_T,
            p: crypto::ARGON2_P,
            salt: STANDARD.encode(salt),
        };
        let key = crypto::argon2id_derive(pw.as_bytes(), &salt, crypto::ARGON2_M_KIB, crypto::ARGON2_T, crypto::ARGON2_P).unwrap();

        let dir = std::env::temp_dir().join(format!("authio-imp-{}", std::process::id()));
        let backup_path = dir.join("backup.json");
        let payload = br#"{"app":"authio","kind":"backup","version":1,"encrypted":true,"accounts":[{"issuer":"GitHub","name":"alice","secret":"JBSWY3DPEHPK3PXP","algorithm":"SHA1","digits":6,"period":30,"type":"totp"}]}"#;
        vault::write_envelope(&backup_path, "backup", &kdf, &key, payload).unwrap();

        // Plain export path.
        let plain_text = String::from_utf8_lossy(payload).into_owned();
        let out = parse_text(&plain_text, None).unwrap();
        assert_eq!(out.format, "authio-plain");
        assert_eq!(out.drafts.len(), 1);
        assert_eq!(out.drafts[0].issuer, "GitHub");

        // Encrypted path: asks for password, fails on wrong password, succeeds on right one.
        let enc_text = std::fs::read_to_string(&backup_path).unwrap();
        assert!(parse_text(&enc_text, None).unwrap().needs_password);
        assert!(parse_text(&enc_text, Some("wrong-pass")).is_err());
        let out2 = parse_text(&enc_text, Some(pw)).unwrap();
        assert_eq!(out2.drafts.len(), 1);
        assert_eq!(out2.drafts[0].name, "alice");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn aegis_plain_import() {
        let json = r#"{
          "version": 1,
          "header": {"slots": [], "params": {}},
          "db": {"version": 2, "entries": [
            {"type":"totp","uuid":"x","name":"alice","issuer":"GitHub","note":"","icon":"","info":{"algo":"SHA1","secret":"JBSWY3DPEHPK3PXP","digits":6,"period":30}},
            {"type":"steam","uuid":"y","name":"s","issuer":"Steam","info":{"algo":"SHA1","secret":"JBSWY3DPEHPK3PXP","digits":5,"period":30}}
          ]}
        }"#;
        let out = parse_text(json, None).unwrap();
        assert_eq!(out.format, "aegis-plain");
        assert_eq!(out.drafts.len(), 1);
        assert_eq!(out.skipped, 1);
    }

    #[test]
    fn authme_tolerant_import() {
        let json = r#"{"secrets":[{"name":"alice","secret":"JBSWY3DPEHPK3PXP","issuer":"GitHub"},{"name":"broken","secret":"!!!","issuer":"X"}]}"#;
        let out = parse_text(json, None).unwrap();
        assert_eq!(out.format, "authme");
        assert_eq!(out.drafts.len(), 1);
        assert_eq!(out.skipped, 1);
    }
}
