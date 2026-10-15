//! Import pipeline: detects the source format, decrypts if necessary, and turns
//! it into validated [`Draft`]s. Each importer is an isolated function with its
//! own tests so per-app format changes never cross-contaminate.

use crate::crypto;
use crate::migration;
use crate::model::{Algorithm, Draft, Kind};
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
    if v.get("secrets").is_some() || v.is_array() {
        return import_authme(&v);
    }
    Err("unsupported JSON format (not Authio, Aegis, or Authme)".into())
}

// ---------------------------------------------------------------------------
// Authio backups

#[derive(Deserialize)]
struct BackupAccount {
    #[serde(default)]
    issuer: String,
    #[serde(default)]
    name: String,
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
        let d = Draft {
            issuer: self.issuer.clone(),
            name: self.name.clone(),
            secret: Zeroizing::new(b32_decode(&self.secret)?),
            algorithm: self.algorithm.as_deref().and_then(Algorithm::parse).unwrap_or_default(),
            digits: self.digits.unwrap_or(6),
            period: self.period.unwrap_or(30),
            kind: if self.kind.as_deref() == Some("hotp") {
                Kind::Hotp { counter: self.counter.unwrap_or(0) }
            } else {
                Kind::Totp
            },
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

fn import_authme(v: &serde_json::Value) -> Result<ImportOutcome, String> {
    let arr: &Vec<serde_json::Value> = if let Some(s) = v.get("secrets") {
        s.as_array().ok_or("Authme export: 'secrets' is not an array")?
    } else {
        v.as_array().ok_or("Authme export is not an array")?
    };
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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rand_bytes;

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
