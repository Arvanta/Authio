//! `otpauth://` URI parsing & serialization, plus tolerant Base32 handling.

use crate::model::{Account, Algorithm, Draft, Flavor, Kind};
use data_encoding::BASE32_NOPAD;
use zeroize::Zeroizing;

/// Tolerant Base32 decode: accepts lowercase, spaces, and missing/wrong padding.
pub fn b32_decode(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if cleaned.is_empty() {
        return Err("empty secret".into());
    }
    // Strict alphabet check first for a clear error message.
    if !cleaned.chars().all(|c| "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".contains(c)) {
        return Err("secret is not valid Base32 (A–Z, 2–7)".into());
    }
    BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map_err(|_| "secret has an invalid Base32 length".to_string())
}

pub fn b32_encode(bytes: &[u8]) -> String {
    BASE32_NOPAD.encode(bytes)
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
        }
        // Note: '+' is kept literal — otpauth encoders use %20 for spaces.
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|pair| {
            let mut it = pair.splitn(2, '=');
            let k = percent_decode(it.next()?);
            let v = percent_decode(it.next().unwrap_or(""));
            Some((k, v))
        })
        .collect()
}

/// Parse `otpauth://totp/...` and `otpauth://hotp/...` URIs into a validated Draft.
pub fn parse_otpauth(uri: &str) -> Result<Draft, String> {
    let rest = uri
        .trim()
        .strip_prefix("otpauth://")
        .ok_or("not an otpauth:// URI")?;
    let (left, query) = match rest.split_once('?') {
        Some((l, q)) => (l, q),
        None => (rest, ""),
    };
    let (type_part, label_part) = left.split_once('/').ok_or("missing account label in URI")?;
    let is_hotp = match type_part.to_ascii_lowercase().as_str() {
        "totp" => false,
        "hotp" => true,
        other => return Err(format!("unsupported otpauth type \"{other}\"")),
    };

    let label = percent_decode(label_part.trim_end_matches('/'));
    let (label_issuer, label_name) = match label.split_once(':') {
        Some((a, b)) => (a.trim().to_string(), b.trim().to_string()),
        None => (String::new(), label.trim().to_string()),
    };

    let params = parse_query(query);
    let get = |k: &str| params.iter().find(|(pk, _)| pk.eq_ignore_ascii_case(k)).map(|(_, v)| v.clone());

    let secret_raw = get("secret").ok_or("URI is missing the secret parameter")?;
    let secret = b32_decode(&secret_raw)?;
    let algorithm = get("algorithm")
        .and_then(|a| Algorithm::parse(&a))
        .unwrap_or_default();
    let digits: u32 = get("digits").and_then(|d| d.parse().ok()).unwrap_or(6);
    let period: u32 = get("period").and_then(|d| d.parse().ok()).unwrap_or(30);
    let counter: u64 = get("counter").and_then(|d| d.parse().ok()).unwrap_or(0);

    // The issuer parameter, when present, wins over the label prefix.
    let issuer = get("issuer").filter(|i| !i.trim().is_empty()).unwrap_or(label_issuer);

    // Steam Guard entries (shared secret in base64 style URIs with
    // issuer=Steam) use Steam's 5-character alphabet rendering.
    let is_steam = issuer.trim().eq_ignore_ascii_case("steam");

    let draft = Draft {
        issuer: issuer.trim().to_string(),
        name: label_name,
        secret: Zeroizing::new(secret),
        algorithm: if is_steam { Algorithm::SHA1 } else { algorithm },
        digits: if is_steam { 5 } else { digits },
        period: if is_steam { 30 } else { period },
        kind: if is_hotp && !is_steam { Kind::Hotp { counter } } else { Kind::Totp },
        flavor: if is_steam { Flavor::Steam } else { Flavor::Standard },
        group: String::new(),
    };
    draft.validate()?;
    Ok(draft)
}

/// Serialize an account back to an otpauth URI (used for "show/reveal secret").
pub fn to_otpauth(a: &Account) -> String {
    let enc = |s: &str| -> String {
        s.chars()
            .map(|c| match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
                _ => format!("%{:02X}", c as u32),
            })
            .collect()
    };
    let label = if a.issuer.is_empty() {
        enc(&a.name)
    } else {
        format!("{}:{}", enc(&a.issuer), enc(&a.name))
    };
    let kind_path = if a.kind.is_hotp() { "hotp" } else { "totp" };
    let mut uri = format!(
        "otpauth://{}/{}?secret={}&algorithm={}&digits={}",
        kind_path,
        label,
        b32_encode(&a.secret),
        a.algorithm.as_str(),
        a.digits
    );
    if !a.issuer.is_empty() {
        uri += &format!("&issuer={}", enc(&a.issuer));
    }
    match a.kind {
        Kind::Totp => uri += &format!("&period={}", a.period),
        Kind::Hotp { counter } => uri += &format!("&counter={}", counter),
    }
    uri
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_totp_uri() {
        let d = parse_otpauth(
            "otpauth://totp/GitHub:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(d.issuer, "GitHub");
        assert_eq!(d.name, "alice@example.com");
        assert_eq!(d.algorithm, Algorithm::SHA256);
        assert_eq!(d.digits, 8);
        assert_eq!(d.period, 60);
        assert_eq!(d.secret.as_slice(), b"Hello!\xde\xad\xbe\xef");
    }

    #[test]
    fn tolerant_base32() {
        assert_eq!(b32_decode("jbsw y3dp ehpk 3pxp").unwrap(), b"Hello!\xde\xad\xbe\xef");
        assert_eq!(b32_decode("JBSWY3DPEHPK3PXP====").unwrap(), b"Hello!\xde\xad\xbe\xef");
        assert!(b32_decode("!!!!").is_err());
        assert!(b32_decode("").is_err());
    }

    #[test]
    fn parses_hotp_with_counter() {
        let d = parse_otpauth("otpauth://hotp/Service:bob?secret=JBSWY3DPEHPK3PXP&counter=42").unwrap();
        match d.kind {
            Kind::Hotp { counter } => assert_eq!(counter, 42),
            _ => panic!("expected hotp"),
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_otpauth("otpauth://totp/x?secret=NOTB32").is_err());
        assert!(parse_otpauth("otpauth://totp/x").is_err());
        assert!(parse_otpauth("https://example.com").is_err());
    }

    #[test]
    fn roundtrip_uri() {
        let d = parse_otpauth("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub").unwrap();
        let a = d.into_account("id1".into(), 0, 0);
        let uri = to_otpauth(&a);
        let d2 = parse_otpauth(&uri).unwrap();
        assert_eq!(d2.issuer, "GitHub");
        assert_eq!(d2.name, "alice");
        assert_eq!(d2.secret.as_slice(), a.secret.as_slice());
    }
}
