//! Google Authenticator migration format: `otpauth-migration://offline?data=<base64>`
//! carrying a protobuf payload. A minimal hand-written protobuf-wire parser keeps
//! us dependency-free; only the fields we need are read:

//!   MigrationPayload { repeated OtpParameters otp_parameters = 1; }
//!   OtpParameters { bytes secret = 1; string name = 2; string issuer = 3;
//!                   Algorithm algorithm = 4; DigitCount digits = 5;
//!                   OtpType type = 6; int64 counter = 7; }

use crate::model::{Algorithm, Draft, Kind};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD}, Engine as _};
use zeroize::Zeroizing;

fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0;
    loop {
        if *pos >= buf.len() || shift > 63 {
            return None;
        }
        let b = buf[*pos];
        *pos += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Some(result)
}

fn read_len_delim<'a>(buf: &'a [u8], pos: &mut usize) -> Result<&'a [u8], String> {
    let len = usize::try_from(read_varint(buf, pos).ok_or("truncated protobuf (length)")?)
        .map_err(|_| "truncated protobuf (field)".to_string())?;
    // checked_add: a hostile length near usize::MAX must not wrap around the bound check.
    let end = pos.checked_add(len).filter(|e| *e <= buf.len()).ok_or("truncated protobuf (field)")?;
    let slice = &buf[*pos..end];
    *pos = end;
    Ok(slice)
}

/// Returns the drafts plus the number of entries that had to be skipped
/// (unsupported algorithm such as MD5, invalid secret, …).
pub fn parse_migration_payload(b64: &str) -> Result<(Vec<Draft>, u32), String> {
    let b64 = b64.trim();
    let raw = URL_SAFE_NO_PAD
        .decode(b64)
        .or_else(|_| URL_SAFE.decode(b64))
        .or_else(|_| STANDARD.decode(b64))
        .map_err(|_| "migration data is not valid base64")?;
    let mut pos = 0;
    let mut drafts = Vec::new();
    let mut skipped = 0u32;
    while pos < raw.len() {
        let key = read_varint(&raw, &mut pos).ok_or("truncated protobuf (key)")?;
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        match wire {
            0 => {
                read_varint(&raw, &mut pos).ok_or("truncated protobuf (varint)")?;
            }
            1 => pos = skip_fixed(&raw, pos, 8)?,
            5 => pos = skip_fixed(&raw, pos, 4)?,
            2 => {
                let bytes = read_len_delim(&raw, &mut pos)?;
                if field == 1 {
                    match parse_otp_parameters(bytes) {
                        Ok(d) => drafts.push(d),
                        Err(_) => skipped += 1,
                    }
                }
            }
            w => return Err(format!("unsupported protobuf wire type {w}")),
        }
    }
    if drafts.is_empty() {
        return Err("no accounts found in migration payload".into());
    }
    Ok((drafts, skipped))
}

fn skip_fixed(buf: &[u8], pos: usize, n: usize) -> Result<usize, String> {
    pos.checked_add(n).filter(|e| *e <= buf.len()).ok_or_else(|| "truncated protobuf (fixed field)".to_string())
}

fn parse_otp_parameters(buf: &[u8]) -> Result<Draft, String> {
    let mut secret: Option<Vec<u8>> = None;
    let mut name = String::new();
    let mut issuer = String::new();
    let mut algorithm = Algorithm::SHA1;
    let mut digits: u32 = 6;
    let mut is_totp = true;
    let mut counter: u64 = 0;
    let mut pos = 0;
    while pos < buf.len() {
        let key = read_varint(buf, &mut pos).ok_or("truncated protobuf (entry key)")?;
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        match (field, wire) {
            (1, 2) => secret = Some(read_len_delim(buf, &mut pos)?.to_vec()),
            (2, 2) => name = String::from_utf8_lossy(read_len_delim(buf, &mut pos)?).into_owned(),
            (3, 2) => issuer = String::from_utf8_lossy(read_len_delim(buf, &mut pos)?).into_owned(),
            (4, 0) => {
                algorithm = match read_varint(buf, &mut pos) {
                    Some(2) => Algorithm::SHA256,
                    Some(3) => Algorithm::SHA512,
                    // 4 = MD5: unsupported — silently using SHA-1 would yield wrong codes.
                    Some(4) => return Err("MD5 accounts are not supported".into()),
                    _ => Algorithm::SHA1,
                }
            }
            (5, 0) => digits = if read_varint(buf, &mut pos) == Some(2) { 8 } else { 6 },
            (6, 0) => is_totp = !matches!(read_varint(buf, &mut pos), Some(1)),
            (7, 0) => counter = read_varint(buf, &mut pos).unwrap_or(0),
            (_, 0) => {
                read_varint(buf, &mut pos);
            }
            (_, 2) => {
                let _ = read_len_delim(buf, &mut pos)?;
            }
            (_, 1) => pos = skip_fixed(buf, pos, 8)?,
            (_, 5) => pos = skip_fixed(buf, pos, 4)?,
            _ => return Err("invalid protobuf field".into()),
        }
    }

    // Google sometimes packs "Issuer:account" into the name field.
    if issuer.is_empty() {
        if let Some((a, b)) = name.split_once(':') {
            if !a.trim().is_empty() {
                issuer = a.trim().to_string();
                name = b.trim().to_string();
            }
        }
    }

    let draft = Draft {
        issuer: issuer.trim().to_string(),
        name: name.trim().to_string(),
        secret: Zeroizing::new(secret.ok_or("migration entry has no secret")?),
        algorithm,
        digits,
        period: 30,
        kind: if is_totp { Kind::Totp } else { Kind::Hotp { counter } },
        flavor: crate::model::Flavor::Standard,
        group: String::new(),
    };
    draft.validate()?;
    Ok(draft)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a minimal MigrationPayload with one TOTP/sha1/6 entry.
    fn sample_payload_b64() -> String {
        let secret = *b"\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad"; // 10 random-ish bytes (valid length)
        let mut entry = Vec::new();
        entry.push(0x0a); // field 1, wire 2
        entry.push(secret.len() as u8);
        entry.extend_from_slice(&secret);
        entry.push(0x12); // field 2 (name)
        let name = b"Example:alice";
        entry.push(name.len() as u8);
        entry.extend_from_slice(name);
        entry.push(0x20); // field 4 (algorithm), wire 0: varint 1 = SHA1
        entry.push(0x01);
        entry.push(0x28); // field 5 (digits), wire 0: 0x01 = SIX
        entry.push(0x01);
        entry.push(0x30); // field 6 (type), wire 0: 0x02 = TOTP
        entry.push(0x02);
        let mut payload = Vec::new();
        payload.push(0x0a); // field 1 of payload, wire 2
        payload.push(entry.len() as u8);
        payload.extend_from_slice(&entry);
        URL_SAFE_NO_PAD.encode(payload)
    }

    #[test]
    fn parses_google_migration() {
        let (drafts, skipped) = parse_migration_payload(&sample_payload_b64()).unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].issuer, "Example");
        assert_eq!(drafts[0].name, "alice");
        assert_eq!(drafts[0].digits, 6);
        assert_eq!(drafts[0].algorithm, Algorithm::SHA1);
    }

    #[test]
    fn hostile_length_is_an_error_not_a_panic() {
        // field 1, wire 2, length = u64::MAX
        let mut raw = vec![0x0a];
        raw.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
        assert!(parse_migration_payload(&URL_SAFE_NO_PAD.encode(&raw)).is_err());
        // truncated fixed64 field
        assert!(parse_migration_payload(&URL_SAFE_NO_PAD.encode([0x09u8, 1, 2])).is_err());
    }

    #[test]
    fn md5_entry_is_skipped_not_misrendered() {
        let mut entry = vec![0x0a, 10];
        entry.extend_from_slice(b"0123456789");
        entry.extend_from_slice(&[0x12, 1, b'x', 0x20, 0x04]); // name "x", algorithm = MD5
        let mut good = vec![0x0a, 10];
        good.extend_from_slice(b"0123456789");
        good.extend_from_slice(&[0x12, 1, b'y']);
        let mut payload = vec![0x0a, entry.len() as u8];
        payload.extend_from_slice(&entry);
        payload.extend_from_slice(&[0x0a, good.len() as u8]);
        payload.extend_from_slice(&good);
        let (d, skipped) = parse_migration_payload(&URL_SAFE_NO_PAD.encode(payload)).unwrap();
        assert_eq!((d.len(), skipped), (1, 1));
        assert_eq!(d[0].name, "y");
    }
}
