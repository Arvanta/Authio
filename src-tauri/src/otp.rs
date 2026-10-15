//! Hand-written HOTP (RFC 4226) and TOTP (RFC 6238) implementation.
//!
//! Written from the specs and verified against the official RFC test vectors
//! (see the `tests` module — also executed in CI by `cargo test`).

use crate::model::Algorithm;
use hmac::{digest::KeyInit, Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

fn hmac_digest(algo: Algorithm, key: &[u8], msg: &[u8]) -> Vec<u8> {
    match algo {
        Algorithm::SHA1 => {
            let mut m = <Hmac<Sha1> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
            Mac::update(&mut m, msg);
            m.finalize().into_bytes().to_vec()
        }
        Algorithm::SHA256 => {
            let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
            Mac::update(&mut m, msg);
            m.finalize().into_bytes().to_vec()
        }
        Algorithm::SHA512 => {
            let mut m = <Hmac<Sha512> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
            Mac::update(&mut m, msg);
            m.finalize().into_bytes().to_vec()
        }
    }
}

/// HOTP per RFC 4226 §5.3 — dynamic binary code truncation.
pub fn hotp(secret: &[u8], counter: u64, digits: u32, algo: Algorithm) -> String {
    let mac = hmac_digest(algo, secret, &counter.to_be_bytes());
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let binary = ((mac[offset] as u32 & 0x7f) << 24)
        | ((mac[offset + 1] as u32) << 16)
        | ((mac[offset + 2] as u32) << 8)
        | (mac[offset + 3] as u32);
    let modulus: u64 = 10u64.pow(digits);
    let value = (binary as u64) % modulus;
    format!("{:0width$}", value, width = digits as usize)
}

/// TOTP per RFC 6238 §4.2 — returns (code, seconds_remaining, progress 0..=1).
pub fn totp(
    secret: &[u8],
    period: u32,
    digits: u32,
    algo: Algorithm,
    unix_time: u64,
) -> (String, u64, f64) {
    let period = if period == 0 { 30 } else { period };
    let counter = unix_time / period as u64;
    let code = hotp(secret, counter, digits, algo);
    let remaining = period as u64 - (unix_time % period as u64);
    let progress = remaining as f64 / period as f64;
    (code, remaining, progress)
}

/// Steam's non-standard TOTP variant: five characters from its proprietary
/// 26-symbol alphabet over the vanilla HMAC-SHA1/30-second core. Steam
/// publishes no official vectors; this matches the de-facto reference
/// implementations and is snapshot-tested below.
const STEAM_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";

pub fn totp_steam(secret: &[u8], unix_time: u64) -> (String, u64, f64) {
    const PERIOD: u64 = 30;
    let counter = unix_time / PERIOD;
    let mac = hmac_digest(Algorithm::SHA1, secret, &counter.to_be_bytes());
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let mut value = (((mac[offset] as u32 & 0x7f) << 24)
        | ((mac[offset + 1] as u32) << 16)
        | ((mac[offset + 2] as u32) << 8)
        | (mac[offset + 3] as u32)) as u64;
    let mut code = String::with_capacity(5);
    for _ in 0..5 {
        code.push(STEAM_ALPHABET[(value % 26) as usize] as char);
        value /= 26;
    }
    let remaining = PERIOD - (unix_time % PERIOD);
    (code, remaining, remaining as f64 / PERIOD as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steam_totp_shape_and_alphabet() {
        for t in [0u64, 59, 1_111_111_111, 1_234_567_890, 2_000_000_000] {
            let (code, remaining, progress) = totp_steam(b"12345678901234567890", t);
            assert_eq!(code.len(), 5);
            assert!(code.bytes().all(|b| STEAM_ALPHABET.contains(&b)));
            assert_eq!(remaining, 30 - (t % 30));
            assert!((progress - remaining as f64 / 30.0).abs() < 1e-9);
        }
    }

    #[test]
    fn steam_totp_snapshot() {
        // Snapshot of the same RFC 6238 secret used in the vectors above, so a
        // regression in truncation or alphabet mapping fails loudly.
        let (code, _, _) = totp_steam(b"12345678901234567890", 1_234_567_890);
        assert_eq!(code, "VHHQY");
    }

    #[test]
    fn rfc4226_hotp_vectors() {
        // RFC 4226 Appendix D — secret = ASCII "12345678901234567890"
        let secret = b"12345678901234567890";
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, code) in expected.iter().enumerate() {
            assert_eq!(hotp(secret, counter as u64, 6, Algorithm::SHA1), *code);
        }
    }

    fn rfc6238_check(algo: Algorithm, secret: &[u8], expected: &[(u64, &str)]) {
        for (time, code) in expected {
            let (got, _, _) = totp(secret, 30, 8, algo, *time);
            assert_eq!(got, *code, "wrong TOTP at t={} for {:?}", time, algo);
        }
    }

    #[test]
    fn rfc6238_sha1_vectors() {
        rfc6238_check(
            Algorithm::SHA1,
            b"12345678901234567890",
            &[
                (59, "94287082"),
                (1111111109, "07081804"),
                (1111111111, "14050471"),
                (1234567890, "89005924"),
                (2000000000, "69279037"),
                (20000000000, "65353130"),
            ],
        );
    }

    #[test]
    fn rfc6238_sha256_vectors() {
        rfc6238_check(
            Algorithm::SHA256,
            b"12345678901234567890123456789012",
            &[
                (59, "46119246"),
                (1111111109, "68084774"),
                (1111111111, "67062674"),
                (1234567890, "91819424"),
                (2000000000, "90698825"),
                (20000000000, "77737706"),
            ],
        );
    }

    #[test]
    fn rfc6238_sha512_vectors() {
        rfc6238_check(
            Algorithm::SHA512,
            b"1234567890123456789012345678901234567890123456789012345678901234",
            &[
                (59, "90693936"),
                (1111111109, "25091201"),
                (1111111111, "99943326"),
                (1234567890, "93441116"),
                (2000000000, "38618901"),
                (20000000000, "47863826"),
            ],
        );
    }

    #[test]
    fn totp_remaining_and_progress() {
        let (code, remaining, progress) = totp(b"12345678901234567890", 30, 6, Algorithm::SHA1, 45);
        assert_eq!(code, hotp(b"12345678901234567890", 1, 6, Algorithm::SHA1));
        assert_eq!(remaining, 15);
        assert!((progress - 0.5).abs() < 1e-9);
    }
}
