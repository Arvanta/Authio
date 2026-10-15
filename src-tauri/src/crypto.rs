//! Cryptographic primitives: AES-256-GCM, Argon2id, scrypt, secure random.
//!
//! - Argon2id (m = 64 MiB, t = 3, p = 4) derives the vault key from the master
//!   password over a fresh 128-bit salt.
//! - Every encryption uses a fresh random 96-bit nonce; the AEAD tag authenticates
//!   the ciphertext, so tampered vault/backup files fail to open (no oracle).

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

// Vault Argon2id parameters (m is in KiB → 64 MiB).
pub const ARGON2_M_KIB: u32 = 65_536;
pub const ARGON2_T: u32 = 3;
pub const ARGON2_P: u32 = 4;

pub fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("operating-system random source unavailable");
    buf
}

pub fn argon2id_derive(password: &[u8], salt: &[u8], m_kib: u32, t: u32, p: u32) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    let params = argon2::Params::new(m_kib, t, p, Some(KEY_LEN)).map_err(|e| format!("argon2 params: {e}"))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, &mut *key)
        .map_err(|e| format!("key derivation failed: {e}"))?;
    Ok(key)
}

/// scrypt — only used by the Aegis encrypted-vault importer.
pub fn scrypt_derive(password: &[u8], salt: &[u8], log_n: u8, r: u32, p: u32) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    let params = scrypt::Params::new(log_n, r, p).map_err(|e| format!("scrypt params: {e}"))?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    scrypt::scrypt(password, salt, &params, &mut *key).map_err(|e| format!("scrypt failed: {e}"))?;
    Ok(key)
}

/// AES-256-GCM encrypt → (nonce, ciphertext || 16-byte tag).
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("cipher init: {e}"))?;
    let nonce = rand_bytes::<NONCE_LEN>();
    let nonce_ga = Nonce::from(nonce);
    let ct = cipher
        .encrypt(&nonce_ga, plaintext)
        .map_err(|_| "encryption failed".to_string())?;
    Ok((nonce.to_vec(), ct))
}

/// AES-256-GCM decrypt of (ciphertext || tag). Fails closed on any tampering.
pub fn decrypt(key: &[u8; KEY_LEN], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if nonce.len() != NONCE_LEN {
        return Err("invalid nonce length".into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("cipher init: {e}"))?;
    let nonce_ga = Nonce::try_from(nonce).map_err(|_| "invalid nonce length")?;
    cipher
        .decrypt(&nonce_ga, ciphertext)
        .map_err(|_| "decryption failed: wrong password or corrupted/tampered data".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_roundtrip() {
        let key = rand_bytes::<32>();
        let msg = b"authio secret payload";
        let (nonce, ct) = encrypt(&key, msg).unwrap();
        assert_eq!(decrypt(&key, &nonce, &ct).unwrap(), msg);
    }

    #[test]
    fn aes_gcm_detects_tampering() {
        let key = rand_bytes::<32>();
        let (nonce, mut ct) = encrypt(&key, b"data").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 1;
        assert!(decrypt(&key, &nonce, &ct).is_err());
    }

    #[test]
    fn argon2id_stable_and_salted() {
        let salt_a = rand_bytes::<16>();
        let salt_b = rand_bytes::<16>();
        let k1 = argon2id_derive(b"pw", &salt_a, 19_456, 2, 1).unwrap(); // smaller params for test speed
        let k2 = argon2id_derive(b"pw", &salt_a, 19_456, 2, 1).unwrap();
        let k3 = argon2id_derive(b"pw", &salt_b, 19_456, 2, 1).unwrap();
        assert_eq!(*k1, *k2);
        assert_ne!(*k1, *k3);
    }

    #[test]
    fn scrypt_matches_rfc7914_vector() {
        // RFC 7914 §12: scrypt("", "", N=16, r=1, p=1, dkLen=64) first 16 bytes.
        let params = scrypt::Params::new(4, 1, 1).unwrap();
        let mut out = [0u8; 64];
        scrypt::scrypt(b"", b"", &params, &mut out).unwrap();
        assert_eq!(
            &out[..16],
            &[0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20, 0x3b, 0x19, 0xca, 0x42, 0xc1, 0x8a, 0x04, 0x97]
        );
    }
}
