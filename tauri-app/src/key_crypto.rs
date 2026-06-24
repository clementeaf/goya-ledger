//! Password-based encryption for private keys.
//!
//! Derives a 256-bit key via Argon2id, then encrypts/decrypts with AES-256-GCM.
//! Storage format: `hex(salt):hex(nonce):hex(ciphertext+tag)`.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
// OWASP minimum for Argon2id: m=19456 KiB, t=2, p=1.
const ARGON2_M_COST: u32 = 19_456;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

/// Errors from key encryption/decryption.
#[derive(Debug, thiserror::Error)]
pub enum KeyCryptoError {
    #[error("key derivation failed: {0}")]
    Derivation(String),
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("decryption failed — wrong password or corrupted data")]
    Decryption,
    #[error("invalid format: expected salt:nonce:ciphertext")]
    Format,
}

/// Encrypt raw private key bytes with a user-supplied password.
///
/// Returns `hex(salt):hex(nonce):hex(ciphertext)`.
pub fn encrypt_key(private_key: &[u8], password: &str) -> Result<String, KeyCryptoError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let derived = derive_key(password.as_bytes(), &salt)?;

    let cipher = Aes256Gcm::new_from_slice(&derived)
        .map_err(|e| KeyCryptoError::Encryption(e.to_string()))?;

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), private_key)
        .map_err(|e| KeyCryptoError::Encryption(e.to_string()))?;

    Ok([
        hex::encode(salt),
        hex::encode(nonce_bytes),
        hex::encode(ciphertext),
    ]
    .join(":"))
}

/// Decrypt a previously encrypted private key with the user's password.
pub fn decrypt_key(encrypted: &str, password: &str) -> Result<Vec<u8>, KeyCryptoError> {
    let parts: Vec<&str> = encrypted.splitn(3, ':').collect();
    let [salt_hex, nonce_hex, ct_hex]: [&str; 3] =
        parts.try_into().map_err(|_| KeyCryptoError::Format)?;

    let salt = hex::decode(salt_hex).map_err(|_| KeyCryptoError::Format)?;
    let nonce_bytes = hex::decode(nonce_hex).map_err(|_| KeyCryptoError::Format)?;
    let ciphertext = hex::decode(ct_hex).map_err(|_| KeyCryptoError::Format)?;

    let derived = derive_key(password.as_bytes(), &salt)?;

    let cipher = Aes256Gcm::new_from_slice(&derived)
        .map_err(|e| KeyCryptoError::Encryption(e.to_string()))?;

    cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        .map_err(|_| KeyCryptoError::Decryption)
}

fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN], KeyCryptoError> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_LEN))
        .map_err(|e| KeyCryptoError::Derivation(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| KeyCryptoError::Derivation(e.to_string()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PASSWORD: &str = "correct-horse-battery-staple";
    const TEST_KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";

    #[test]
    fn round_trip_encrypt_decrypt() {
        let encrypted = encrypt_key(TEST_KEY, TEST_PASSWORD).unwrap();
        let decrypted = decrypt_key(&encrypted, TEST_PASSWORD).unwrap();
        assert_eq!(decrypted, TEST_KEY);
    }

    #[test]
    fn wrong_password_fails() {
        let encrypted = encrypt_key(TEST_KEY, TEST_PASSWORD).unwrap();
        let result = decrypt_key(&encrypted, "wrong-password");
        assert!(matches!(result, Err(KeyCryptoError::Decryption)));
    }

    #[test]
    fn different_encryptions_produce_different_output() {
        let a = encrypt_key(TEST_KEY, TEST_PASSWORD).unwrap();
        let b = encrypt_key(TEST_KEY, TEST_PASSWORD).unwrap();
        assert_ne!(a, b, "random salt+nonce should make each encryption unique");
    }

    #[test]
    fn format_is_three_hex_parts() {
        let encrypted = encrypt_key(TEST_KEY, TEST_PASSWORD).unwrap();
        let parts: Vec<&str> = encrypted.splitn(3, ':').collect();
        assert_eq!(parts.len(), 3);
        parts.iter().for_each(|p| {
            assert!(hex::decode(p).is_ok(), "each part must be valid hex: {p}");
        });
    }

    #[test]
    fn salt_length_correct() {
        let encrypted = encrypt_key(TEST_KEY, TEST_PASSWORD).unwrap();
        let salt_hex = encrypted.split(':').next().unwrap();
        assert_eq!(
            hex::decode(salt_hex).unwrap().len(),
            SALT_LEN,
            "salt must be {SALT_LEN} bytes"
        );
    }

    #[test]
    fn nonce_length_correct() {
        let encrypted = encrypt_key(TEST_KEY, TEST_PASSWORD).unwrap();
        let nonce_hex = encrypted.split(':').nth(1).unwrap();
        assert_eq!(
            hex::decode(nonce_hex).unwrap().len(),
            NONCE_LEN,
            "nonce must be {NONCE_LEN} bytes"
        );
    }

    #[test]
    fn malformed_input_returns_format_error() {
        let cases = ["", "aabb", "aa:bb", "not:valid:hex!"];
        cases.iter().for_each(|input| {
            assert!(
                matches!(
                    decrypt_key(input, TEST_PASSWORD),
                    Err(KeyCryptoError::Format)
                ),
                "expected Format error for input: {input}"
            );
        });
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let encrypted = encrypt_key(b"", TEST_PASSWORD).unwrap();
        let decrypted = decrypt_key(&encrypted, TEST_PASSWORD).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn variable_length_keys_round_trip() {
        [16, 32, 48, 64, 128].iter().for_each(|&len| {
            let key: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let encrypted = encrypt_key(&key, TEST_PASSWORD).unwrap();
            let decrypted = decrypt_key(&encrypted, TEST_PASSWORD).unwrap();
            assert_eq!(decrypted, key, "failed for key length {len}");
        });
    }
}
