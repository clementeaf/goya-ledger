#[allow(deprecated)]
mod inner {
    pub use aes_gcm::aead::{Aead, KeyInit};
    pub use aes_gcm::{Aes256Gcm, Nonce};
}
use inner::*;

use crate::errors::CryptoError;
use crate::mlkem;
use crate::types::{MlKemCiphertext, MlKemPrivateKey, MlKemPublicKey};

pub struct EncryptedBlob {
    pub kem_ciphertext: Vec<u8>,
    pub aes_nonce: [u8; 12],
    pub aes_ciphertext: Vec<u8>,
}

impl EncryptedBlob {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let ct_len = self.kem_ciphertext.len() as u32;
        out.extend_from_slice(&ct_len.to_be_bytes());
        out.extend_from_slice(&self.kem_ciphertext);
        out.extend_from_slice(&self.aes_nonce);
        out.extend_from_slice(&self.aes_ciphertext);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < 4 {
            return Err(CryptoError::InvalidKey("encrypted blob too short".into()));
        }
        let ct_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let offset = 4;
        if data.len() < offset + ct_len + 12 {
            return Err(CryptoError::InvalidKey("encrypted blob truncated".into()));
        }
        let kem_ciphertext = data[offset..offset + ct_len].to_vec();
        let nonce_start = offset + ct_len;
        let mut aes_nonce = [0u8; 12];
        aes_nonce.copy_from_slice(&data[nonce_start..nonce_start + 12]);
        let aes_ciphertext = data[nonce_start + 12..].to_vec();
        Ok(Self {
            kem_ciphertext,
            aes_nonce,
            aes_ciphertext,
        })
    }
}

pub fn encrypt_at_rest(
    plaintext: &[u8],
    recipient_pk: &MlKemPublicKey,
) -> Result<EncryptedBlob, CryptoError> {
    let (kem_ct, shared_secret) = mlkem::encapsulate_raw(recipient_pk)?;

    let ss_bytes = shared_secret.as_bytes();
    let key = derive_aes_key(ss_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| CryptoError::InvalidKey(format!("AES key init: {e}")))?;

    let mut nonce_bytes = [0u8; 12];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aes_ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::InvalidKey(format!("AES-GCM encrypt: {e}")))?;

    Ok(EncryptedBlob {
        kem_ciphertext: kem_ct.as_bytes().to_vec(),
        aes_nonce: nonce_bytes,
        aes_ciphertext,
    })
}

pub fn decrypt_at_rest(
    blob: &EncryptedBlob,
    recipient_sk: &MlKemPrivateKey,
) -> Result<Vec<u8>, CryptoError> {
    let kem_ct = MlKemCiphertext(blob.kem_ciphertext.clone());
    let shared_secret = mlkem::decapsulate_raw(recipient_sk, &kem_ct)?;

    let ss_bytes = shared_secret.as_bytes();
    let key = derive_aes_key(ss_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| CryptoError::InvalidKey(format!("AES key init: {e}")))?;

    let nonce = Nonce::from_slice(&blob.aes_nonce);

    cipher
        .decrypt(nonce, blob.aes_ciphertext.as_ref())
        .map_err(|e| CryptoError::InvalidKey(format!("AES-GCM decrypt: {e}")))
}

fn derive_aes_key(shared_secret: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"goya-encrypt-at-rest-v1");
    hasher.update(shared_secret);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_keypair() -> crate::mlkem::MlKemKeyPair {
        mlkem::generate_keypair_raw().unwrap()
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let kp = generate_keypair();
        let plaintext = b"sensitive CA private key material";
        let blob = encrypt_at_rest(plaintext, &kp.public_key).unwrap();
        let decrypted = decrypt_at_rest(&blob, &kp.private_key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_produces_different_ciphertext_each_time() {
        let kp = generate_keypair();
        let plaintext = b"same data twice";
        let blob1 = encrypt_at_rest(plaintext, &kp.public_key).unwrap();
        let blob2 = encrypt_at_rest(plaintext, &kp.public_key).unwrap();
        assert_ne!(blob1.aes_ciphertext, blob2.aes_ciphertext);
        assert_ne!(blob1.kem_ciphertext, blob2.kem_ciphertext);
    }

    #[test]
    fn decrypt_fails_with_wrong_key() {
        let kp1 = generate_keypair();
        let kp2 = generate_keypair();
        let plaintext = b"secret";
        let blob = encrypt_at_rest(plaintext, &kp1.public_key).unwrap();
        let result = decrypt_at_rest(&blob, &kp2.private_key);
        assert!(result.is_err() || result.unwrap() != plaintext);
    }

    #[test]
    fn decrypt_fails_with_tampered_ciphertext() {
        let kp = generate_keypair();
        let plaintext = b"integrity check";
        let mut blob = encrypt_at_rest(plaintext, &kp.public_key).unwrap();
        if let Some(byte) = blob.aes_ciphertext.last_mut() {
            *byte ^= 0xFF;
        }
        assert!(decrypt_at_rest(&blob, &kp.private_key).is_err());
    }

    #[test]
    fn blob_serialization_roundtrip() {
        let kp = generate_keypair();
        let plaintext = b"serialize me";
        let blob = encrypt_at_rest(plaintext, &kp.public_key).unwrap();
        let bytes = blob.to_bytes();
        let blob2 = EncryptedBlob::from_bytes(&bytes).unwrap();
        let decrypted = decrypt_at_rest(&blob2, &kp.private_key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_empty_data() {
        let kp = generate_keypair();
        let blob = encrypt_at_rest(b"", &kp.public_key).unwrap();
        let decrypted = decrypt_at_rest(&blob, &kp.private_key).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn encrypt_large_data() {
        let kp = generate_keypair();
        let plaintext = vec![0xAB; 1_000_000];
        let blob = encrypt_at_rest(&plaintext, &kp.public_key).unwrap();
        let decrypted = decrypt_at_rest(&blob, &kp.private_key).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
