//! SLH-DSA-SHAKE-128s signing and verification (FIPS 205).
//!
//! Hash-based backup signature scheme. Independent security assumption
//! from ML-DSA (lattice) — survives even if lattice problems fall.

use pqcrypto_sphincsplus::sphincsshake128ssimple;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

use crate::approved_mode::require_approved;
use crate::errors::CryptoError;

pub const SIG_BYTES: usize = 7856;
pub const PK_BYTES: usize = 32;
pub const SK_BYTES: usize = 64;

#[derive(Debug, Clone)]
pub struct SlhDsaPublicKey(pub Vec<u8>);

impl SlhDsaPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != PK_BYTES {
            return Err(CryptoError::InvalidKey(format!(
                "SLH-DSA pk must be {PK_BYTES} bytes, got {}",
                bytes.len()
            )));
        }
        Ok(Self(bytes.to_vec()))
    }
}

#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SlhDsaPrivateKey(pub Vec<u8>);

impl SlhDsaPrivateKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SlhDsaPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SlhDsaPrivateKey([REDACTED; {} bytes])", self.0.len())
    }
}

#[derive(Debug, Clone)]
pub struct SlhDsaSignature(pub Vec<u8>);

impl SlhDsaSignature {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub struct SlhDsaKeyPair {
    pub public_key: SlhDsaPublicKey,
    pub private_key: SlhDsaPrivateKey,
}

pub fn generate_keypair() -> Result<SlhDsaKeyPair, CryptoError> {
    require_approved()?;
    Ok(generate_keypair_raw())
}

pub(crate) fn generate_keypair_raw() -> SlhDsaKeyPair {
    let (pk, sk) = sphincsshake128ssimple::keypair();
    SlhDsaKeyPair {
        public_key: SlhDsaPublicKey(pk.as_bytes().to_vec()),
        private_key: SlhDsaPrivateKey(sk.as_bytes().to_vec()),
    }
}

pub fn sign_message(
    private_key: &SlhDsaPrivateKey,
    message: &[u8],
) -> Result<SlhDsaSignature, CryptoError> {
    require_approved()?;
    sign_message_raw(private_key, message)
}

pub fn sign_message_raw(
    private_key: &SlhDsaPrivateKey,
    message: &[u8],
) -> Result<SlhDsaSignature, CryptoError> {
    let sk = sphincsshake128ssimple::SecretKey::from_bytes(&private_key.0)
        .map_err(|e| CryptoError::InvalidKey(format!("SLH-DSA secret key: {e}")))?;
    let sig = sphincsshake128ssimple::detached_sign(message, &sk);
    Ok(SlhDsaSignature(sig.as_bytes().to_vec()))
}

pub fn verify_signature(
    public_key: &SlhDsaPublicKey,
    message: &[u8],
    signature: &SlhDsaSignature,
) -> Result<(), CryptoError> {
    require_approved()?;
    verify_signature_raw(public_key, message, signature)
}

pub fn verify_signature_raw(
    public_key: &SlhDsaPublicKey,
    message: &[u8],
    signature: &SlhDsaSignature,
) -> Result<(), CryptoError> {
    let pk = sphincsshake128ssimple::PublicKey::from_bytes(&public_key.0)
        .map_err(|_| CryptoError::InvalidKey("invalid SLH-DSA public key".into()))?;
    let sig = sphincsshake128ssimple::DetachedSignature::from_bytes(&signature.0)
        .map_err(|_| CryptoError::InvalidSignature)?;
    sphincsshake128ssimple::verify_detached_signature(&sig, message, &pk)
        .map_err(|_| CryptoError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_produces_valid_sizes() {
        let kp = generate_keypair_raw();
        assert_eq!(kp.public_key.as_bytes().len(), PK_BYTES);
        assert_eq!(kp.private_key.as_bytes().len(), SK_BYTES);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let kp = generate_keypair_raw();
        let sig = sign_message_raw(&kp.private_key, b"SLH-DSA test").unwrap();
        assert_eq!(sig.as_bytes().len(), SIG_BYTES);
        verify_signature_raw(&kp.public_key, b"SLH-DSA test", &sig).unwrap();
    }

    #[test]
    fn wrong_message_fails() {
        let kp = generate_keypair_raw();
        let sig = sign_message_raw(&kp.private_key, b"correct").unwrap();
        assert!(verify_signature_raw(&kp.public_key, b"wrong", &sig).is_err());
    }

    #[test]
    fn cross_keypair_rejected() {
        let kp_a = generate_keypair_raw();
        let kp_b = generate_keypair_raw();
        let sig = sign_message_raw(&kp_a.private_key, b"cross-key").unwrap();
        assert!(verify_signature_raw(&kp_b.public_key, b"cross-key", &sig).is_err());
    }

    #[test]
    fn private_key_debug_redacted() {
        let kp = generate_keypair_raw();
        let dbg = format!("{:?}", kp.private_key);
        assert!(dbg.contains("REDACTED"));
    }
}
