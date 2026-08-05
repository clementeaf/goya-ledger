//! HSM-backed signing provider using PKCS#11 (feature-gated under `hsm`).
//!
//! When the `hsm` feature is enabled, `HsmSigningProvider` delegates signing
//! to a hardware security module via the PKCS#11 interface (using `cryptoki`).
//!
//! Configuration via environment variables:
//! - `HSM_PKCS11_LIB` — path to the PKCS#11 shared library
//! - `HSM_SLOT_ID` — PKCS#11 slot identifier
//! - `HSM_PIN` — user PIN for the slot
//! - `HSM_KEY_LABEL` — label of the Ed25519 signing key object

use thiserror::Error;

#[derive(Debug, Error)]
pub enum HsmError {
    #[allow(dead_code)]
    #[error("PKCS#11 library not found: {0}")]
    LibraryNotFound(String),
    #[allow(dead_code)]
    #[error("slot not found: {0}")]
    SlotNotFound(u64),
    #[error("authentication failed")]
    AuthFailed,
    #[allow(dead_code)]
    #[error("key not found: {0}")]
    KeyNotFound(String),
    #[allow(dead_code)]
    #[error("signing operation failed: {0}")]
    SignFailed(String),
    #[error("HSM feature not enabled")]
    NotEnabled,
}

/// Configuration for connecting to an HSM via PKCS#11.
#[derive(Debug, Clone)]
pub struct HsmConfig {
    #[allow(dead_code)]
    pub pkcs11_lib: String,
    #[allow(dead_code)]
    pub slot_id: u64,
    #[allow(dead_code)]
    pub pin: String,
    #[allow(dead_code)]
    pub key_label: String,
}

impl HsmConfig {
    #[allow(dead_code)]
    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self, HsmError> {
        Ok(Self {
            pkcs11_lib: std::env::var("HSM_PKCS11_LIB")
                .map_err(|_| HsmError::LibraryNotFound("HSM_PKCS11_LIB not set".into()))?,
            slot_id: std::env::var("HSM_SLOT_ID")
                .unwrap_or_else(|_| "0".into())
                .parse()
                .unwrap_or(0),
            pin: std::env::var("HSM_PIN").map_err(|_| HsmError::AuthFailed)?,
            key_label: std::env::var("HSM_KEY_LABEL").unwrap_or_else(|_| "ed25519-key".into()),
        })
    }
}

/// HSM-backed signing provider.
///
/// When the `hsm` feature is not enabled, construction always returns
/// `Err(HsmError::NotEnabled)`. When enabled, it delegates to PKCS#11.
pub struct HsmSigningProvider {
    /// Cached public key bytes (read from HSM during construction).
    public_key: [u8; 32],
    /// Placeholder for the PKCS#11 context — real impl under `#[cfg(feature = "hsm")]`.
    _config: HsmConfig,
}

impl HsmSigningProvider {
    #[allow(dead_code)]
    /// Connect to an HSM and locate the signing key.
    ///
    /// This is a no-op stub when compiled without the `hsm` feature.
    #[cfg(not(feature = "hsm"))]
    pub fn new(
        _pkcs11_lib: &str,
        _slot_id: u64,
        _pin: &str,
        _key_label: &str,
    ) -> Result<Self, HsmError> {
        Err(HsmError::NotEnabled)
    }

    #[cfg(feature = "hsm")]
    pub fn new(
        pkcs11_lib: &str,
        slot_id: u64,
        pin: &str,
        key_label: &str,
    ) -> Result<Self, HsmError> {
        use cryptoki::context::{CInitializeArgs, Pkcs11};

        let ctx = Pkcs11::new(pkcs11_lib).map_err(|e| HsmError::LibraryNotFound(e.to_string()))?;
        ctx.initialize(CInitializeArgs::OsThreads)
            .map_err(|e| HsmError::LibraryNotFound(e.to_string()))?;

        let slots = ctx
            .get_slots_with_token()
            .map_err(|e| HsmError::SlotNotFound(slot_id))?;
        let slot = slots
            .into_iter()
            .find(|s| s.id() == slot_id)
            .ok_or(HsmError::SlotNotFound(slot_id))?;

        // Open session and login.
        let session = ctx
            .open_rw_session(slot)
            .map_err(|e| HsmError::AuthFailed)?;
        session
            .login(cryptoki::session::UserType::User, Some(pin))
            .map_err(|_| HsmError::AuthFailed)?;

        // For now, return a placeholder public key — full PKCS#11 key lookup
        // would require CKA_LABEL search and CKM_EDDSA mechanism support.
        Ok(Self {
            public_key: [0u8; 32],
            _config: HsmConfig {
                pkcs11_lib: pkcs11_lib.to_string(),
                slot_id,
                pin: pin.to_string(),
                key_label: key_label.to_string(),
            },
        })
    }
}

impl super::signing::SigningProvider for HsmSigningProvider {
    fn algorithm(&self) -> super::signing::SigningAlgorithm {
        super::signing::SigningAlgorithm::Ed25519
    }

    #[cfg(not(feature = "hsm"))]
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, super::signing::SigningError> {
        Err(super::signing::SigningError::SignFailed(
            "HSM signing not available in this build".into(),
        ))
    }

    #[cfg(feature = "hsm")]
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, super::signing::SigningError> {
        // In a full implementation, this would:
        // 1. Open a PKCS#11 session to the HSM
        // 2. Find the key by label (CKA_LABEL)
        // 3. Call C_Sign with CKM_EDDSA mechanism
        // 4. Return the 64-byte Ed25519 signature
        //
        // For now, delegate to the software fallback using the cached public key
        // as a placeholder. Real HSM integration requires hardware testing.
        let _ = data;
        Err(super::signing::SigningError::SignFailed(
            "HSM sign: key lookup not yet implemented — requires hardware testing".into(),
        ))
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key.to_vec()
    }

    #[cfg(not(feature = "hsm"))]
    fn verify(&self, _data: &[u8], _sig: &[u8]) -> Result<bool, super::signing::SigningError> {
        Err(super::signing::SigningError::VerifyFailed(
            "HSM verification not available in this build".into(),
        ))
    }

    #[cfg(feature = "hsm")]
    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, super::signing::SigningError> {
        use pqc_crypto_module::legacy::ed25519::{Signature, VerifyingKey};
        let sig_bytes: [u8; 64] = sig.try_into().map_err(|_| {
            super::signing::SigningError::VerifyFailed("Ed25519 signature must be 64 bytes".into())
        })?;
        let vk = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|e| super::signing::SigningError::VerifyFailed(e.to_string()))?;
        let signature = Signature::from_bytes(&sig_bytes);
        Ok(vk.verify_strict(data, &signature).is_ok())
    }
}

// ── Simulated HSM Provider ────────────────────────────────────────────────

/// Software-backed HSM simulator for testing and development.
///
/// Implements `SigningProvider` with the same lifecycle as a real HSM
/// (config, session open, key lookup by label) but uses in-memory Ed25519.
/// Allows full integration testing without hardware.
pub struct SimulatedHsmProvider {
    config: HsmConfig,
    signing_key: ed25519_dalek::SigningKey,
    session_open: bool,
}

impl SimulatedHsmProvider {
    /// Create a simulated HSM with a generated key.
    pub fn new(config: HsmConfig) -> Result<Self, HsmError> {
        if config.pin.is_empty() {
            return Err(HsmError::AuthFailed);
        }
        if config.key_label.is_empty() {
            return Err(HsmError::KeyNotFound("empty label".into()));
        }
        use pqc_crypto_module::legacy::rng::OsRng;
        Ok(Self {
            config,
            signing_key: ed25519_dalek::SigningKey::generate(&mut OsRng),
            session_open: true,
        })
    }

    /// Create from environment variables.
    pub fn from_env() -> Result<Self, HsmError> {
        let config = HsmConfig::from_env()?;
        Self::new(config)
    }

    /// Close the simulated session.
    pub fn close_session(&mut self) {
        self.session_open = false;
    }

    /// Re-open the simulated session (requires PIN).
    pub fn reopen_session(&mut self, pin: &str) -> Result<(), HsmError> {
        if pin != self.config.pin {
            return Err(HsmError::AuthFailed);
        }
        self.session_open = true;
        Ok(())
    }

    /// Check if the session is open.
    pub fn is_session_open(&self) -> bool {
        self.session_open
    }

    /// Get the key label.
    pub fn key_label(&self) -> &str {
        &self.config.key_label
    }

    fn require_session(&self) -> Result<(), super::signing::SigningError> {
        if !self.session_open {
            return Err(super::signing::SigningError::SignFailed(
                "HSM session is closed".into(),
            ));
        }
        Ok(())
    }
}

impl super::signing::SigningProvider for SimulatedHsmProvider {
    fn algorithm(&self) -> super::signing::SigningAlgorithm {
        super::signing::SigningAlgorithm::Ed25519
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, super::signing::SigningError> {
        self.require_session()?;
        use pqc_crypto_module::legacy::ed25519::Signer;
        let sig = self.signing_key.sign(data);
        Ok(sig.to_bytes().to_vec())
    }

    fn public_key(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }

    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, super::signing::SigningError> {
        use pqc_crypto_module::legacy::ed25519::{Signature, Verifier};
        let sig_bytes: [u8; 64] = sig.try_into().map_err(|_| {
            super::signing::SigningError::VerifyFailed("Ed25519 signature must be 64 bytes".into())
        })?;
        let signature = Signature::from_bytes(&sig_bytes);
        Ok(self
            .signing_key
            .verifying_key()
            .verify(data, &signature)
            .is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::SigningProvider;

    fn test_config() -> HsmConfig {
        HsmConfig {
            pkcs11_lib: "/usr/lib/softhsm/libsofthsm2.so".into(),
            slot_id: 0,
            pin: "1234".into(),
            key_label: "ed25519-key".into(),
        }
    }

    #[test]
    fn hsm_config_fields() {
        let cfg = test_config();
        assert_eq!(cfg.slot_id, 0);
        assert_eq!(cfg.key_label, "ed25519-key");
    }

    #[test]
    fn hsm_provider_not_enabled_without_feature() {
        #[cfg(not(feature = "hsm"))]
        {
            let result = HsmSigningProvider::new("/lib.so", 0, "pin", "label");
            assert!(matches!(result, Err(HsmError::NotEnabled)));
        }
    }

    // ── SimulatedHsmProvider ──────────────────────────────────────────

    #[test]
    fn sim_creates_with_valid_config() {
        let provider = SimulatedHsmProvider::new(test_config()).unwrap();
        assert!(provider.is_session_open());
        assert_eq!(provider.key_label(), "ed25519-key");
    }

    #[test]
    fn sim_rejects_empty_pin() {
        let mut cfg = test_config();
        cfg.pin = String::new();
        let result = SimulatedHsmProvider::new(cfg);
        assert!(matches!(result, Err(HsmError::AuthFailed)));
    }

    #[test]
    fn sim_rejects_empty_key_label() {
        let mut cfg = test_config();
        cfg.key_label = String::new();
        let result = SimulatedHsmProvider::new(cfg);
        assert!(matches!(result, Err(HsmError::KeyNotFound(_))));
    }

    #[test]
    fn sim_sign_and_verify() {
        let provider = SimulatedHsmProvider::new(test_config()).unwrap();
        let data = b"test message";
        let sig = provider.sign(data).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(provider.verify(data, &sig).unwrap());
    }

    #[test]
    fn sim_sign_different_data_different_sig() {
        let provider = SimulatedHsmProvider::new(test_config()).unwrap();
        let sig1 = provider.sign(b"msg1").unwrap();
        let sig2 = provider.sign(b"msg2").unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn sim_verify_rejects_wrong_data() {
        let provider = SimulatedHsmProvider::new(test_config()).unwrap();
        let sig = provider.sign(b"original").unwrap();
        assert!(!provider.verify(b"tampered", &sig).unwrap());
    }

    #[test]
    fn sim_verify_rejects_wrong_sig() {
        let provider = SimulatedHsmProvider::new(test_config()).unwrap();
        let bad_sig = vec![0u8; 64];
        assert!(!provider.verify(b"data", &bad_sig).unwrap());
    }

    #[test]
    fn sim_verify_rejects_short_sig() {
        let provider = SimulatedHsmProvider::new(test_config()).unwrap();
        let result = provider.verify(b"data", &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn sim_public_key_is_32_bytes() {
        let provider = SimulatedHsmProvider::new(test_config()).unwrap();
        assert_eq!(provider.public_key().len(), 32);
    }

    #[test]
    fn sim_algorithm_is_ed25519() {
        let provider = SimulatedHsmProvider::new(test_config()).unwrap();
        assert_eq!(
            provider.algorithm(),
            crate::identity::signing::SigningAlgorithm::Ed25519
        );
    }

    #[test]
    fn sim_close_session_prevents_signing() {
        let mut provider = SimulatedHsmProvider::new(test_config()).unwrap();
        provider.close_session();
        assert!(!provider.is_session_open());
        let result = provider.sign(b"data");
        assert!(result.is_err());
    }

    #[test]
    fn sim_reopen_session_with_correct_pin() {
        let mut provider = SimulatedHsmProvider::new(test_config()).unwrap();
        provider.close_session();
        provider.reopen_session("1234").unwrap();
        assert!(provider.is_session_open());
        assert!(provider.sign(b"data").is_ok());
    }

    #[test]
    fn sim_reopen_session_with_wrong_pin_fails() {
        let mut provider = SimulatedHsmProvider::new(test_config()).unwrap();
        provider.close_session();
        let result = provider.reopen_session("wrong");
        assert!(matches!(result, Err(HsmError::AuthFailed)));
        assert!(!provider.is_session_open());
    }

    #[test]
    fn sim_verify_works_with_closed_session() {
        let mut provider = SimulatedHsmProvider::new(test_config()).unwrap();
        let sig = provider.sign(b"data").unwrap();
        provider.close_session();
        assert!(provider.verify(b"data", &sig).unwrap());
    }

    #[test]
    fn sim_implements_signing_provider_trait() {
        let provider = SimulatedHsmProvider::new(test_config()).unwrap();
        let boxed: Box<dyn SigningProvider> = Box::new(provider);
        let sig = boxed.sign(b"trait test").unwrap();
        assert!(boxed.verify(b"trait test", &sig).unwrap());
    }

    #[test]
    fn sim_cross_verify_with_software_provider() {
        let hsm = SimulatedHsmProvider::new(test_config()).unwrap();
        let data = b"cross-verify test";
        let sig = hsm.sign(data).unwrap();
        let pk_hex = hex::encode(hsm.public_key());
        let sig_hex = hex::encode(&sig);
        assert!(crate::signature::verify_signature(
            crate::identity::signing::SigningAlgorithm::Ed25519,
            &pk_hex,
            data,
            &sig_hex,
        ));
    }

    #[test]
    fn sim_usable_as_tsa_signer() {
        use std::sync::Arc;
        let hsm = SimulatedHsmProvider::new(test_config()).unwrap();
        let signer: Arc<dyn SigningProvider> = Arc::new(hsm);
        let tsa = crate::tsa::TsaProvider::new(signer, "did:goya:hsm-tsa".into());
        let req = crate::tsa::TimeStampRequest {
            hash_algorithm: crate::crypto::hasher::HashAlgorithm::Sha256,
            message_imprint: hex::encode(crate::crypto::hasher::hash_with(
                crate::crypto::hasher::HashAlgorithm::Sha256,
                b"hsm test",
            )),
            nonce: Some(1),
            require_ordering: false,
        };
        let resp = tsa.issue(&req);
        assert_eq!(resp.status, 0);
        assert!(crate::tsa::verify_token(&resp.token.unwrap()));
    }
}
