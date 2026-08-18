//! Validator registry — maps validator IDs to ML-DSA-65 public keys.
//!
//! Used by `RegistryVerifier` to perform real cryptographic signature
//! verification on BFT votes, replacing the testnet `AcceptAllVerifier`.

use std::collections::HashMap;
use std::sync::Arc;

use super::quorum::SignatureVerifier;

/// Maps `validator_id → ML-DSA-65 public key bytes`.
///
/// Validated at construction time: no duplicates, no malformed keys.
#[derive(Clone)]
pub struct ValidatorRegistry {
    keys: HashMap<String, Vec<u8>>,
}

/// Errors during registry construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    DuplicateId(String),
    DuplicateKey(String, String),
    InvalidHex {
        id: String,
        err: String,
    },
    InvalidKeySize {
        id: String,
        size: usize,
        expected: usize,
    },
    Empty,
    ParseError(String),
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateId(id) => write!(f, "duplicate validator ID: {id}"),
            Self::DuplicateKey(a, b) => {
                write!(f, "validators {a} and {b} share the same public key")
            }
            Self::InvalidHex { id, err } => write!(f, "invalid hex for {id}: {err}"),
            Self::InvalidKeySize { id, size, expected } => {
                write!(f, "key for {id} is {size} bytes, expected {expected}")
            }
            Self::Empty => write!(f, "validator registry is empty"),
            Self::ParseError(msg) => write!(f, "parse error: {msg}"),
        }
    }
}

/// Expected ML-DSA-65 public key size in bytes.
const MLDSA65_PK_SIZE: usize = 1952;

impl ValidatorRegistry {
    /// Parse from env-var format: `id1:<hex_pk>,id2:<hex_pk>,...`
    pub fn from_env_str(s: &str) -> Result<Self, RegistryError> {
        let mut keys = HashMap::new();
        let mut seen_keys: HashMap<Vec<u8>, String> = HashMap::new();

        for entry in s.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (id, hex_pk) = entry.split_once(':').ok_or_else(|| {
                RegistryError::ParseError(format!("expected 'id:hex_pk', got '{entry}'"))
            })?;
            let id = id.trim().to_string();
            let hex_pk = hex_pk.trim();

            if keys.contains_key(&id) {
                return Err(RegistryError::DuplicateId(id));
            }

            let pk_bytes = hex::decode(hex_pk).map_err(|e| RegistryError::InvalidHex {
                id: id.clone(),
                err: e.to_string(),
            })?;

            if pk_bytes.len() != MLDSA65_PK_SIZE {
                return Err(RegistryError::InvalidKeySize {
                    id: id.clone(),
                    size: pk_bytes.len(),
                    expected: MLDSA65_PK_SIZE,
                });
            }

            // Check for duplicate keys across different IDs.
            if let Some(other_id) = seen_keys.get(&pk_bytes) {
                return Err(RegistryError::DuplicateKey(other_id.clone(), id));
            }
            seen_keys.insert(pk_bytes.clone(), id.clone());

            keys.insert(id, pk_bytes);
        }

        if keys.is_empty() {
            return Err(RegistryError::Empty);
        }

        Ok(Self { keys })
    }

    /// Build from a pre-validated map (for tests).
    pub fn from_map(keys: HashMap<String, Vec<u8>>) -> Self {
        Self { keys }
    }

    /// Look up a validator's public key.
    pub fn get(&self, validator_id: &str) -> Option<&[u8]> {
        self.keys.get(validator_id).map(|v| v.as_slice())
    }

    /// All validator IDs.
    pub fn validator_ids(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }

    /// Number of registered validators.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Real ML-DSA-65 signature verifier backed by `ValidatorRegistry`.
///
/// Replaces `NodeVerifier` (testnet stub). Looks up the voter's public key
/// in the registry and verifies the signature using `pqc_crypto_module`.
#[derive(Clone)]
pub struct RegistryVerifier {
    registry: Arc<ValidatorRegistry>,
}

impl RegistryVerifier {
    pub fn new(registry: Arc<ValidatorRegistry>) -> Self {
        Self { registry }
    }
}

impl SignatureVerifier for RegistryVerifier {
    fn verify(&self, voter_id: &str, payload: &[u8], signature: &[u8]) -> bool {
        let pk_bytes = match self.registry.get(voter_id) {
            Some(pk) => pk,
            None => return false, // unknown voter → reject
        };

        let pk = match pqc_crypto_module::types::MldsaPublicKey::from_bytes(pk_bytes) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let sig = match pqc_crypto_module::types::MldsaSignature::from_bytes(signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        pqc_crypto_module::mldsa::verify_signature_raw(&pk, payload, &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::bft::types::{BftPhase, VoteMessage};
    use crate::identity::signing::{MlDsaSigningProvider, SigningProvider};

    fn gen_keypair() -> (String, Vec<u8>, MlDsaSigningProvider) {
        let provider = MlDsaSigningProvider::generate();
        let pk = provider.public_key();
        let id = format!("node-{}", hex::encode(&pk[..4]));
        (id, pk, provider)
    }

    fn make_registry(pairs: &[(String, Vec<u8>)]) -> ValidatorRegistry {
        let map: HashMap<String, Vec<u8>> = pairs.iter().cloned().collect();
        ValidatorRegistry::from_map(map)
    }

    // ── Registry construction ───────────────────────────────────────

    #[test]
    fn parse_env_str_valid() {
        let (id, pk, _) = gen_keypair();
        let (id2, pk2, _) = gen_keypair();
        let env = format!("{}:{},{}:{}", id, hex::encode(&pk), id2, hex::encode(&pk2));
        let reg = ValidatorRegistry::from_env_str(&env).unwrap();
        assert_eq!(reg.len(), 2);
        assert_eq!(reg.get(&id).unwrap(), pk.as_slice());
    }

    #[test]
    fn parse_env_str_duplicate_id_errors() {
        let (id, pk, _) = gen_keypair();
        let (_, pk2, _) = gen_keypair();
        let env = format!("{id}:{},{id}:{}", hex::encode(&pk), hex::encode(&pk2));
        assert!(matches!(
            ValidatorRegistry::from_env_str(&env),
            Err(RegistryError::DuplicateId(_))
        ));
    }

    #[test]
    fn parse_env_str_duplicate_key_errors() {
        let (_, pk, _) = gen_keypair();
        let hex_pk = hex::encode(&pk);
        let env = format!("node-a:{hex_pk},node-b:{hex_pk}");
        assert!(matches!(
            ValidatorRegistry::from_env_str(&env),
            Err(RegistryError::DuplicateKey(_, _))
        ));
    }

    #[test]
    fn parse_env_str_invalid_hex_errors() {
        let env = "node-a:ZZZZ";
        assert!(matches!(
            ValidatorRegistry::from_env_str(env),
            Err(RegistryError::InvalidHex { .. })
        ));
    }

    #[test]
    fn parse_env_str_wrong_key_size_errors() {
        let env = format!("node-a:{}", hex::encode(vec![0u8; 100]));
        assert!(matches!(
            ValidatorRegistry::from_env_str(&env),
            Err(RegistryError::InvalidKeySize { .. })
        ));
    }

    #[test]
    fn parse_env_str_empty_errors() {
        assert!(matches!(
            ValidatorRegistry::from_env_str(""),
            Err(RegistryError::Empty)
        ));
    }

    // ── Real ML-DSA-65 verification ─────────────────────────────────

    #[test]
    fn real_mldsa65_sign_and_verify() {
        let (id, pk, signer) = gen_keypair();
        let reg = Arc::new(make_registry(&[(id.clone(), pk)]));
        let verifier = RegistryVerifier::new(reg);

        let bh = [0xAAu8; 32];
        let payload = VoteMessage::signing_payload_v2(BftPhase::Prepare, &bh, 5, &id);
        let sig = signer.sign(&payload).unwrap();

        assert!(verifier.verify(&id, &payload, &sig));
    }

    #[test]
    fn wrong_voter_id_rejects() {
        let (id_a, pk_a, signer_a) = gen_keypair();
        let (id_b, pk_b, _) = gen_keypair();
        let reg = Arc::new(make_registry(&[(id_a.clone(), pk_a), (id_b.clone(), pk_b)]));
        let verifier = RegistryVerifier::new(reg);

        let bh = [0xAAu8; 32];
        let payload = VoteMessage::signing_payload_v2(BftPhase::Prepare, &bh, 5, &id_a);
        let sig = signer_a.sign(&payload).unwrap();

        // Signature by A verified with B's key → reject.
        assert!(!verifier.verify(&id_b, &payload, &sig));
    }

    #[test]
    fn modified_block_hash_rejects() {
        let (id, pk, signer) = gen_keypair();
        let reg = Arc::new(make_registry(&[(id.clone(), pk)]));
        let verifier = RegistryVerifier::new(reg);

        let bh = [0xAAu8; 32];
        let payload = VoteMessage::signing_payload_v2(BftPhase::Prepare, &bh, 5, &id);
        let sig = signer.sign(&payload).unwrap();

        // Tamper block_hash in payload.
        let mut tampered_bh = [0xAAu8; 32];
        tampered_bh[0] = 0xBB;
        let bad_payload = VoteMessage::signing_payload_v2(BftPhase::Prepare, &tampered_bh, 5, &id);
        assert!(!verifier.verify(&id, &bad_payload, &sig));
    }

    #[test]
    fn modified_round_rejects() {
        let (id, pk, signer) = gen_keypair();
        let reg = Arc::new(make_registry(&[(id.clone(), pk)]));
        let verifier = RegistryVerifier::new(reg);

        let bh = [0xAAu8; 32];
        let payload = VoteMessage::signing_payload_v2(BftPhase::Prepare, &bh, 5, &id);
        let sig = signer.sign(&payload).unwrap();

        let bad_payload = VoteMessage::signing_payload_v2(BftPhase::Prepare, &bh, 99, &id);
        assert!(!verifier.verify(&id, &bad_payload, &sig));
    }

    #[test]
    fn modified_phase_rejects() {
        let (id, pk, signer) = gen_keypair();
        let reg = Arc::new(make_registry(&[(id.clone(), pk)]));
        let verifier = RegistryVerifier::new(reg);

        let bh = [0xAAu8; 32];
        let payload = VoteMessage::signing_payload_v2(BftPhase::Prepare, &bh, 5, &id);
        let sig = signer.sign(&payload).unwrap();

        let bad_payload = VoteMessage::signing_payload_v2(BftPhase::Commit, &bh, 5, &id);
        assert!(!verifier.verify(&id, &bad_payload, &sig));
    }

    #[test]
    fn modified_voter_id_rejects() {
        let (id, pk, signer) = gen_keypair();
        let (id2, pk2, _) = gen_keypair();
        let reg = Arc::new(make_registry(&[(id.clone(), pk), (id2.clone(), pk2)]));
        let verifier = RegistryVerifier::new(reg);

        let bh = [0xAAu8; 32];
        let payload = VoteMessage::signing_payload_v2(BftPhase::Prepare, &bh, 5, &id);
        let sig = signer.sign(&payload).unwrap();

        // Verify with the same key (id) but the payload was for a different voter_id.
        let bad_payload = VoteMessage::signing_payload_v2(BftPhase::Prepare, &bh, 5, &id2);
        assert!(!verifier.verify(&id, &bad_payload, &sig));
    }

    #[test]
    fn signature_bit_flip_rejects() {
        let (id, pk, signer) = gen_keypair();
        let reg = Arc::new(make_registry(&[(id.clone(), pk)]));
        let verifier = RegistryVerifier::new(reg);

        let bh = [0xAAu8; 32];
        let payload = VoteMessage::signing_payload_v2(BftPhase::Prepare, &bh, 5, &id);
        let mut sig = signer.sign(&payload).unwrap();
        sig[100] ^= 0xFF; // flip a bit

        assert!(!verifier.verify(&id, &payload, &sig));
    }

    #[test]
    fn unknown_voter_rejects() {
        let (id, pk, _) = gen_keypair();
        let reg = Arc::new(make_registry(&[(id, pk)]));
        let verifier = RegistryVerifier::new(reg);

        assert!(!verifier.verify("unknown", b"data", &[1u8; 3309]));
    }

    // ── E2E: 4 validators, real QC with 3 signatures ────────────────

    #[test]
    fn real_mldsa65_quorum_3_of_4() {
        let pairs: Vec<_> = (0..4).map(|_| gen_keypair()).collect();
        let reg_entries: Vec<(String, Vec<u8>)> = pairs
            .iter()
            .map(|(id, pk, _)| (id.clone(), pk.clone()))
            .collect();
        let reg = Arc::new(make_registry(&reg_entries));
        let verifier = RegistryVerifier::new(reg);

        let bh = [0x42u8; 32];
        let round = 7u64;
        let phase = BftPhase::Commit;

        // 3 validators sign.
        for (id, _, signer) in pairs.iter().take(3) {
            let payload = VoteMessage::signing_payload_v2(phase, &bh, round, id);
            let sig = signer.sign(&payload).unwrap();
            assert!(
                verifier.verify(id, &payload, &sig),
                "validator {id} signature should verify"
            );
        }

        // 4th validator's forged signature (signed by validator 0) rejects.
        let (ref id_3, _, _) = pairs[3];
        let (_, _, ref signer_0) = pairs[0];
        let payload_3 = VoteMessage::signing_payload_v2(phase, &bh, round, id_3);
        let forged_sig = signer_0.sign(&payload_3).unwrap();
        assert!(
            !verifier.verify(id_3, &payload_3, &forged_sig),
            "forged signature must reject"
        );
    }
}
