//! SD-JWT VC — Selective Disclosure JWT Verifiable Credentials.
//!
//! RFC 9901 (SD-JWT) + draft-ietf-oauth-sd-jwt-vc (VC profile).
//! No external JWT crate — JWT is base64url(header).base64url(payload).signature.
//!
//! SD-JWT format: `<issuer-jwt>~<disclosure1>~<disclosure2>~...~`
//! Each disclosure: base64url(json([salt, claim_name, claim_value]))
//! The JWT payload contains `_sd` array with SHA-256 hashes of disclosures.

use crate::crypto::hasher::{hash_with, HashAlgorithm};
use crate::identity::signing::{SigningAlgorithm, SigningProvider};
use serde::{Deserialize, Serialize};

/// SD-JWT VC — an issued credential with selective disclosure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdJwtVc {
    /// The compact serialization: `<jwt>~<disclosure1>~...~`
    pub compact: String,
    /// Individual disclosures (base64url encoded).
    pub disclosures: Vec<String>,
    /// The issuer JWT (first segment before ~).
    pub jwt: String,
}

/// Claims for an SD-JWT VC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcClaims {
    /// Issuer DID or URI.
    pub iss: String,
    /// Subject DID.
    pub sub: String,
    /// Issued at (unix seconds).
    pub iat: u64,
    /// Expiration (unix seconds).
    pub exp: u64,
    /// Credential type (e.g. "IdentityCredential").
    pub vct: String,
    /// Selectively disclosable claims (name → value).
    pub claims: Vec<(String, serde_json::Value)>,
}

/// A single disclosure: [salt, claim_name, claim_value].
#[derive(Debug, Clone)]
pub struct Disclosure {
    pub salt: String,
    pub claim_name: String,
    pub claim_value: serde_json::Value,
    pub encoded: String,
    pub hash: String,
}

/// Verified SD-JWT VC fields.
#[derive(Debug, Clone)]
pub struct VerifiedSdJwt {
    pub iss: String,
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    pub vct: String,
    pub disclosed_claims: Vec<(String, serde_json::Value)>,
    pub algorithm: SigningAlgorithm,
}

fn base64url_encode(data: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, data)
}

fn base64url_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, s)
        .map_err(|e| e.to_string())
}

fn make_disclosure(salt: &str, name: &str, value: &serde_json::Value) -> Disclosure {
    let arr = serde_json::json!([salt, name, value]);
    let json_bytes = serde_json::to_vec(&arr).unwrap_or_default();
    let encoded = base64url_encode(&json_bytes);
    let hash_bytes = hash_with(HashAlgorithm::Sha256, encoded.as_bytes());
    let hash = base64url_encode(&hash_bytes);
    Disclosure {
        salt: salt.to_string(),
        claim_name: name.to_string(),
        claim_value: value.clone(),
        encoded,
        hash,
    }
}

fn generate_salt() -> String {
    use pqc_crypto_module::legacy::rng::OsRng;
    use rand_core::RngCore;
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    base64url_encode(&buf)
}

fn alg_to_jwt(alg: SigningAlgorithm) -> &'static str {
    match alg {
        SigningAlgorithm::Ed25519 => "EdDSA",
        SigningAlgorithm::MlDsa65 => "ML-DSA-65",
        SigningAlgorithm::Rsa => "RS256",
    }
}

fn jwt_to_alg(s: &str) -> Option<SigningAlgorithm> {
    match s {
        "EdDSA" => Some(SigningAlgorithm::Ed25519),
        "ML-DSA-65" => Some(SigningAlgorithm::MlDsa65),
        "RS256" => Some(SigningAlgorithm::Rsa),
        _ => None,
    }
}

/// Issue an SD-JWT VC.
pub fn issue_sd_jwt_vc(
    claims: &VcClaims,
    provider: &dyn SigningProvider,
) -> Result<SdJwtVc, String> {
    let mut disclosures = Vec::new();
    let mut sd_hashes = Vec::new();

    for (name, value) in &claims.claims {
        let salt = generate_salt();
        let d = make_disclosure(&salt, name, value);
        sd_hashes.push(serde_json::Value::String(d.hash.clone()));
        disclosures.push(d);
    }

    let header = serde_json::json!({
        "alg": alg_to_jwt(provider.algorithm()),
        "typ": "vc+sd-jwt",
    });
    let payload = serde_json::json!({
        "iss": claims.iss,
        "sub": claims.sub,
        "iat": claims.iat,
        "exp": claims.exp,
        "vct": claims.vct,
        "_sd_alg": "sha-256",
        "_sd": sd_hashes,
    });

    let header_b64 = base64url_encode(&serde_json::to_vec(&header).map_err(|e| e.to_string())?);
    let payload_b64 = base64url_encode(&serde_json::to_vec(&payload).map_err(|e| e.to_string())?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = provider
        .sign(signing_input.as_bytes())
        .map_err(|e| e.to_string())?;
    let sig_b64 = base64url_encode(&sig);

    let jwt = format!("{signing_input}.{sig_b64}");
    let disclosure_strs: Vec<String> = disclosures.iter().map(|d| d.encoded.clone()).collect();

    let mut compact = jwt.clone();
    for d in &disclosure_strs {
        compact.push('~');
        compact.push_str(d);
    }
    compact.push('~');

    Ok(SdJwtVc {
        compact,
        disclosures: disclosure_strs,
        jwt,
    })
}

/// Create a presentation with only selected disclosures.
pub fn present_sd_jwt(sd_jwt: &SdJwtVc, disclosed_indices: &[usize]) -> String {
    let mut presentation = sd_jwt.jwt.clone();
    for &i in disclosed_indices {
        if let Some(d) = sd_jwt.disclosures.get(i) {
            presentation.push('~');
            presentation.push_str(d);
        }
    }
    presentation.push('~');
    presentation
}

/// Verify an SD-JWT VC presentation and extract disclosed claims.
pub fn verify_sd_jwt_vc(presentation: &str, public_key_hex: &str) -> Result<VerifiedSdJwt, String> {
    let parts: Vec<&str> = presentation.split('~').collect();
    if parts.is_empty() {
        return Err("empty presentation".into());
    }

    let jwt = parts[0];
    let jwt_parts: Vec<&str> = jwt.split('.').collect();
    if jwt_parts.len() != 3 {
        return Err("JWT must have 3 parts".into());
    }

    let header_bytes = base64url_decode(jwt_parts[0])?;
    let payload_bytes = base64url_decode(jwt_parts[1])?;
    let sig_bytes = base64url_decode(jwt_parts[2])?;

    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|e| e.to_string())?;
    let payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|e| e.to_string())?;

    let alg_str = header["alg"].as_str().ok_or("missing alg")?;
    let algorithm = jwt_to_alg(alg_str).ok_or_else(|| format!("unknown alg: {alg_str}"))?;

    // Verify signature
    let signing_input = format!("{}.{}", jwt_parts[0], jwt_parts[1]);
    let sig_hex = hex::encode(&sig_bytes);
    if !crate::signature::verify_signature(
        algorithm,
        public_key_hex,
        signing_input.as_bytes(),
        &sig_hex,
    ) {
        return Err("signature verification failed".into());
    }

    let iss = payload["iss"].as_str().unwrap_or("").to_string();
    let sub = payload["sub"].as_str().unwrap_or("").to_string();
    let iat = payload["iat"].as_u64().unwrap_or(0);
    let exp = payload["exp"].as_u64().unwrap_or(0);
    let vct = payload["vct"].as_str().unwrap_or("").to_string();

    let sd_hashes: Vec<String> = payload["_sd"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Process disclosed claims
    let mut disclosed_claims = Vec::new();
    for part in &parts[1..] {
        if part.is_empty() {
            continue;
        }
        let decoded = base64url_decode(part)?;
        let arr: serde_json::Value = serde_json::from_slice(&decoded).map_err(|e| e.to_string())?;
        let arr = arr.as_array().ok_or("disclosure not an array")?;
        if arr.len() != 3 {
            return Err("disclosure must have 3 elements".into());
        }

        // Verify disclosure hash is in _sd
        let disclosure_hash_bytes = hash_with(HashAlgorithm::Sha256, part.as_bytes());
        let disclosure_hash = base64url_encode(&disclosure_hash_bytes);
        if !sd_hashes.contains(&disclosure_hash) {
            return Err(format!("disclosure hash not in _sd: {disclosure_hash}"));
        }

        let name = arr[1].as_str().ok_or("claim name not string")?;
        disclosed_claims.push((name.to_string(), arr[2].clone()));
    }

    Ok(VerifiedSdJwt {
        iss,
        sub,
        iat,
        exp,
        vct,
        disclosed_claims,
        algorithm,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::SoftwareSigningProvider;

    fn test_claims() -> VcClaims {
        VcClaims {
            iss: "did:goya:issuer".to_string(),
            sub: "did:goya:subject".to_string(),
            iat: 1_700_000_000,
            exp: 1_731_536_000,
            vct: "IdentityCredential".to_string(),
            claims: vec![
                ("given_name".to_string(), serde_json::json!("Juan")),
                ("family_name".to_string(), serde_json::json!("Pérez")),
                ("birth_date".to_string(), serde_json::json!("1990-01-15")),
                ("nationality".to_string(), serde_json::json!("CL")),
            ],
        }
    }

    #[test]
    fn issue_and_verify_full() {
        let provider = SoftwareSigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &provider).unwrap();
        assert!(sd_jwt.compact.contains('~'));
        assert_eq!(sd_jwt.disclosures.len(), 4);

        let pk_hex = hex::encode(provider.public_key());
        let verified = verify_sd_jwt_vc(&sd_jwt.compact, &pk_hex).unwrap();
        assert_eq!(verified.iss, "did:goya:issuer");
        assert_eq!(verified.sub, "did:goya:subject");
        assert_eq!(verified.vct, "IdentityCredential");
        assert_eq!(verified.disclosed_claims.len(), 4);
        assert_eq!(verified.algorithm, SigningAlgorithm::Ed25519);
    }

    #[test]
    fn selective_disclosure() {
        let provider = SoftwareSigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &provider).unwrap();

        // Only disclose given_name (index 0) and nationality (index 3)
        let presentation = present_sd_jwt(&sd_jwt, &[0, 3]);
        let pk_hex = hex::encode(provider.public_key());
        let verified = verify_sd_jwt_vc(&presentation, &pk_hex).unwrap();
        assert_eq!(verified.disclosed_claims.len(), 2);

        let names: Vec<&str> = verified
            .disclosed_claims
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();
        assert!(names.contains(&"given_name"));
        assert!(names.contains(&"nationality"));
        assert!(!names.contains(&"family_name"));
        assert!(!names.contains(&"birth_date"));
    }

    #[test]
    fn zero_disclosures() {
        let provider = SoftwareSigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &provider).unwrap();

        let presentation = present_sd_jwt(&sd_jwt, &[]);
        let pk_hex = hex::encode(provider.public_key());
        let verified = verify_sd_jwt_vc(&presentation, &pk_hex).unwrap();
        assert!(verified.disclosed_claims.is_empty());
        // But metadata is still visible
        assert_eq!(verified.iss, "did:goya:issuer");
        assert_eq!(verified.vct, "IdentityCredential");
    }

    #[test]
    fn wrong_key_fails() {
        let provider = SoftwareSigningProvider::generate();
        let other = SoftwareSigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &provider).unwrap();

        let wrong_pk = hex::encode(other.public_key());
        assert!(verify_sd_jwt_vc(&sd_jwt.compact, &wrong_pk).is_err());
    }

    #[test]
    fn tampered_disclosure_rejected() {
        let provider = SoftwareSigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &provider).unwrap();

        // Create a fake disclosure not in _sd
        let fake = base64url_encode(
            &serde_json::to_vec(&serde_json::json!(["fakesalt", "fake_claim", "fake_value"]))
                .unwrap(),
        );
        let tampered = format!("{}~{}~", sd_jwt.jwt, fake);
        let pk_hex = hex::encode(provider.public_key());
        assert!(verify_sd_jwt_vc(&tampered, &pk_hex).is_err());
    }

    #[test]
    fn jwt_has_correct_type() {
        let provider = SoftwareSigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &provider).unwrap();
        let jwt_parts: Vec<&str> = sd_jwt.jwt.split('.').collect();
        let header_bytes = base64url_decode(jwt_parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["typ"], "vc+sd-jwt");
        assert_eq!(header["alg"], "EdDSA");
    }

    #[test]
    fn payload_has_sd_array() {
        let provider = SoftwareSigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &provider).unwrap();
        let jwt_parts: Vec<&str> = sd_jwt.jwt.split('.').collect();
        let payload_bytes = base64url_decode(jwt_parts[1]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["_sd_alg"], "sha-256");
        assert_eq!(payload["_sd"].as_array().unwrap().len(), 4);
        assert_eq!(payload["vct"], "IdentityCredential");
    }

    #[test]
    fn mldsa65_roundtrip() {
        use crate::identity::signing::MlDsaSigningProvider;
        let provider = MlDsaSigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &provider).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let verified = verify_sd_jwt_vc(&sd_jwt.compact, &pk_hex).unwrap();
        assert_eq!(verified.algorithm, SigningAlgorithm::MlDsa65);
        assert_eq!(verified.disclosed_claims.len(), 4);
    }

    #[test]
    fn rsa_roundtrip() {
        use crate::identity::signing::RsaSigningProvider;
        let provider = RsaSigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &provider).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let verified = verify_sd_jwt_vc(&sd_jwt.compact, &pk_hex).unwrap();
        assert_eq!(verified.algorithm, SigningAlgorithm::Rsa);
    }

    #[test]
    fn single_claim_disclosure() {
        let provider = SoftwareSigningProvider::generate();
        let claims = VcClaims {
            iss: "did:goya:i".to_string(),
            sub: "did:goya:s".to_string(),
            iat: 1_700_000_000,
            exp: 1_731_536_000,
            vct: "AgeVerification".to_string(),
            claims: vec![("age_over_18".to_string(), serde_json::json!(true))],
        };
        let sd_jwt = issue_sd_jwt_vc(&claims, &provider).unwrap();
        assert_eq!(sd_jwt.disclosures.len(), 1);

        let pk_hex = hex::encode(provider.public_key());
        let verified = verify_sd_jwt_vc(&sd_jwt.compact, &pk_hex).unwrap();
        assert_eq!(verified.disclosed_claims.len(), 1);
        assert_eq!(verified.disclosed_claims[0].0, "age_over_18");
        assert_eq!(verified.disclosed_claims[0].1, true);
    }

    #[test]
    fn empty_claims() {
        let provider = SoftwareSigningProvider::generate();
        let claims = VcClaims {
            iss: "did:goya:i".to_string(),
            sub: "did:goya:s".to_string(),
            iat: 1_700_000_000,
            exp: 1_731_536_000,
            vct: "EmptyVC".to_string(),
            claims: vec![],
        };
        let sd_jwt = issue_sd_jwt_vc(&claims, &provider).unwrap();
        assert!(sd_jwt.disclosures.is_empty());
        let pk_hex = hex::encode(provider.public_key());
        let verified = verify_sd_jwt_vc(&sd_jwt.compact, &pk_hex).unwrap();
        assert!(verified.disclosed_claims.is_empty());
    }
}
