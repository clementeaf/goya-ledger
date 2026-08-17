//! IETF Token Status List (draft-ietf-oauth-status-list-20/21).
//!
//! Implements the Attestation Status List (ASL) for EUDI credential revocation.
//! Format: `statuslist+jwt` — ZLIB-compressed bitstring wrapped in a signed JWT.
//!
//! Wire format follows the IETF spec exactly:
//! - `bits`: 2 (supports VALID/INVALID/SUSPENDED)
//! - `lst`: base64url(zlib(bitstring))
//! - Status reference in credential: `status.status_list.{idx, uri}`

use crate::crypto::hasher::{hash_with, HashAlgorithm};
use crate::identity::signing::SigningProvider;

const DEFAULT_BITS: u8 = 2;
const MIN_LIST_SIZE: usize = 16384; // ponytail: 16K entries, ARF recommends 10K+

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CredentialStatus {
    Valid = 0x00,
    Invalid = 0x01,   // revoked — permanent
    Suspended = 0x02, // temporary
}

impl CredentialStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Valid),
            0x01 => Some(Self::Invalid),
            0x02 => Some(Self::Suspended),
            _ => None,
        }
    }
}

impl std::fmt::Display for CredentialStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid => write!(f, "VALID"),
            Self::Invalid => write!(f, "INVALID"),
            Self::Suspended => write!(f, "SUSPENDED"),
        }
    }
}

/// Core status list bitstring. Thread-safe for concurrent issuer use.
pub struct StatusList {
    id: String,
    bits: u8,
    data: std::sync::Mutex<StatusListData>,
}

struct StatusListData {
    entries: Vec<u8>,
    allocated: std::collections::HashSet<usize>,
    version: u64,
}

fn base64url_encode(data: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, data)
}

fn base64url_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, s)
        .map_err(|e| e.to_string())
}

impl StatusList {
    pub fn new(id: impl Into<String>, capacity: usize) -> Self {
        let cap = capacity.max(MIN_LIST_SIZE);
        let bits = DEFAULT_BITS;
        let entries_per_byte = 8 / bits as usize;
        let byte_len = cap.div_ceil(entries_per_byte);
        Self {
            id: id.into(),
            bits,
            data: std::sync::Mutex::new(StatusListData {
                entries: vec![0u8; byte_len],
                allocated: std::collections::HashSet::new(),
                version: 0,
            }),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn capacity(&self) -> usize {
        let data = self.data.lock().unwrap();
        data.entries.len() * (8 / self.bits as usize)
    }

    /// Allocate a random, unpredictable index for a new credential.
    pub fn allocate_index(&self) -> Result<usize, String> {
        use pqc_crypto_module::legacy::rng::OsRng;
        use rand_core::RngCore;

        let mut data = self.data.lock().unwrap();
        let cap = data.entries.len() * (8 / self.bits as usize);

        if data.allocated.len() >= cap {
            return Err("status list full".into());
        }

        // Random probing — expected O(1) when list is <80% full
        let mut buf = [0u8; 8];
        for _ in 0..1000 {
            OsRng.fill_bytes(&mut buf);
            let idx = (u64::from_le_bytes(buf) as usize) % cap;
            if data.allocated.insert(idx) {
                return Ok(idx);
            }
        }
        Err("failed to allocate unique index after 1000 attempts".into())
    }

    /// Set the status of a credential at `idx`.
    pub fn set_status(&self, idx: usize, status: CredentialStatus) -> Result<(), String> {
        let mut data = self.data.lock().unwrap();
        let entries_per_byte = 8 / self.bits as usize;
        let cap = data.entries.len() * entries_per_byte;
        if idx >= cap {
            return Err(format!("index {idx} out of range (capacity {cap})"));
        }
        let byte_idx = idx * self.bits as usize / 8;
        let bit_offset = (idx * self.bits as usize) % 8;
        let mask = ((1u16 << self.bits) - 1) as u8;
        data.entries[byte_idx] &= !(mask << bit_offset);
        data.entries[byte_idx] |= (status as u8 & mask) << bit_offset;
        data.version += 1;
        Ok(())
    }

    /// Get the status of a credential at `idx`.
    pub fn get_status(&self, idx: usize) -> Result<CredentialStatus, String> {
        let data = self.data.lock().unwrap();
        get_status_from_bytes(&data.entries, self.bits, idx)
    }

    /// Compress the bitstring with ZLIB (RFC 1950) and base64url-encode.
    fn compressed_lst(&self) -> Result<String, String> {
        let data = self.data.lock().unwrap();
        compress_and_encode(&data.entries)
    }

    pub fn version(&self) -> u64 {
        self.data.lock().unwrap().version
    }

    /// Produce the signed `statuslist+jwt` token.
    pub fn to_jwt(
        &self,
        issuer_uri: &str,
        ttl_secs: u64,
        provider: &dyn SigningProvider,
    ) -> Result<String, String> {
        let now = now_secs();
        let lst = self.compressed_lst()?;
        let sub = format!("{issuer_uri}/api/v1/statuslist/{}", self.id);

        let header = serde_json::json!({
            "alg": crate::identity::sd_jwt::alg_to_jwt_pub(provider.algorithm()),
            "typ": "statuslist+jwt",
        });
        let payload = serde_json::json!({
            "sub": sub,
            "iat": now,
            "exp": now + ttl_secs,
            "ttl": ttl_secs,
            "status_list": {
                "bits": self.bits,
                "lst": lst,
            },
        });

        sign_jwt(&header, &payload, provider)
    }

    /// SHA-256 hash of the current list state — for DLT anchoring.
    pub fn anchor_hash(&self) -> [u8; 32] {
        let data = self.data.lock().unwrap();
        let mut preimage = Vec::new();
        preimage.extend_from_slice(self.id.as_bytes());
        preimage.extend_from_slice(&data.version.to_le_bytes());
        preimage.extend_from_slice(&data.entries);
        let h = hash_with(HashAlgorithm::Sha256, &preimage);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h);
        out
    }
}

fn compress_and_encode(data: &[u8]) -> Result<String, String> {
    use std::io::Write;
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(data).map_err(|e| e.to_string())?;
    let compressed = encoder.finish().map_err(|e| e.to_string())?;
    Ok(base64url_encode(&compressed))
}

fn decompress(encoded: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let compressed = base64url_decode(encoded)?;
    let mut decoder = flate2::read::ZlibDecoder::new(&compressed[..]);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

fn get_status_from_bytes(entries: &[u8], bits: u8, idx: usize) -> Result<CredentialStatus, String> {
    let entries_per_byte = 8 / bits as usize;
    let cap = entries.len() * entries_per_byte;
    if idx >= cap {
        return Err(format!("index {idx} out of range (capacity {cap})"));
    }
    let byte_idx = idx * bits as usize / 8;
    let bit_offset = (idx * bits as usize) % 8;
    let mask = ((1u16 << bits) - 1) as u8;
    let val = (entries[byte_idx] >> bit_offset) & mask;
    CredentialStatus::from_u8(val).ok_or_else(|| format!("unknown status value {val}"))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn sign_jwt(
    header: &serde_json::Value,
    payload: &serde_json::Value,
    provider: &dyn SigningProvider,
) -> Result<String, String> {
    let h = base64url_encode(&serde_json::to_vec(header).map_err(|e| e.to_string())?);
    let p = base64url_encode(&serde_json::to_vec(payload).map_err(|e| e.to_string())?);
    let signing_input = format!("{h}.{p}");
    let sig = provider
        .sign(signing_input.as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(format!("{signing_input}.{}", base64url_encode(&sig)))
}

// ── Verification (Relying Party side) ────────────────────────────────────

/// Verify a `statuslist+jwt` and extract the status for a given index.
pub fn verify_status_from_jwt(
    status_list_jwt: &str,
    idx: usize,
    issuer_pubkey_hex: &str,
) -> Result<CredentialStatus, String> {
    let parts: Vec<&str> = status_list_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("statuslist+jwt must have 3 parts".into());
    }

    let header: serde_json::Value =
        serde_json::from_slice(&base64url_decode(parts[0])?).map_err(|e| e.to_string())?;
    let payload: serde_json::Value =
        serde_json::from_slice(&base64url_decode(parts[1])?).map_err(|e| e.to_string())?;

    // Verify typ
    let typ = header.get("typ").and_then(|v| v.as_str()).unwrap_or("");
    if typ != "statuslist+jwt" {
        return Err(format!("expected typ=statuslist+jwt, got {typ}"));
    }

    // Verify signature
    let alg_str = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    let algorithm = crate::identity::sd_jwt::jwt_to_alg_pub(alg_str)
        .ok_or_else(|| format!("unsupported alg: {alg_str}"))?;
    let sig_bytes = base64url_decode(parts[2])?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    if !crate::signature::verify_signature(
        algorithm,
        issuer_pubkey_hex,
        signing_input.as_bytes(),
        &hex::encode(&sig_bytes),
    ) {
        return Err("status list signature verification failed".into());
    }

    // Check expiration
    if let Some(exp) = payload.get("exp").and_then(|v| v.as_u64()) {
        if now_secs() > exp {
            return Err("status list expired".into());
        }
    }

    // Decode status_list
    let sl = payload
        .get("status_list")
        .ok_or("missing status_list claim")?;
    let bits = sl
        .get("bits")
        .and_then(|v| v.as_u64())
        .ok_or("missing status_list.bits")? as u8;
    let lst = sl
        .get("lst")
        .and_then(|v| v.as_str())
        .ok_or("missing status_list.lst")?;

    let entries = decompress(lst)?;
    get_status_from_bytes(&entries, bits, idx)
}

/// Build the `status` claim to embed in an SD-JWT VC or mdoc.
pub fn status_claim(uri: &str, idx: usize) -> serde_json::Value {
    serde_json::json!({
        "status_list": {
            "idx": idx,
            "uri": uri,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::{EcdsaP256SigningProvider, SigningProvider};

    #[test]
    fn new_list_all_valid() {
        let sl = StatusList::new("test-1", 100);
        assert!(sl.capacity() >= 100);
        for i in 0..100 {
            assert_eq!(sl.get_status(i).unwrap(), CredentialStatus::Valid);
        }
    }

    #[test]
    fn set_and_get_status() {
        let sl = StatusList::new("test-2", 1000);
        sl.set_status(42, CredentialStatus::Invalid).unwrap();
        sl.set_status(99, CredentialStatus::Suspended).unwrap();
        assert_eq!(sl.get_status(42).unwrap(), CredentialStatus::Invalid);
        assert_eq!(sl.get_status(99).unwrap(), CredentialStatus::Suspended);
        assert_eq!(sl.get_status(0).unwrap(), CredentialStatus::Valid);
    }

    #[test]
    fn revoke_then_check() {
        let sl = StatusList::new("revoke", 500);
        sl.set_status(100, CredentialStatus::Invalid).unwrap();
        assert_eq!(sl.get_status(100).unwrap(), CredentialStatus::Invalid);
        // Other entries unaffected
        assert_eq!(sl.get_status(99).unwrap(), CredentialStatus::Valid);
        assert_eq!(sl.get_status(101).unwrap(), CredentialStatus::Valid);
    }

    #[test]
    fn suspend_and_reactivate() {
        let sl = StatusList::new("suspend", 500);
        sl.set_status(200, CredentialStatus::Suspended).unwrap();
        assert_eq!(sl.get_status(200).unwrap(), CredentialStatus::Suspended);
        sl.set_status(200, CredentialStatus::Valid).unwrap();
        assert_eq!(sl.get_status(200).unwrap(), CredentialStatus::Valid);
    }

    #[test]
    fn out_of_range_fails() {
        let sl = StatusList::new("range", 100);
        let cap = sl.capacity();
        assert!(sl.get_status(cap).is_err());
        assert!(sl.set_status(cap, CredentialStatus::Invalid).is_err());
    }

    #[test]
    fn allocate_index_unique() {
        let sl = StatusList::new("alloc", MIN_LIST_SIZE);
        let mut indices = std::collections::HashSet::new();
        for _ in 0..100 {
            let idx = sl.allocate_index().unwrap();
            assert!(indices.insert(idx), "duplicate index {idx}");
        }
    }

    #[test]
    fn compress_decompress_roundtrip() {
        let data = vec![0u8; 4096]; // all zeros = high compression
        let encoded = compress_and_encode(&data).unwrap();
        let decoded = decompress(&encoded).unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    fn jwt_sign_and_verify() {
        let provider = EcdsaP256SigningProvider::generate();
        let sl = StatusList::new("jwt-test", MIN_LIST_SIZE);
        sl.set_status(42, CredentialStatus::Invalid).unwrap();

        let jwt = sl
            .to_jwt("https://issuer.example.com", 3600, &provider)
            .unwrap();
        let pk_hex = hex::encode(provider.public_key());

        let status = verify_status_from_jwt(&jwt, 42, &pk_hex).unwrap();
        assert_eq!(status, CredentialStatus::Invalid);

        let status_0 = verify_status_from_jwt(&jwt, 0, &pk_hex).unwrap();
        assert_eq!(status_0, CredentialStatus::Valid);
    }

    #[test]
    fn jwt_wrong_key_rejects() {
        let signer = EcdsaP256SigningProvider::generate();
        let wrong = EcdsaP256SigningProvider::generate();
        let sl = StatusList::new("wrong-key", MIN_LIST_SIZE);
        let jwt = sl
            .to_jwt("https://issuer.example.com", 3600, &signer)
            .unwrap();
        let wrong_pk = hex::encode(wrong.public_key());
        assert!(verify_status_from_jwt(&jwt, 0, &wrong_pk).is_err());
    }

    #[test]
    fn jwt_tampered_payload_rejects() {
        let provider = EcdsaP256SigningProvider::generate();
        let sl = StatusList::new("tamper", MIN_LIST_SIZE);
        let jwt = sl
            .to_jwt("https://issuer.example.com", 3600, &provider)
            .unwrap();
        let pk_hex = hex::encode(provider.public_key());

        // Tamper payload
        let parts: Vec<&str> = jwt.split('.').collect();
        let mut payload_bytes = base64url_decode(parts[1]).unwrap();
        payload_bytes[0] ^= 0xff;
        let tampered_payload = base64url_encode(&payload_bytes);
        let tampered = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

        assert!(verify_status_from_jwt(&tampered, 0, &pk_hex).is_err());
    }

    #[test]
    fn jwt_expired_list_rejects() {
        let provider = EcdsaP256SigningProvider::generate();
        let sl = StatusList::new("expired", MIN_LIST_SIZE);
        // TTL=0 → already expired by the time we verify
        let jwt = sl
            .to_jwt("https://issuer.example.com", 0, &provider)
            .unwrap();
        let pk_hex = hex::encode(provider.public_key());
        // Might pass if verification happens in same second
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(verify_status_from_jwt(&jwt, 0, &pk_hex).is_err());
    }

    #[test]
    fn jwt_invalid_index_rejects() {
        let provider = EcdsaP256SigningProvider::generate();
        let sl = StatusList::new("bad-idx", MIN_LIST_SIZE);
        let jwt = sl
            .to_jwt("https://issuer.example.com", 3600, &provider)
            .unwrap();
        let pk_hex = hex::encode(provider.public_key());
        assert!(verify_status_from_jwt(&jwt, usize::MAX, &pk_hex).is_err());
    }

    #[test]
    fn status_claim_format() {
        let claim = status_claim("https://issuer.example.com/api/v1/statuslist/1", 42);
        assert_eq!(claim["status_list"]["idx"], 42);
        assert_eq!(
            claim["status_list"]["uri"],
            "https://issuer.example.com/api/v1/statuslist/1"
        );
    }

    #[test]
    fn anchor_hash_changes_on_revocation() {
        let sl = StatusList::new("anchor", MIN_LIST_SIZE);
        let h1 = sl.anchor_hash();
        sl.set_status(10, CredentialStatus::Invalid).unwrap();
        let h2 = sl.anchor_hash();
        assert_ne!(h1, h2);
    }

    #[test]
    fn anchor_hash_deterministic() {
        let sl = StatusList::new("det", MIN_LIST_SIZE);
        sl.set_status(5, CredentialStatus::Invalid).unwrap();
        let h1 = sl.anchor_hash();
        let h2 = sl.anchor_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn min_list_size_enforced() {
        let sl = StatusList::new("small", 10);
        assert!(sl.capacity() >= MIN_LIST_SIZE);
    }

    #[test]
    fn bit_packing_ietf_spec_compliant() {
        // Verify LSB-first packing per IETF draft §5.1
        let sl = StatusList::new("pack", MIN_LIST_SIZE);
        // idx 0 → byte 0, bits 0-1
        sl.set_status(0, CredentialStatus::Invalid).unwrap(); // 0b01
                                                              // idx 1 → byte 0, bits 2-3
        sl.set_status(1, CredentialStatus::Suspended).unwrap(); // 0b10
                                                                // idx 2 → byte 0, bits 4-5
        sl.set_status(2, CredentialStatus::Valid).unwrap(); // 0b00
                                                            // idx 3 → byte 0, bits 6-7
        sl.set_status(3, CredentialStatus::Invalid).unwrap(); // 0b01

        // Expected byte: 0b01_00_10_01 = 0x49
        let data = sl.data.lock().unwrap();
        assert_eq!(
            data.entries[0], 0x49,
            "byte 0 = 0x{:02X}, expected 0x49",
            data.entries[0]
        );
    }

    #[test]
    fn version_increments() {
        let sl = StatusList::new("ver", MIN_LIST_SIZE);
        assert_eq!(sl.version(), 0);
        sl.set_status(0, CredentialStatus::Invalid).unwrap();
        assert_eq!(sl.version(), 1);
        sl.set_status(0, CredentialStatus::Valid).unwrap();
        assert_eq!(sl.version(), 2);
    }
}
