//! DER-encoded OCSP request/response per RFC 6960.
//!
//! Produces binary OCSPResponse wrapping a BasicOCSPResponse with
//! signed ResponseData. Zero external ASN.1 deps — inline DER helpers
//! matching the cades_der.rs / rfc3161_der.rs pattern.

use crate::crypto::hasher::{hash_with, HashAlgorithm};
use crate::identity::signing::{SigningAlgorithm, SigningProvider};
use crate::msp::ocsp::{CertStatus, OcspResponse, SingleResponse};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OcspDerError {
    #[error("DER encoding: {0}")]
    Der(String),
    #[error("signing: {0}")]
    Signing(#[from] crate::identity::signing::SigningError),
    #[error("invalid: {0}")]
    Invalid(String),
}

// ── Pre-computed OIDs ─────────────────────────────────────────────────────

/// id-pkix-ocsp-basic 1.3.6.1.5.5.7.48.1.1
const OID_OCSP_BASIC: &[u8] = &[
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01,
];
/// id-pkix-ocsp-nonce 1.3.6.1.5.5.7.48.1.2
const OID_OCSP_NONCE: &[u8] = &[
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02,
];
/// id-sha256 2.16.840.1.101.3.4.2.1
const OID_SHA256: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
];
/// id-EdDSA 1.3.101.112 (Ed25519)
const OID_ED25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];
/// id-ML-DSA-65 2.16.840.1.101.3.4.3.17
const OID_MLDSA65: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
];
/// id-slh-dsa-shake-128s 2.16.840.1.101.3.4.3.20 (FIPS 205)
const OID_SLHDSA128S: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14,
];
/// sha256WithRSAEncryption 1.2.840.113549.1.1.11
const OID_RSA_SHA256: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
];
/// ecdsa-with-SHA256 1.2.840.10045.4.3.2
const OID_ECDSA_P256: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

// ── DER helpers ───────────────────────────────────────────────────────────

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(value.len()));
    out.extend(value);
    out
}

fn der_seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn der_octet(v: &[u8]) -> Vec<u8> {
    tlv(0x04, v)
}

fn der_int_bytes(v: &[u8]) -> Vec<u8> {
    if v.is_empty() {
        return tlv(0x02, &[0]);
    }
    let start = v.iter().position(|&b| b != 0).unwrap_or(v.len() - 1);
    let mut val: Vec<u8> = v[start..].to_vec();
    if val[0] & 0x80 != 0 {
        val.insert(0, 0);
    }
    tlv(0x02, &val)
}

fn der_enum(v: u8) -> Vec<u8> {
    tlv(0x0A, &[v])
}

fn der_bitstring(v: &[u8]) -> Vec<u8> {
    let mut content = vec![0x00]; // no unused bits
    content.extend(v);
    tlv(0x03, &content)
}

fn der_gentime(s: &str) -> Vec<u8> {
    tlv(0x18, s.as_bytes())
}

fn format_gen_time(unix: u64) -> String {
    use chrono::TimeZone;
    chrono::Utc
        .timestamp_opt(unix as i64, 0)
        .single()
        .map(|dt| dt.format("%Y%m%d%H%M%SZ").to_string())
        .unwrap_or_else(|| "19700101000000Z".to_string())
}

fn signing_oid(alg: SigningAlgorithm) -> &'static [u8] {
    match alg {
        SigningAlgorithm::Ed25519 => OID_ED25519,
        SigningAlgorithm::MlDsa65 => OID_MLDSA65,
        SigningAlgorithm::Rsa => OID_RSA_SHA256,
        SigningAlgorithm::EcdsaP256 => OID_ECDSA_P256,
        SigningAlgorithm::SlhDsa128s => OID_SLHDSA128S,
    }
}

// ── Build OCSP DER ───────────────────────────────────────────────────────

/// Build a CertID per RFC 6960 §4.1.1.
/// Uses SHA-256 for issuer hashing. `issuer_name` is hashed as UTF-8 bytes
/// (simplification — real X.509 would hash the DER-encoded Name).
fn build_cert_id(issuer_name: &str, issuer_key: &[u8], serial: &[u8]) -> Vec<u8> {
    let sha256_aid = der_seq(&[OID_SHA256]);
    let name_hash = hash_with(HashAlgorithm::Sha256, issuer_name.as_bytes());
    let key_hash = hash_with(HashAlgorithm::Sha256, issuer_key);
    der_seq(&[
        &sha256_aid,
        &der_octet(&name_hash),
        &der_octet(&key_hash),
        &der_int_bytes(serial),
    ])
}

/// CertStatus encoding per RFC 6960 §4.2.1:
/// good        [0] IMPLICIT NULL
/// revoked     [1] IMPLICIT RevokedInfo (we use thisUpdate as revocation time)
/// unknown     [2] IMPLICIT NULL
fn encode_cert_status(status: CertStatus, this_update: u64) -> Vec<u8> {
    match status {
        CertStatus::Good => tlv(0x80, &[]), // [0] IMPLICIT NULL (zero-length)
        CertStatus::Revoked => {
            let revoked_time = der_gentime(&format_gen_time(this_update));
            tlv(0xA1, &revoked_time) // [1] IMPLICIT SEQUENCE { revocationTime }
        }
        CertStatus::Unknown => tlv(0x82, &[]), // [2] IMPLICIT NULL
    }
}

/// Build a DER SingleResponse per RFC 6960 §4.2.1.
fn build_single_response_der(
    single: &SingleResponse,
    issuer_name: &str,
    issuer_key: &[u8],
) -> Result<Vec<u8>, OcspDerError> {
    let serial_bytes = hex::decode(&single.serial)
        .map_err(|e| OcspDerError::Der(format!("bad serial hex: {e}")))?;
    let cert_id = build_cert_id(issuer_name, issuer_key, &serial_bytes);
    let cert_status = encode_cert_status(single.status, single.this_update);
    let this_update = der_gentime(&format_gen_time(single.this_update));
    let next_update = tlv(0xA0, &der_gentime(&format_gen_time(single.next_update)));
    Ok(der_seq(&[
        &cert_id,
        &cert_status,
        &this_update,
        &next_update,
    ]))
}

/// Encode the full DER OCSPResponse from our JSON OcspResponse.
///
/// Structure (RFC 6960 §4.2.1):
/// ```text
/// OCSPResponse ::= SEQUENCE {
///   responseStatus  ENUMERATED,
///   responseBytes   [0] EXPLICIT ResponseBytes OPTIONAL }
/// ResponseBytes ::= SEQUENCE {
///   responseType  OID (id-pkix-ocsp-basic),
///   response      OCTET STRING (DER BasicOCSPResponse) }
/// BasicOCSPResponse ::= SEQUENCE {
///   tbsResponseData  ResponseData,
///   signatureAlgorithm AlgorithmIdentifier,
///   signature        BIT STRING,
///   certs        [0] EXPLICIT ... OPTIONAL }
/// ```
pub fn encode_ocsp_response_der(
    resp: &OcspResponse,
    provider: &dyn SigningProvider,
) -> Result<Vec<u8>, OcspDerError> {
    let ocsp_status = match resp.response_status {
        0 => 0u8, // successful
        1 => 1,   // malformedRequest
        2 => 2,   // internalError
        6 => 6,   // unauthorized
        s => {
            return Err(OcspDerError::Der(format!("unsupported status {s}")));
        }
    };

    if resp.response_status != 0 {
        return Ok(der_seq(&[&der_enum(ocsp_status)]));
    }

    let single = resp.response.as_ref().ok_or_else(|| {
        OcspDerError::Invalid("successful response without SingleResponse".into())
    })?;

    let pk = provider.public_key();
    let pk_hash = hash_with(HashAlgorithm::Sha256, &pk);
    let responder_key_hash = &pk_hash[..20];

    let single_resp_der = build_single_response_der(single, &resp.responder_id, &pk)?;

    let produced_at = der_gentime(&format_gen_time(resp.produced_at));

    // ResponderID: byKey [2] EXPLICIT KeyHash OCTET STRING
    let responder_id_der = tlv(0xA2, &der_octet(responder_key_hash));

    // ResponseData (tbsResponseData)
    let mut tbs_parts: Vec<Vec<u8>> = vec![
        responder_id_der,
        produced_at,
        der_seq(&[&single_resp_der]), // responses SEQUENCE OF SingleResponse
    ];

    // responseExtensions [1] EXPLICIT Extensions: nonce
    if let Some(nonce) = resp.nonce {
        let nonce_value = der_octet(&nonce.to_be_bytes());
        let nonce_ext = der_seq(&[OID_OCSP_NONCE, &der_octet(&nonce_value)]);
        let exts = tlv(0xA1, &der_seq(&[&nonce_ext]));
        tbs_parts.push(exts);
    }

    let tbs_refs: Vec<&[u8]> = tbs_parts.iter().map(|v| v.as_slice()).collect();
    let tbs_response_data = der_seq(&tbs_refs);

    // Sign tbsResponseData
    let signature = provider.sign(&tbs_response_data)?;
    let sig_alg = der_seq(&[signing_oid(provider.algorithm())]);
    let sig_bits = der_bitstring(&signature);

    let basic_ocsp = der_seq(&[&tbs_response_data, &sig_alg, &sig_bits]);

    // ResponseBytes
    let response_bytes = der_seq(&[OID_OCSP_BASIC, &der_octet(&basic_ocsp)]);

    // OCSPResponse
    Ok(der_seq(&[
        &der_enum(ocsp_status),
        &tlv(0xA0, &response_bytes),
    ]))
}

// ── DER parsing helpers ──────────────────────────────────────────────────

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

fn parse_tlv(data: &[u8]) -> Result<(Tlv<'_>, &[u8]), OcspDerError> {
    if data.is_empty() {
        return Err(OcspDerError::Invalid("unexpected end".into()));
    }
    let tag = data[0];
    let (len, hdr) = parse_der_len(&data[1..])?;
    let total = 1 + hdr + len;
    if total > data.len() {
        return Err(OcspDerError::Invalid("truncated TLV".into()));
    }
    Ok((
        Tlv {
            tag,
            value: &data[1 + hdr..total],
        },
        &data[total..],
    ))
}

fn parse_der_len(data: &[u8]) -> Result<(usize, usize), OcspDerError> {
    if data.is_empty() {
        return Err(OcspDerError::Invalid("missing length".into()));
    }
    if data[0] < 0x80 {
        return Ok((data[0] as usize, 1));
    }
    let n = (data[0] & 0x7F) as usize;
    if n == 0 || n > 3 || 1 + n > data.len() {
        return Err(OcspDerError::Invalid("bad DER length".into()));
    }
    let mut len = 0usize;
    for &b in &data[1..1 + n] {
        len = (len << 8) | b as usize;
    }
    Ok((len, 1 + n))
}

fn parse_elements(data: &[u8]) -> Result<Vec<Tlv<'_>>, OcspDerError> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let (t, r) = parse_tlv(rest)?;
        out.push(t);
        rest = r;
    }
    Ok(out)
}

fn parse_int_u64(data: &[u8]) -> u64 {
    let mut v = 0u64;
    for &b in data {
        v = (v << 8) | b as u64;
    }
    v
}

/// Verified fields extracted from a DER OCSPResponse.
#[derive(Debug, Clone)]
pub struct OcspDerFields {
    pub response_status: u8,
    pub cert_status_tag: u8,
    pub serial_hex: String,
    pub produced_at: String,
    pub this_update: String,
    pub next_update: Option<String>,
    pub nonce: Option<u64>,
    pub signature_verified: bool,
}

/// Verify a DER-encoded OCSPResponse and extract fields.
pub fn verify_ocsp_response_der(
    der_bytes: &[u8],
    public_key_hex: &str,
) -> Result<OcspDerFields, OcspDerError> {
    let inv = |s: &str| OcspDerError::Invalid(s.into());

    let (outer, _) = parse_tlv(der_bytes)?;
    if outer.tag != 0x30 {
        return Err(inv("not a SEQUENCE"));
    }
    let outer_elems = parse_elements(outer.value)?;
    if outer_elems.is_empty() {
        return Err(inv("empty OCSPResponse"));
    }

    // responseStatus ENUMERATED
    if outer_elems[0].tag != 0x0A {
        return Err(inv("responseStatus not ENUMERATED"));
    }
    let response_status = outer_elems[0].value[0];

    if response_status != 0 {
        return Ok(OcspDerFields {
            response_status,
            cert_status_tag: 0,
            serial_hex: String::new(),
            produced_at: String::new(),
            this_update: String::new(),
            next_update: None,
            nonce: None,
            signature_verified: false,
        });
    }

    // responseBytes [0] EXPLICIT
    if outer_elems.len() < 2 || outer_elems[1].tag != 0xA0 {
        return Err(inv("missing responseBytes"));
    }
    let (rb_seq, _) = parse_tlv(outer_elems[1].value)?;
    if rb_seq.tag != 0x30 {
        return Err(inv("ResponseBytes not SEQUENCE"));
    }
    let rb_elems = parse_elements(rb_seq.value)?;
    if rb_elems.len() < 2 {
        return Err(inv("ResponseBytes too short"));
    }
    // Verify responseType OID
    if rb_elems[0].tag != 0x06 {
        return Err(inv("responseType not OID"));
    }

    // response OCTET STRING → BasicOCSPResponse
    if rb_elems[1].tag != 0x04 {
        return Err(inv("response not OCTET STRING"));
    }
    let (basic, _) = parse_tlv(rb_elems[1].value)?;
    if basic.tag != 0x30 {
        return Err(inv("BasicOCSPResponse not SEQUENCE"));
    }
    let basic_elems = parse_elements(basic.value)?;
    if basic_elems.len() < 3 {
        return Err(inv("BasicOCSPResponse too short"));
    }

    // tbsResponseData is the first SEQUENCE
    let tbs = &basic_elems[0];
    if tbs.tag != 0x30 {
        return Err(inv("tbsResponseData not SEQUENCE"));
    }
    let tbs_raw = tlv(0x30, tbs.value);

    let tbs_elems = parse_elements(tbs.value)?;

    // Parse tbs elements: responderID, producedAt, responses, [extensions]
    let mut idx = 0;

    // Skip responderID ([1] byName or [2] byKey)
    if idx < tbs_elems.len() && (tbs_elems[idx].tag == 0xA1 || tbs_elems[idx].tag == 0xA2) {
        idx += 1;
    }

    // producedAt GeneralizedTime
    let produced_at = if idx < tbs_elems.len() && tbs_elems[idx].tag == 0x18 {
        let s = String::from_utf8_lossy(tbs_elems[idx].value).to_string();
        idx += 1;
        s
    } else {
        return Err(inv("missing producedAt"));
    };

    // responses SEQUENCE OF SingleResponse
    if idx >= tbs_elems.len() || tbs_elems[idx].tag != 0x30 {
        return Err(inv("missing responses SEQUENCE"));
    }
    let responses_elems = parse_elements(tbs_elems[idx].value)?;
    idx += 1;

    if responses_elems.is_empty() {
        return Err(inv("empty responses"));
    }
    // Parse first SingleResponse
    let sr = parse_single_response(&responses_elems[0])?;

    // Check for nonce extension in [1] responseExtensions
    let mut nonce = None;
    if idx < tbs_elems.len() && tbs_elems[idx].tag == 0xA1 {
        let (exts_seq, _) = parse_tlv(tbs_elems[idx].value)?;
        if exts_seq.tag == 0x30 {
            let exts = parse_elements(exts_seq.value)?;
            for ext in &exts {
                if ext.tag == 0x30 {
                    let ext_parts = parse_elements(ext.value)?;
                    if ext_parts.len() >= 2
                        && ext_parts[0].tag == 0x06
                        && ext_parts[0].value == &OID_OCSP_NONCE[2..]
                    {
                        // extnValue OCTET STRING wrapping OCTET STRING wrapping nonce bytes
                        if ext_parts[1].tag == 0x04 {
                            let (inner, _) = parse_tlv(ext_parts[1].value)?;
                            if inner.tag == 0x04 {
                                nonce = Some(parse_int_u64(inner.value));
                            }
                        }
                    }
                }
            }
        }
    }

    // Verify signature
    // signatureAlgorithm
    let sig_alg_elem = &basic_elems[1];
    if sig_alg_elem.tag != 0x30 {
        return Err(inv("signatureAlgorithm not SEQUENCE"));
    }
    let alg_children = parse_elements(sig_alg_elem.value)?;
    if alg_children.is_empty() || alg_children[0].tag != 0x06 {
        return Err(inv("missing algorithm OID"));
    }
    let oid_with_tag = tlv(0x06, alg_children[0].value);
    let algorithm = if oid_with_tag == OID_ED25519 {
        SigningAlgorithm::Ed25519
    } else if oid_with_tag == OID_MLDSA65 {
        SigningAlgorithm::MlDsa65
    } else if oid_with_tag == OID_RSA_SHA256 {
        SigningAlgorithm::Rsa
    } else {
        return Err(inv("unknown signature algorithm OID"));
    };

    // signature BIT STRING
    if basic_elems[2].tag != 0x03 {
        return Err(inv("signature not BIT STRING"));
    }
    let sig_value = if !basic_elems[2].value.is_empty() {
        &basic_elems[2].value[1..] // skip unused-bits byte
    } else {
        return Err(inv("empty signature"));
    };

    let sig_hex = hex::encode(sig_value);
    let verified =
        crate::signature::verify::verify_signature(algorithm, public_key_hex, &tbs_raw, &sig_hex);

    Ok(OcspDerFields {
        response_status,
        cert_status_tag: sr.cert_status_tag,
        serial_hex: sr.serial_hex,
        produced_at,
        this_update: sr.this_update,
        next_update: sr.next_update,
        nonce,
        signature_verified: verified,
    })
}

struct ParsedSingleResponse {
    serial_hex: String,
    this_update: String,
    next_update: Option<String>,
    cert_status_tag: u8,
}

fn parse_single_response(sr: &Tlv<'_>) -> Result<ParsedSingleResponse, OcspDerError> {
    let inv = |s: &str| OcspDerError::Invalid(s.into());
    if sr.tag != 0x30 {
        return Err(inv("SingleResponse not SEQUENCE"));
    }
    let elems = parse_elements(sr.value)?;
    if elems.len() < 3 {
        return Err(inv("SingleResponse too short"));
    }

    // CertID SEQUENCE
    let cert_id_elems = parse_elements(elems[0].value)?;
    if cert_id_elems.len() < 4 {
        return Err(inv("CertID too short"));
    }
    // serialNumber is the 4th element (INTEGER)
    let serial_hex = hex::encode(cert_id_elems[3].value);
    // Strip leading zero used for DER sign padding
    let serial_hex = serial_hex.trim_start_matches('0').to_string();
    let serial_hex = if serial_hex.is_empty() {
        "0".to_string()
    } else {
        serial_hex
    };

    // certStatus: [0]=good, [1]=revoked, [2]=unknown
    let cert_status_tag = elems[1].tag & 0x1F; // strip class bits

    // thisUpdate GeneralizedTime
    let this_update = if elems[2].tag == 0x18 {
        String::from_utf8_lossy(elems[2].value).to_string()
    } else {
        String::new()
    };

    // nextUpdate [0] EXPLICIT GeneralizedTime (optional)
    let next_update = if elems.len() > 3 && elems[3].tag == 0xA0 {
        let (gt, _) = parse_tlv(elems[3].value)?;
        if gt.tag == 0x18 {
            Some(String::from_utf8_lossy(gt.value).to_string())
        } else {
            None
        }
    } else {
        None
    };

    Ok(ParsedSingleResponse {
        serial_hex,
        this_update,
        next_update,
        cert_status_tag,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::SoftwareSigningProvider;
    use crate::msp::ocsp::{OcspRequest, OcspResponder};
    use crate::msp::{CrlStore, MemoryCrlStore};
    use std::sync::Arc;

    fn make_responder_and_provider() -> (OcspResponder, Arc<SoftwareSigningProvider>) {
        let signer = Arc::new(SoftwareSigningProvider::generate());
        let responder = OcspResponder::new(signer.clone(), "did:goya:ocsp-der".to_string());
        (responder, signer)
    }

    fn make_crl_store(msp_id: &str, revoked: &[&str]) -> MemoryCrlStore {
        let store = MemoryCrlStore::new();
        let serials: Vec<String> = revoked.iter().map(|s| s.to_string()).collect();
        store.write_crl(msp_id, &serials).unwrap();
        store
    }

    fn query_and_encode(revoked: &[&str], serial: &str, nonce: Option<u64>) -> (Vec<u8>, String) {
        let (responder, signer) = make_responder_and_provider();
        let store = make_crl_store("msp1", revoked);
        let req = OcspRequest {
            msp_id: "msp1".into(),
            serial: serial.to_string(),
            nonce,
        };
        let resp = responder.query(&req, &store);
        let der = encode_ocsp_response_der(&resp, signer.as_ref()).unwrap();
        let pk_hex = hex::encode(signer.public_key());
        (der, pk_hex)
    }

    #[test]
    fn der_roundtrip_good() {
        let serial = hex::encode([1u8; 8]);
        let (der, pk_hex) = query_and_encode(&[], &serial, Some(42));
        assert_eq!(der[0], 0x30, "must start with SEQUENCE");

        let fields = verify_ocsp_response_der(&der, &pk_hex).unwrap();
        assert_eq!(fields.response_status, 0);
        assert_eq!(fields.cert_status_tag, 0); // good
        assert!(fields.signature_verified);
        assert_eq!(fields.nonce, Some(42));
    }

    #[test]
    fn der_roundtrip_revoked() {
        let serial = hex::encode([2u8; 8]);
        let (der, pk_hex) = query_and_encode(&[&serial], &serial, None);
        let fields = verify_ocsp_response_der(&der, &pk_hex).unwrap();
        assert_eq!(fields.response_status, 0);
        assert_eq!(fields.cert_status_tag, 1); // revoked
        assert!(fields.signature_verified);
        assert!(fields.nonce.is_none());
    }

    #[test]
    fn der_error_response_no_body() {
        let (responder, signer) = make_responder_and_provider();
        let store = make_crl_store("msp1", &[]);
        let req = OcspRequest {
            msp_id: String::new(), // triggers malformed
            serial: String::new(),
            nonce: None,
        };
        let resp = responder.query(&req, &store);
        let der = encode_ocsp_response_der(&resp, signer.as_ref()).unwrap();
        let pk_hex = hex::encode(signer.public_key());
        let fields = verify_ocsp_response_der(&der, &pk_hex).unwrap();
        assert_eq!(fields.response_status, 1); // malformedRequest
        assert!(!fields.signature_verified);
    }

    #[test]
    fn wrong_key_fails_verification() {
        let serial = hex::encode([1u8; 8]);
        let (der, _) = query_and_encode(&[], &serial, None);
        let other = SoftwareSigningProvider::generate();
        let wrong_pk = hex::encode(other.public_key());
        let fields = verify_ocsp_response_der(&der, &wrong_pk).unwrap();
        assert!(!fields.signature_verified);
    }

    #[test]
    fn tampered_der_fails() {
        let serial = hex::encode([1u8; 8]);
        let (mut der, pk_hex) = query_and_encode(&[], &serial, None);
        let mid = der.len() / 2;
        der[mid] ^= 0xFF;
        match verify_ocsp_response_der(&der, &pk_hex) {
            Err(_) => {} // parse error — expected
            Ok(f) => assert!(!f.signature_verified, "tampered DER must not verify"),
        }
    }

    #[test]
    fn truncated_der_fails() {
        let serial = hex::encode([1u8; 8]);
        let (der, pk_hex) = query_and_encode(&[], &serial, None);
        assert!(verify_ocsp_response_der(&der[..10], &pk_hex).is_err());
    }

    #[test]
    fn nonce_roundtrip_zero() {
        let serial = hex::encode([1u8; 8]);
        let (der, pk_hex) = query_and_encode(&[], &serial, Some(0));
        let fields = verify_ocsp_response_der(&der, &pk_hex).unwrap();
        assert_eq!(fields.nonce, Some(0));
    }

    #[test]
    fn next_update_present() {
        let serial = hex::encode([1u8; 8]);
        let (der, pk_hex) = query_and_encode(&[], &serial, None);
        let fields = verify_ocsp_response_der(&der, &pk_hex).unwrap();
        assert!(fields.next_update.is_some());
    }

    #[test]
    fn mldsa65_der_roundtrip() {
        use crate::identity::signing::MlDsaSigningProvider;
        let signer = Arc::new(MlDsaSigningProvider::generate());
        let responder = OcspResponder::new(signer.clone(), "did:goya:ocsp-pqc".into());
        let store = make_crl_store("msp1", &[]);
        let req = OcspRequest {
            msp_id: "msp1".into(),
            serial: hex::encode([1u8; 8]),
            nonce: Some(99),
        };
        let resp = responder.query(&req, &store);
        let der = encode_ocsp_response_der(&resp, signer.as_ref()).unwrap();
        let pk_hex = hex::encode(signer.public_key());
        let fields = verify_ocsp_response_der(&der, &pk_hex).unwrap();
        assert!(fields.signature_verified);
        assert_eq!(fields.nonce, Some(99));
    }

    #[test]
    fn interop_x509_parser_parses_ocsp_response() {
        let serial = hex::encode([1u8; 8]);
        let (der, _) = query_and_encode(&[], &serial, None);
        let (rem, parsed) =
            x509_parser::der_parser::parse_der(&der).expect("x509-parser must parse OCSP DER");
        assert!(rem.is_empty());
        let resp_seq = parsed.as_sequence().unwrap();
        assert!(resp_seq.len() >= 2, "OCSPResponse: status + responseBytes");
        // responseStatus ENUMERATED = 0 (successful)
        let status = resp_seq[0].as_u32().unwrap();
        assert_eq!(status, 0);
    }
}
