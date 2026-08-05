//! DER-encoded CMS SignedData for CAdES-BES (ETSI TS 101 733).
//!
//! Standards-compliant CMS (RFC 5652) binary output. Zero external ASN.1 deps —
//! OIDs are pre-computed, DER is built with inline helpers.
//! The signature covers DER-encoded SignedAttributes per RFC 5652 §5.4.

use crate::crypto::hasher::{hash_with, HashAlgorithm};
use crate::identity::signing::{SigningAlgorithm, SigningError, SigningProvider};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CadesDerError {
    #[error("DER encoding: {0}")]
    Der(String),
    #[error("signing: {0}")]
    Signing(#[from] SigningError),
    #[error("invalid CMS: {0}")]
    Invalid(String),
}

// ── Pre-computed DER-encoded OIDs (tag 0x06 + length + value) ──────────────

/// id-signedData 1.2.840.113549.1.7.2
const OID_SIGNED_DATA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
];
/// id-data 1.2.840.113549.1.7.1
const OID_DATA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
];
/// id-sha256 2.16.840.1.101.3.4.2.1
const OID_SHA256: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
];
/// id-EdDSA 1.3.101.112 (Ed25519)
const OID_ED25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];
/// id-ML-DSA-65 2.16.840.1.101.3.4.3.17 (FIPS 204)
const OID_MLDSA65: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
];
/// sha256WithRSAEncryption 1.2.840.113549.1.1.11
const OID_RSA_SHA256: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
];
/// id-contentType 1.2.840.113549.1.9.3
const OID_CONTENT_TYPE: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03,
];
/// id-messageDigest 1.2.840.113549.1.9.4
const OID_MESSAGE_DIGEST: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04,
];
/// id-signingTime 1.2.840.113549.1.9.5
const OID_SIGNING_TIME: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05,
];

// ── DER encoding helpers ───────────────────────────────────────────────────

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
fn der_set(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x31, &parts.concat())
}
fn der_octet(v: &[u8]) -> Vec<u8> {
    tlv(0x04, v)
}
fn der_int(v: u8) -> Vec<u8> {
    tlv(0x02, &[v])
}
fn der_utctime(s: &str) -> Vec<u8> {
    tlv(0x17, s.as_bytes())
}

// ── DER parsing helpers ────────────────────────────────────────────────────

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    raw: &'a [u8],
}

fn parse_tlv(data: &[u8]) -> Result<(Tlv<'_>, &[u8]), CadesDerError> {
    if data.is_empty() {
        return Err(invalid("unexpected end of data"));
    }
    let tag = data[0];
    let (len, hdr) = parse_der_len(&data[1..])?;
    let total = 1 + hdr + len;
    if total > data.len() {
        return Err(invalid("truncated TLV"));
    }
    Ok((
        Tlv {
            tag,
            value: &data[1 + hdr..total],
            raw: &data[..total],
        },
        &data[total..],
    ))
}

fn parse_der_len(data: &[u8]) -> Result<(usize, usize), CadesDerError> {
    if data.is_empty() {
        return Err(invalid("missing length"));
    }
    if data[0] < 0x80 {
        return Ok((data[0] as usize, 1));
    }
    let n = (data[0] & 0x7F) as usize;
    if n == 0 || n > 3 || 1 + n > data.len() {
        return Err(invalid("bad DER length encoding"));
    }
    let mut len = 0usize;
    for &b in &data[1..1 + n] {
        len = (len << 8) | b as usize;
    }
    Ok((len, 1 + n))
}

fn parse_elements(data: &[u8]) -> Result<Vec<Tlv<'_>>, CadesDerError> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let (t, r) = parse_tlv(rest)?;
        out.push(t);
        rest = r;
    }
    Ok(out)
}

fn invalid(msg: &str) -> CadesDerError {
    CadesDerError::Invalid(msg.into())
}

fn expect_tag(got: u8, want: u8, ctx: &str) -> Result<(), CadesDerError> {
    if got != want {
        Err(invalid(&format!(
            "{ctx}: expected tag 0x{want:02X}, got 0x{got:02X}"
        )))
    } else {
        Ok(())
    }
}

// ── Build ──────────────────────────────────────────────────────────────────

/// Verified fields extracted from a CMS SignedData envelope.
#[derive(Debug, Clone)]
pub struct CadesDerFields {
    pub message_digest: Vec<u8>,
    pub signing_time: String,
    pub algorithm: SigningAlgorithm,
    pub signature: Vec<u8>,
    pub subject_key_id: Vec<u8>,
}

/// Build a DER-encoded CMS SignedData (CAdES-BES detached signature).
///
/// Returns complete ContentInfo DER bytes. The signature covers
/// DER-encoded SignedAttributes per RFC 5652 §5.4.
pub fn build_cades_bes_der(
    content: &[u8],
    provider: &dyn SigningProvider,
    signing_time: u64,
) -> Result<Vec<u8>, CadesDerError> {
    let digest = hash_with(HashAlgorithm::Sha256, content);
    let pk = provider.public_key();
    let pk_hash = hash_with(HashAlgorithm::Sha256, &pk);
    let ski = &pk_hash[..20];

    let sha256_aid = der_seq(&[OID_SHA256]);
    let sig_oid = signing_oid(provider.algorithm());
    let sig_aid = der_seq(&[sig_oid]);

    // Signed attributes (each is an Attribute SEQUENCE)
    let attr_ct = der_seq(&[OID_CONTENT_TYPE, &der_set(&[OID_DATA])]);
    let attr_md = der_seq(&[OID_MESSAGE_DIGEST, &der_set(&[&der_octet(&digest)])]);
    let utc = format_utc_time(signing_time);
    let attr_st = der_seq(&[OID_SIGNING_TIME, &der_set(&[&der_utctime(&utc)])]);

    // DER SET OF: sort by encoding for canonical form
    let mut attrs = vec![attr_ct, attr_md, attr_st];
    attrs.sort();
    let attrs_inner: Vec<u8> = attrs.into_iter().flatten().collect();

    // Sign over SET-tagged attributes (RFC 5652 §5.4)
    let attrs_for_signing = tlv(0x31, &attrs_inner);
    let signature = provider
        .sign(&attrs_for_signing)
        .map_err(CadesDerError::Signing)?;

    // SignerInfo SEQUENCE
    let signer_info = der_seq(&[
        &der_int(3),
        &tlv(0x80, ski),          // sid: SubjectKeyIdentifier [0] IMPLICIT
        &sha256_aid,              // digestAlgorithm
        &tlv(0xA0, &attrs_inner), // signedAttrs [0] IMPLICIT CONSTRUCTED
        &sig_aid,                 // signatureAlgorithm
        &der_octet(&signature),   // signature
    ]);

    // SignedData SEQUENCE
    let signed_data = der_seq(&[
        &der_int(3),
        &der_set(&[&sha256_aid]),  // digestAlgorithms
        &der_seq(&[OID_DATA]),     // encapContentInfo (detached — no eContent)
        &der_set(&[&signer_info]), // signerInfos
    ]);

    // ContentInfo SEQUENCE
    Ok(der_seq(&[OID_SIGNED_DATA, &tlv(0xA0, &signed_data)]))
}

fn signing_oid(alg: SigningAlgorithm) -> &'static [u8] {
    match alg {
        SigningAlgorithm::Ed25519 => OID_ED25519,
        SigningAlgorithm::MlDsa65 => OID_MLDSA65,
        SigningAlgorithm::Rsa => OID_RSA_SHA256,
    }
}

fn format_utc_time(unix: u64) -> String {
    use chrono::TimeZone;
    chrono::Utc
        .timestamp_opt(unix as i64, 0)
        .single()
        .map(|dt| dt.format("%y%m%d%H%M%SZ").to_string())
        .unwrap_or_else(|| "700101000000Z".to_string())
}

// ── Verify ─────────────────────────────────────────────────────────────────

/// Verify a DER-encoded CMS SignedData against content.
///
/// Checks message-digest matches SHA-256 of content, then verifies
/// the cryptographic signature over the DER-encoded SignedAttributes.
pub fn verify_cades_bes_der(
    der_bytes: &[u8],
    content: &[u8],
    public_key_hex: &str,
) -> Result<CadesDerFields, CadesDerError> {
    // ContentInfo SEQUENCE
    let (ci, _) = parse_tlv(der_bytes)?;
    expect_tag(ci.tag, 0x30, "ContentInfo")?;
    let ci_elems = parse_elements(ci.value)?;
    if ci_elems.len() < 2 {
        return Err(invalid("ContentInfo: need >= 2 elements"));
    }
    if ci_elems[0].raw != OID_SIGNED_DATA {
        return Err(invalid("not id-signedData"));
    }

    // [0] EXPLICIT → SignedData SEQUENCE
    expect_tag(ci_elems[1].tag, 0xA0, "content [0]")?;
    let (sd, _) = parse_tlv(ci_elems[1].value)?;
    expect_tag(sd.tag, 0x30, "SignedData")?;
    let sd_elems = parse_elements(sd.value)?;

    // signerInfos is the last SET in SignedData
    let si_set = sd_elems
        .iter()
        .rev()
        .find(|e| e.tag == 0x31)
        .ok_or_else(|| invalid("no signerInfos SET"))?;

    // First SignerInfo SEQUENCE
    let (si, _) = parse_tlv(si_set.value)?;
    expect_tag(si.tag, 0x30, "SignerInfo")?;
    let si_elems = parse_elements(si.value)?;

    // Walk SignerInfo fields by tag to handle optional signedAttrs
    let mut idx = 0;
    // version (INTEGER)
    if idx >= si_elems.len() {
        return Err(invalid("SignerInfo: missing version"));
    }
    idx += 1;

    // sid
    if idx >= si_elems.len() {
        return Err(invalid("SignerInfo: missing sid"));
    }
    let ski = if si_elems[idx].tag == 0x80 {
        si_elems[idx].value.to_vec()
    } else {
        vec![]
    };
    idx += 1;

    // digestAlgorithm (SEQUENCE)
    if idx >= si_elems.len() {
        return Err(invalid("SignerInfo: missing digestAlgorithm"));
    }
    idx += 1;

    // signedAttrs [0] IMPLICIT CONSTRUCTED (optional in CMS, required for CAdES-BES)
    if idx >= si_elems.len() {
        return Err(invalid("SignerInfo: truncated"));
    }
    let attrs_value = if si_elems[idx].tag == 0xA0 {
        let v = si_elems[idx].value;
        idx += 1;
        v
    } else {
        return Err(invalid("CAdES-BES requires signedAttrs"));
    };

    // signatureAlgorithm (SEQUENCE)
    if idx >= si_elems.len() {
        return Err(invalid("SignerInfo: missing signatureAlgorithm"));
    }
    let alg_elem = &si_elems[idx];
    expect_tag(alg_elem.tag, 0x30, "signatureAlgorithm")?;
    let alg_children = parse_elements(alg_elem.value)?;
    let algorithm = if alg_children.is_empty() {
        return Err(invalid("empty signatureAlgorithm"));
    } else {
        match alg_children[0].raw {
            r if r == OID_ED25519 => SigningAlgorithm::Ed25519,
            r if r == OID_MLDSA65 => SigningAlgorithm::MlDsa65,
            r if r == OID_RSA_SHA256 => SigningAlgorithm::Rsa,
            _ => return Err(invalid("unknown signature algorithm OID")),
        }
    };
    idx += 1;

    // signature (OCTET STRING)
    if idx >= si_elems.len() {
        return Err(invalid("SignerInfo: missing signature"));
    }
    expect_tag(si_elems[idx].tag, 0x04, "signature")?;
    let signature = si_elems[idx].value.to_vec();

    // Extract message-digest and signing-time from signed attributes
    let attr_elements = parse_elements(attrs_value)?;
    let (message_digest, signing_time) = extract_attrs(&attr_elements)?;

    // Verify message digest matches content
    let computed = hash_with(HashAlgorithm::Sha256, content);
    if message_digest[..] != computed[..] {
        return Err(invalid("message-digest does not match content hash"));
    }

    // Re-tag as SET for signature verification (RFC 5652 §5.4)
    let attrs_for_verify = tlv(0x31, attrs_value);
    let sig_hex = hex::encode(&signature);
    if !crate::signature::verify::verify_signature(
        algorithm,
        public_key_hex,
        &attrs_for_verify,
        &sig_hex,
    ) {
        return Err(invalid("cryptographic signature verification failed"));
    }

    Ok(CadesDerFields {
        message_digest,
        signing_time,
        algorithm,
        signature,
        subject_key_id: ski,
    })
}

fn extract_attrs(attrs: &[Tlv<'_>]) -> Result<(Vec<u8>, String), CadesDerError> {
    let mut digest = Vec::new();
    let mut time = String::new();
    for attr in attrs {
        if attr.tag != 0x30 {
            continue;
        }
        let parts = parse_elements(attr.value)?;
        if parts.len() < 2 {
            continue;
        }
        if parts[0].raw == OID_MESSAGE_DIGEST && parts[1].tag == 0x31 {
            let vals = parse_elements(parts[1].value)?;
            if !vals.is_empty() && vals[0].tag == 0x04 {
                digest = vals[0].value.to_vec();
            }
        } else if parts[0].raw == OID_SIGNING_TIME && parts[1].tag == 0x31 {
            let vals = parse_elements(parts[1].value)?;
            if !vals.is_empty() && vals[0].tag == 0x17 {
                time = String::from_utf8_lossy(vals[0].value).into();
            }
        }
    }
    if digest.is_empty() {
        return Err(invalid("missing message-digest attribute"));
    }
    Ok((digest, time))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::{MlDsaSigningProvider, SoftwareSigningProvider};

    #[test]
    fn build_and_verify_ed25519() {
        let provider = SoftwareSigningProvider::generate();
        let content = b"CAdES-BES test document";
        let der = build_cades_bes_der(content, &provider, 1_700_000_000).unwrap();
        assert_eq!(der[0], 0x30, "ContentInfo must start with SEQUENCE");

        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_cades_bes_der(&der, content, &pk_hex).unwrap();
        assert_eq!(fields.algorithm, SigningAlgorithm::Ed25519);
        assert_eq!(
            fields.message_digest[..],
            hash_with(HashAlgorithm::Sha256, content)[..]
        );
        assert!(fields.signing_time.contains("231114"));
    }

    #[test]
    fn build_and_verify_mldsa65() {
        let provider = MlDsaSigningProvider::generate();
        let content = b"PQC CAdES-BES document";
        let der = build_cades_bes_der(content, &provider, 1_700_000_000).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_cades_bes_der(&der, content, &pk_hex).unwrap();
        assert_eq!(fields.algorithm, SigningAlgorithm::MlDsa65);
    }

    #[test]
    fn wrong_content_fails() {
        let provider = SoftwareSigningProvider::generate();
        let der = build_cades_bes_der(b"original", &provider, 1_700_000_000).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        assert!(verify_cades_bes_der(&der, b"tampered", &pk_hex).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let signer = SoftwareSigningProvider::generate();
        let other = SoftwareSigningProvider::generate();
        let content = b"signed by signer";
        let der = build_cades_bes_der(content, &signer, 1_700_000_000).unwrap();
        let wrong_pk = hex::encode(other.public_key());
        assert!(verify_cades_bes_der(&der, content, &wrong_pk).is_err());
    }

    #[test]
    fn deterministic_output() {
        let provider = SoftwareSigningProvider::generate();
        let content = b"deterministic test";
        let d1 = build_cades_bes_der(content, &provider, 1_700_000_000).unwrap();
        let d2 = build_cades_bes_der(content, &provider, 1_700_000_000).unwrap();
        assert_eq!(d1, d2);
    }

    #[test]
    fn content_info_contains_signed_data_oid() {
        let provider = SoftwareSigningProvider::generate();
        let der = build_cades_bes_der(b"test", &provider, 1_700_000_000).unwrap();
        let (ci, _) = parse_tlv(&der).unwrap();
        let elems = parse_elements(ci.value).unwrap();
        assert_eq!(elems[0].raw, OID_SIGNED_DATA);
    }

    #[test]
    fn empty_content_works() {
        let provider = SoftwareSigningProvider::generate();
        let der = build_cades_bes_der(b"", &provider, 1_700_000_000).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        assert!(verify_cades_bes_der(&der, b"", &pk_hex).is_ok());
    }

    #[test]
    fn truncated_der_fails() {
        let provider = SoftwareSigningProvider::generate();
        let der = build_cades_bes_der(b"test", &provider, 1_700_000_000).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        assert!(verify_cades_bes_der(&der[..10], b"test", &pk_hex).is_err());
    }

    #[test]
    fn subject_key_id_is_20_bytes() {
        let provider = SoftwareSigningProvider::generate();
        let der = build_cades_bes_der(b"ski test", &provider, 1_700_000_000).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_cades_bes_der(&der, b"ski test", &pk_hex).unwrap();
        assert_eq!(fields.subject_key_id.len(), 20);
    }

    #[test]
    fn different_signing_times() {
        let provider = SoftwareSigningProvider::generate();
        let content = b"time test";
        let d1 = build_cades_bes_der(content, &provider, 1_700_000_000).unwrap();
        let d2 = build_cades_bes_der(content, &provider, 1_800_000_000).unwrap();
        assert_ne!(d1, d2);
    }

    #[test]
    fn build_and_verify_rsa() {
        use crate::identity::signing::RsaSigningProvider;
        let provider = RsaSigningProvider::generate();
        let content = b"RSA CAdES-BES document";
        let der = build_cades_bes_der(content, &provider, 1_700_000_000).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_cades_bes_der(&der, content, &pk_hex).unwrap();
        assert_eq!(fields.algorithm, SigningAlgorithm::Rsa);
    }

    #[test]
    fn corrupted_signature_fails() {
        let provider = SoftwareSigningProvider::generate();
        let content = b"corruption test";
        let mut der = build_cades_bes_der(content, &provider, 1_700_000_000).unwrap();
        // Flip a byte near the end (inside the signature)
        let last = der.len() - 5;
        der[last] ^= 0xFF;
        let pk_hex = hex::encode(provider.public_key());
        assert!(verify_cades_bes_der(&der, content, &pk_hex).is_err());
    }
}
