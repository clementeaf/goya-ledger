//! DER-encoded RFC 3161 TimeStampResp / TSTInfo.
//!
//! Produces binary TimeStampResp per RFC 3161 §2.4.2, wrapping a
//! CMS SignedData ContentInfo that encapsulates a DER-encoded TSTInfo.
//! Zero external ASN.1 deps — inline DER helpers matching cades_der.rs.

use crate::crypto::hasher::{hash_with, HashAlgorithm};
use crate::identity::signing::{SigningAlgorithm, SigningProvider};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Rfc3161Error {
    #[error("DER encoding: {0}")]
    Der(String),
    #[error("signing: {0}")]
    Signing(#[from] crate::identity::signing::SigningError),
    #[error("invalid: {0}")]
    Invalid(String),
}

// ── Pre-computed OIDs ─────────────────────────────────────────────────────

/// id-signedData 1.2.840.113549.1.7.2
const OID_SIGNED_DATA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
];
/// id-ct-TSTInfo 1.2.840.113549.1.9.16.1.4
const OID_TST_INFO: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
];
/// id-sha256 2.16.840.1.101.3.4.2.1
const OID_SHA256: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
];
/// id-sha3-256 2.16.840.1.101.3.4.2.8
const OID_SHA3_256: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
];
/// id-EdDSA 1.3.101.112 (Ed25519)
const OID_ED25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];
/// id-ML-DSA-65 2.16.840.1.101.3.4.3.17
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

// ── DER helpers (same as cades_der.rs) ────────────────────────────────────

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
fn der_int_big(v: u64) -> Vec<u8> {
    // Minimal big-endian encoding with leading 0 if high bit set
    if v == 0 {
        return tlv(0x02, &[0]);
    }
    let bytes = v.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    let mut val: Vec<u8> = bytes[start..].to_vec();
    if val[0] & 0x80 != 0 {
        val.insert(0, 0);
    }
    tlv(0x02, &val)
}
fn der_bool(v: bool) -> Vec<u8> {
    tlv(0x01, &[if v { 0xFF } else { 0x00 }])
}
fn der_utctime(s: &str) -> Vec<u8> {
    tlv(0x17, s.as_bytes())
}
fn der_gentime(s: &str) -> Vec<u8> {
    tlv(0x18, s.as_bytes())
}
fn der_utf8(s: &str) -> Vec<u8> {
    tlv(0x0C, s.as_bytes())
}

/// DER-encode an OID from dotted string (e.g. "1.3.6.1.4.1.99999.1.1").
fn der_oid_from_str(oid: &str) -> Vec<u8> {
    let arcs: Vec<u64> = oid.split('.').filter_map(|s| s.parse().ok()).collect();
    if arcs.len() < 2 {
        return tlv(0x06, &[]);
    }
    let mut value = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        if arc < 128 {
            value.push(arc as u8);
        } else {
            let mut tmp = Vec::new();
            let mut a = arc;
            tmp.push((a & 0x7F) as u8);
            a >>= 7;
            while a > 0 {
                tmp.push((a & 0x7F) as u8 | 0x80);
                a >>= 7;
            }
            tmp.reverse();
            value.extend(tmp);
        }
    }
    tlv(0x06, &value)
}

// ── DER parsing helpers ───────────────────────────────────────────────────

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    #[allow(dead_code)]
    raw: &'a [u8],
}

fn parse_tlv(data: &[u8]) -> Result<(Tlv<'_>, &[u8]), Rfc3161Error> {
    if data.is_empty() {
        return Err(Rfc3161Error::Invalid("unexpected end".into()));
    }
    let tag = data[0];
    let (len, hdr) = parse_der_len(&data[1..])?;
    let total = 1 + hdr + len;
    if total > data.len() {
        return Err(Rfc3161Error::Invalid("truncated TLV".into()));
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

fn parse_der_len(data: &[u8]) -> Result<(usize, usize), Rfc3161Error> {
    if data.is_empty() {
        return Err(Rfc3161Error::Invalid("missing length".into()));
    }
    if data[0] < 0x80 {
        return Ok((data[0] as usize, 1));
    }
    let n = (data[0] & 0x7F) as usize;
    if n == 0 || n > 3 || 1 + n > data.len() {
        return Err(Rfc3161Error::Invalid("bad DER length".into()));
    }
    let mut len = 0usize;
    for &b in &data[1..1 + n] {
        len = (len << 8) | b as usize;
    }
    Ok((len, 1 + n))
}

fn parse_elements(data: &[u8]) -> Result<Vec<Tlv<'_>>, Rfc3161Error> {
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

// ── Build TSTInfo ─────────────────────────────────────────────────────────

/// Parameters for building a DER TimeStampResp.
pub struct TstInfoParams<'a> {
    pub policy_oid: &'a str,
    pub hash_algorithm: HashAlgorithm,
    pub message_imprint: &'a [u8],
    pub serial_number: u64,
    pub gen_time: u64,
    pub accuracy_secs: u32,
    pub ordering: bool,
    pub nonce: Option<u64>,
    pub tsa_name: &'a str,
}

/// Verified fields extracted from a DER TSTInfo.
#[derive(Debug, Clone)]
pub struct TstInfoFields {
    pub serial_number: u64,
    pub gen_time_raw: String,
    pub message_imprint: Vec<u8>,
    pub policy_oid_raw: Vec<u8>,
    pub nonce: Option<u64>,
    pub ordering: bool,
}

/// Build DER-encoded TSTInfo per RFC 3161 §2.4.2.
fn build_tst_info_der(p: &TstInfoParams<'_>) -> Vec<u8> {
    let hash_oid = hash_algorithm_oid(p.hash_algorithm);
    let hash_aid = der_seq(&[hash_oid]);

    // MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage OCTET STRING }
    let msg_imprint = der_seq(&[&hash_aid, &der_octet(p.message_imprint)]);

    let policy = der_oid_from_str(p.policy_oid);

    let serial = der_int_big(p.serial_number);

    let gen_time = format_gen_time(p.gen_time);
    let gen_time_der = der_gentime(&gen_time);

    // Accuracy ::= SEQUENCE { seconds [0] INTEGER OPTIONAL, ... }
    // Simplified: just seconds
    let accuracy = der_seq(&[&der_int_big(p.accuracy_secs as u64)]);

    let ordering = der_bool(p.ordering);

    let mut parts: Vec<Vec<u8>> = vec![
        tlv(0x02, &[1]), // version INTEGER 1
        policy,
        msg_imprint,
        serial,
        gen_time_der,
        accuracy,
        ordering,
    ];

    if let Some(n) = p.nonce {
        parts.push(der_int_big(n));
    }

    // tsa [0] GeneralName — directoryName with UTF8String
    let tsa_name = tlv(
        0xA0,
        &tlv(
            0xA4,
            &der_seq(&[&der_set(&[&der_seq(&[
                // id-at-commonName 2.5.4.3
                &der_oid_from_str("2.5.4.3"),
                &der_utf8(p.tsa_name),
            ])])]),
        ),
    );
    parts.push(tsa_name);

    let refs: Vec<&[u8]> = parts.iter().map(|v| v.as_slice()).collect();
    der_seq(&refs)
}

/// Build a complete DER TimeStampResp: PKIStatusInfo + CMS SignedData wrapping TSTInfo.
pub fn build_timestamp_resp_der(
    params: &TstInfoParams<'_>,
    provider: &dyn SigningProvider,
) -> Result<Vec<u8>, Rfc3161Error> {
    let tst_info_der = build_tst_info_der(params);

    // Wrap in CMS SignedData
    let digest = hash_with(HashAlgorithm::Sha256, &tst_info_der);
    let pk = provider.public_key();
    let pk_hash = hash_with(HashAlgorithm::Sha256, &pk);
    let ski = &pk_hash[..20];

    let sha256_aid = der_seq(&[OID_SHA256]);
    let sig_oid = signing_oid(provider.algorithm());
    let sig_aid = der_seq(&[sig_oid]);

    // SignedAttributes
    let attr_ct = der_seq(&[OID_CONTENT_TYPE, &der_set(&[OID_TST_INFO])]);
    let attr_md = der_seq(&[OID_MESSAGE_DIGEST, &der_set(&[&der_octet(&digest)])]);
    let utc = format_utc_time(params.gen_time);
    let attr_st = der_seq(&[OID_SIGNING_TIME, &der_set(&[&der_utctime(&utc)])]);

    let mut attrs = vec![attr_ct, attr_md, attr_st];
    attrs.sort();
    let attrs_inner: Vec<u8> = attrs.into_iter().flatten().collect();

    // Sign SET-tagged attrs (RFC 5652 §5.4)
    let attrs_for_signing = tlv(0x31, &attrs_inner);
    let signature = provider.sign(&attrs_for_signing)?;

    let signer_info = der_seq(&[
        &tlv(0x02, &[3]),         // version 3
        &tlv(0x80, ski),          // sid: SubjectKeyIdentifier
        &sha256_aid,              // digestAlgorithm
        &tlv(0xA0, &attrs_inner), // signedAttrs
        &sig_aid,                 // signatureAlgorithm
        &der_octet(&signature),   // signature
    ]);

    // encapContentInfo: id-ct-TSTInfo + [0] EXPLICIT OCTET STRING
    let encap = der_seq(&[OID_TST_INFO, &tlv(0xA0, &der_octet(&tst_info_der))]);

    let signed_data = der_seq(&[
        &tlv(0x02, &[3]),          // version 3
        &der_set(&[&sha256_aid]),  // digestAlgorithms
        &encap,                    // encapContentInfo
        &der_set(&[&signer_info]), // signerInfos
    ]);

    let content_info = der_seq(&[OID_SIGNED_DATA, &tlv(0xA0, &signed_data)]);

    // TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo }
    // PKIStatusInfo ::= SEQUENCE { status PKIStatus(0=granted) }
    let status_info = der_seq(&[&tlv(0x02, &[0])]);

    Ok(der_seq(&[&status_info, &content_info]))
}

/// Verify a DER TimeStampResp and extract TSTInfo fields.
pub fn verify_timestamp_resp_der(
    der_bytes: &[u8],
    public_key_hex: &str,
) -> Result<TstInfoFields, Rfc3161Error> {
    let inv = |s: &str| Rfc3161Error::Invalid(s.into());

    // TimeStampResp SEQUENCE
    let (resp, _) = parse_tlv(der_bytes)?;
    if resp.tag != 0x30 {
        return Err(inv("not a SEQUENCE"));
    }
    let resp_elems = parse_elements(resp.value)?;
    if resp_elems.len() < 2 {
        return Err(inv("TimeStampResp needs status + token"));
    }

    // PKIStatusInfo — check status == 0
    let status_seq = &resp_elems[0];
    if status_seq.tag != 0x30 {
        return Err(inv("PKIStatusInfo not SEQUENCE"));
    }
    let status_elems = parse_elements(status_seq.value)?;
    if status_elems.is_empty() || status_elems[0].tag != 0x02 {
        return Err(inv("missing PKIStatus INTEGER"));
    }
    let status_val = parse_int_u64(status_elems[0].value);
    if status_val != 0 {
        return Err(inv(&format!("PKIStatus {status_val} (not granted)")));
    }

    // ContentInfo (CMS SignedData)
    let ci = &resp_elems[1];
    if ci.tag != 0x30 {
        return Err(inv("ContentInfo not SEQUENCE"));
    }
    let ci_elems = parse_elements(ci.value)?;
    if ci_elems.len() < 2 || ci_elems[0].raw != OID_SIGNED_DATA {
        return Err(inv("not id-signedData"));
    }
    if ci_elems[1].tag != 0xA0 {
        return Err(inv("missing [0] EXPLICIT"));
    }

    let (sd, _) = parse_tlv(ci_elems[1].value)?;
    if sd.tag != 0x30 {
        return Err(inv("SignedData not SEQUENCE"));
    }
    let sd_elems = parse_elements(sd.value)?;

    // Find encapContentInfo to extract TSTInfo
    let encap = sd_elems
        .iter()
        .find(|e| e.tag == 0x30 && e.value.len() > 2 && e.value.starts_with(&OID_TST_INFO[..2]))
        .ok_or_else(|| inv("no encapContentInfo"))?;
    let encap_elems = parse_elements(encap.value)?;
    if encap_elems.len() < 2 {
        return Err(inv("encapContentInfo too short"));
    }
    // [0] EXPLICIT OCTET STRING containing TSTInfo
    if encap_elems[1].tag != 0xA0 {
        return Err(inv("encap [0] missing"));
    }
    let (octet_tlv, _) = parse_tlv(encap_elems[1].value)?;
    if octet_tlv.tag != 0x04 {
        return Err(inv("eContent not OCTET STRING"));
    }
    let tst_info_der = octet_tlv.value;

    // Parse TSTInfo fields
    let tst_fields = parse_tst_info(tst_info_der)?;

    // Verify content digest
    let computed_digest = hash_with(HashAlgorithm::Sha256, tst_info_der);

    // Find signerInfos SET (last SET in SignedData)
    let si_set = sd_elems
        .iter()
        .rev()
        .find(|e| e.tag == 0x31)
        .ok_or_else(|| inv("no signerInfos SET"))?;
    let (si, _) = parse_tlv(si_set.value)?;
    if si.tag != 0x30 {
        return Err(inv("SignerInfo not SEQUENCE"));
    }
    let si_elems = parse_elements(si.value)?;

    // Walk SignerInfo: version, sid, digestAlg, signedAttrs, sigAlg, signature
    let mut idx = 0;
    if idx >= si_elems.len() {
        return Err(inv("SI: missing version"));
    }
    idx += 1; // version
    if idx >= si_elems.len() {
        return Err(inv("SI: missing sid"));
    }
    idx += 1; // sid
    if idx >= si_elems.len() {
        return Err(inv("SI: missing digestAlg"));
    }
    idx += 1; // digestAlgorithm

    if idx >= si_elems.len() {
        return Err(inv("SI: truncated"));
    }
    let attrs_value = if si_elems[idx].tag == 0xA0 {
        let v = si_elems[idx].value;
        idx += 1;
        v
    } else {
        return Err(inv("missing signedAttrs"));
    };

    // Extract and verify message-digest from attrs
    let attr_elements = parse_elements(attrs_value)?;
    let mut found_digest = Vec::new();
    for attr in &attr_elements {
        if attr.tag != 0x30 {
            continue;
        }
        let parts = parse_elements(attr.value)?;
        if parts.len() >= 2 && parts[0].raw == OID_MESSAGE_DIGEST && parts[1].tag == 0x31 {
            let vals = parse_elements(parts[1].value)?;
            if !vals.is_empty() && vals[0].tag == 0x04 {
                found_digest = vals[0].value.to_vec();
            }
        }
    }
    if found_digest.is_empty() {
        return Err(inv("missing message-digest attr"));
    }
    if found_digest[..] != computed_digest[..] {
        return Err(inv("message-digest mismatch"));
    }

    // signatureAlgorithm
    if idx >= si_elems.len() {
        return Err(inv("SI: missing sigAlg"));
    }
    let alg_elem = &si_elems[idx];
    if alg_elem.tag != 0x30 {
        return Err(inv("sigAlg not SEQUENCE"));
    }
    let alg_children = parse_elements(alg_elem.value)?;
    let algorithm = if alg_children.is_empty() {
        return Err(inv("empty sigAlg"));
    } else {
        match alg_children[0].raw {
            r if r == OID_ED25519 => SigningAlgorithm::Ed25519,
            r if r == OID_MLDSA65 => SigningAlgorithm::MlDsa65,
            r if r == OID_RSA_SHA256 => SigningAlgorithm::Rsa,
            _ => return Err(inv("unknown sig algorithm OID")),
        }
    };
    idx += 1;

    // signature OCTET STRING
    if idx >= si_elems.len() {
        return Err(inv("SI: missing signature"));
    }
    if si_elems[idx].tag != 0x04 {
        return Err(inv("signature not OCTET STRING"));
    }
    let signature = si_elems[idx].value;

    // Verify cryptographic signature over SET-tagged attrs
    let attrs_for_verify = tlv(0x31, attrs_value);
    let sig_hex = hex::encode(signature);
    if !crate::signature::verify::verify_signature(
        algorithm,
        public_key_hex,
        &attrs_for_verify,
        &sig_hex,
    ) {
        return Err(inv("signature verification failed"));
    }

    Ok(tst_fields)
}

fn parse_tst_info(data: &[u8]) -> Result<TstInfoFields, Rfc3161Error> {
    let inv = |s: &str| Rfc3161Error::Invalid(s.into());
    let (tst, _) = parse_tlv(data)?;
    if tst.tag != 0x30 {
        return Err(inv("TSTInfo not SEQUENCE"));
    }
    let elems = parse_elements(tst.value)?;
    // version(0), policy(1), messageImprint(2), serialNumber(3), genTime(4), ...
    if elems.len() < 5 {
        return Err(inv("TSTInfo too short"));
    }

    // policy OID raw bytes
    let policy_raw = if elems[1].tag == 0x06 {
        elems[1].value.to_vec()
    } else {
        vec![]
    };

    // messageImprint SEQUENCE { algId, OCTET STRING }
    let mi_elems = parse_elements(elems[2].value)?;
    let imprint = if mi_elems.len() >= 2 && mi_elems[1].tag == 0x04 {
        mi_elems[1].value.to_vec()
    } else {
        return Err(inv("bad MessageImprint"));
    };

    let serial = parse_int_u64(elems[3].value);

    let gen_time_raw = if elems[4].tag == 0x18 {
        String::from_utf8_lossy(elems[4].value).into()
    } else {
        String::new()
    };

    // Look for nonce and ordering in remaining elements
    let mut nonce = None;
    let mut ordering = false;
    for e in &elems[5..] {
        match e.tag {
            0x01 => ordering = !e.value.is_empty() && e.value[0] != 0,
            0x02 => nonce = Some(parse_int_u64(e.value)),
            _ => {}
        }
    }

    Ok(TstInfoFields {
        serial_number: serial,
        gen_time_raw,
        message_imprint: imprint,
        policy_oid_raw: policy_raw,
        nonce,
        ordering,
    })
}

fn hash_algorithm_oid(alg: HashAlgorithm) -> &'static [u8] {
    match alg {
        HashAlgorithm::Sha256 => OID_SHA256,
        HashAlgorithm::Sha3_256 => OID_SHA3_256,
    }
}

fn signing_oid(alg: SigningAlgorithm) -> &'static [u8] {
    match alg {
        SigningAlgorithm::Ed25519 => OID_ED25519,
        SigningAlgorithm::MlDsa65 => OID_MLDSA65,
        SigningAlgorithm::Rsa => OID_RSA_SHA256,
    }
}

fn format_gen_time(unix: u64) -> String {
    use chrono::TimeZone;
    chrono::Utc
        .timestamp_opt(unix as i64, 0)
        .single()
        .map(|dt| dt.format("%Y%m%d%H%M%SZ").to_string())
        .unwrap_or_else(|| "19700101000000Z".to_string())
}

fn format_utc_time(unix: u64) -> String {
    use chrono::TimeZone;
    chrono::Utc
        .timestamp_opt(unix as i64, 0)
        .single()
        .map(|dt| dt.format("%y%m%d%H%M%SZ").to_string())
        .unwrap_or_else(|| "700101000000Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::SoftwareSigningProvider;

    fn test_imprint() -> Vec<u8> {
        hash_with(HashAlgorithm::Sha256, b"test data").to_vec()
    }

    fn test_params(imprint: &[u8]) -> TstInfoParams<'_> {
        TstInfoParams {
            policy_oid: "1.3.6.1.4.1.99999.1.1",
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: imprint,
            serial_number: 1,
            gen_time: 1_700_000_000,
            accuracy_secs: 1,
            ordering: false,
            nonce: Some(42),
            tsa_name: "did:goya:tsa-test",
        }
    }

    #[test]
    fn build_and_verify_roundtrip() {
        let provider = SoftwareSigningProvider::generate();
        let imprint = test_imprint();
        let params = test_params(&imprint);
        let der = build_timestamp_resp_der(&params, &provider).unwrap();
        assert_eq!(der[0], 0x30, "must start with SEQUENCE");

        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_timestamp_resp_der(&der, &pk_hex).unwrap();
        assert_eq!(fields.serial_number, 1);
        assert_eq!(fields.message_imprint, imprint);
        assert_eq!(fields.nonce, Some(42));
        assert!(!fields.ordering);
        assert!(fields.gen_time_raw.contains("20231114"));
    }

    #[test]
    fn nonce_none_roundtrip() {
        let provider = SoftwareSigningProvider::generate();
        let imprint = test_imprint();
        let mut params = test_params(&imprint);
        params.nonce = None;
        let der = build_timestamp_resp_der(&params, &provider).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_timestamp_resp_der(&der, &pk_hex).unwrap();
        assert_eq!(fields.nonce, None);
    }

    #[test]
    fn ordering_true() {
        let provider = SoftwareSigningProvider::generate();
        let imprint = test_imprint();
        let mut params = test_params(&imprint);
        params.ordering = true;
        let der = build_timestamp_resp_der(&params, &provider).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_timestamp_resp_der(&der, &pk_hex).unwrap();
        assert!(fields.ordering);
    }

    #[test]
    fn wrong_key_fails() {
        let signer = SoftwareSigningProvider::generate();
        let other = SoftwareSigningProvider::generate();
        let imprint = test_imprint();
        let der = build_timestamp_resp_der(&test_params(&imprint), &signer).unwrap();
        let wrong_pk = hex::encode(other.public_key());
        assert!(verify_timestamp_resp_der(&der, &wrong_pk).is_err());
    }

    #[test]
    fn tampered_der_fails() {
        let provider = SoftwareSigningProvider::generate();
        let imprint = test_imprint();
        let mut der = build_timestamp_resp_der(&test_params(&imprint), &provider).unwrap();
        let last = der.len() - 5;
        der[last] ^= 0xFF;
        let pk_hex = hex::encode(provider.public_key());
        assert!(verify_timestamp_resp_der(&der, &pk_hex).is_err());
    }

    #[test]
    fn truncated_der_fails() {
        let provider = SoftwareSigningProvider::generate();
        let imprint = test_imprint();
        let der = build_timestamp_resp_der(&test_params(&imprint), &provider).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        assert!(verify_timestamp_resp_der(&der[..10], &pk_hex).is_err());
    }

    #[test]
    fn deterministic_output() {
        let provider = SoftwareSigningProvider::generate();
        let imprint = test_imprint();
        let d1 = build_timestamp_resp_der(&test_params(&imprint), &provider).unwrap();
        let d2 = build_timestamp_resp_der(&test_params(&imprint), &provider).unwrap();
        assert_eq!(d1, d2);
    }

    #[test]
    fn different_serials_produce_different_output() {
        let provider = SoftwareSigningProvider::generate();
        let imprint = test_imprint();
        let mut p1 = test_params(&imprint);
        let mut p2 = test_params(&imprint);
        p1.serial_number = 1;
        p2.serial_number = 2;
        let d1 = build_timestamp_resp_der(&p1, &provider).unwrap();
        let d2 = build_timestamp_resp_der(&p2, &provider).unwrap();
        assert_ne!(d1, d2);
    }

    #[test]
    fn mldsa65_roundtrip() {
        use crate::identity::signing::MlDsaSigningProvider;
        let provider = MlDsaSigningProvider::generate();
        let imprint = test_imprint();
        let der = build_timestamp_resp_der(&test_params(&imprint), &provider).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_timestamp_resp_der(&der, &pk_hex).unwrap();
        assert_eq!(fields.serial_number, 1);
    }

    #[test]
    fn rsa_roundtrip() {
        use crate::identity::signing::RsaSigningProvider;
        let provider = RsaSigningProvider::generate();
        let imprint = test_imprint();
        let der = build_timestamp_resp_der(&test_params(&imprint), &provider).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_timestamp_resp_der(&der, &pk_hex).unwrap();
        assert_eq!(fields.serial_number, 1);
    }

    #[test]
    fn sha3_hash_algorithm() {
        let provider = SoftwareSigningProvider::generate();
        let imprint = hash_with(HashAlgorithm::Sha3_256, b"sha3 data").to_vec();
        let mut params = test_params(&imprint);
        params.hash_algorithm = HashAlgorithm::Sha3_256;
        let der = build_timestamp_resp_der(&params, &provider).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_timestamp_resp_der(&der, &pk_hex).unwrap();
        assert_eq!(fields.message_imprint, imprint);
    }

    #[test]
    fn large_serial_number() {
        let provider = SoftwareSigningProvider::generate();
        let imprint = test_imprint();
        let mut params = test_params(&imprint);
        params.serial_number = u64::MAX;
        let der = build_timestamp_resp_der(&params, &provider).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_timestamp_resp_der(&der, &pk_hex).unwrap();
        assert_eq!(fields.serial_number, u64::MAX);
    }

    #[test]
    fn der_oid_encoding() {
        let oid = der_oid_from_str("1.3.6.1.4.1.99999.1.1");
        assert_eq!(oid[0], 0x06);
        assert!(oid.len() > 2);
        // First arc: 1*40+3 = 43
        assert_eq!(oid[2], 43);
    }

    // ── Interop: x509-parser DER parsing ─────────────────────────────

    #[test]
    fn interop_x509_parser_parses_timestamp_resp() {
        let provider = SoftwareSigningProvider::generate();
        let imprint = test_imprint();
        let der = build_timestamp_resp_der(&test_params(&imprint), &provider).unwrap();

        let (rem, parsed) =
            x509_parser::der_parser::parse_der(&der).expect("x509-parser must parse TSA DER");
        assert!(rem.is_empty());
        let resp_seq = parsed.as_sequence().unwrap();
        assert!(resp_seq.len() >= 2, "TimeStampResp: status + token");
        // PKIStatusInfo SEQUENCE → status INTEGER 0
        let status_seq = resp_seq[0].as_sequence().unwrap();
        let status = status_seq[0].as_u32().unwrap();
        assert_eq!(status, 0, "PKIStatus must be granted");
    }

    #[test]
    fn interop_x509_parser_finds_signed_data_oid() {
        let provider = SoftwareSigningProvider::generate();
        let imprint = test_imprint();
        let der = build_timestamp_resp_der(&test_params(&imprint), &provider).unwrap();
        let (_, parsed) = x509_parser::der_parser::parse_der(&der).unwrap();
        let resp_seq = parsed.as_sequence().unwrap();
        // ContentInfo SEQUENCE
        let ci = resp_seq[1].as_sequence().unwrap();
        let oid = ci[0].as_oid().unwrap();
        assert_eq!(oid.to_string(), "1.2.840.113549.1.7.2");
    }

    #[test]
    fn interop_x509_parser_extracts_tst_info_content_type() {
        let provider = SoftwareSigningProvider::generate();
        let imprint = test_imprint();
        let der = build_timestamp_resp_der(&test_params(&imprint), &provider).unwrap();
        let (_, parsed) = x509_parser::der_parser::parse_der(&der).unwrap();
        let resp_seq = parsed.as_sequence().unwrap();
        let ci = resp_seq[1].as_sequence().unwrap();
        // [0] EXPLICIT → SignedData
        let sd_bytes = ci[1].content.as_slice().unwrap();
        let (_, sd_parsed) = x509_parser::der_parser::parse_der(sd_bytes).unwrap();
        let sd = sd_parsed.as_sequence().unwrap();
        // version 3
        assert_eq!(sd[0].as_u32().unwrap(), 3);
        // encapContentInfo SEQUENCE containing id-ct-TSTInfo OID
        let encap = sd[2].as_sequence().unwrap();
        let ct_oid = encap[0].as_oid().unwrap();
        assert_eq!(ct_oid.to_string(), "1.2.840.113549.1.9.16.1.4");
    }
}
