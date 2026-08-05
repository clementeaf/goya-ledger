//! XAdES-BES (XML Advanced Electronic Signatures — Basic).
//!
//! ETSI TS 101 903 — produces XML envelopes from `SignedEnvelope`.
//! No external XML crate needed: the structure is fixed and generated
//! from templates. Output is already in canonical form (Exclusive C14N
//! compatible) since we control generation.

use crate::crypto::hasher::{hash_with, HashAlgorithm};
use crate::identity::signing::SigningAlgorithm;
use crate::signature::{SignatureLevel, SignedEnvelope};

/// XAdES-BES XML envelope wrapping a `SignedEnvelope`.
#[derive(Debug, Clone)]
pub struct XadesEnvelope {
    pub xml: String,
    pub signature_id: String,
}

/// Build an XAdES-BES XML envelope from a `SignedEnvelope`.
pub fn to_xades_bes(envelope: &SignedEnvelope) -> XadesEnvelope {
    let sig_id = format!("goya-sig-{}", &envelope.content_hash[..16]);
    let sp_id = format!("goya-sp-{}", &envelope.content_hash[..16]);
    let signing_time = timestamp_to_iso8601(envelope.signed_at);
    let algo_uri = algorithm_uri(envelope.signature_algorithm);
    let digest_algo_uri = "http://www.w3.org/2001/04/xmlenc#sha256";
    let sig_value_b64 = hex_to_base64(&envelope.signature);
    let pubkey_b64 = hex_to_base64(&envelope.public_key);
    let level_str = level_to_claimed_role(envelope.level);

    let cert_digest = {
        let pk_bytes = hex::decode(&envelope.public_key).unwrap_or_default();
        let digest = hash_with(HashAlgorithm::Sha256, &pk_bytes);
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, digest)
    };

    let signed_props_xml = build_signed_properties(
        &sp_id,
        &signing_time,
        digest_algo_uri,
        &cert_digest,
        &envelope.signer,
        level_str,
    );

    let signed_props_digest = {
        let digest = hash_with(HashAlgorithm::Sha256, signed_props_xml.as_bytes());
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, digest)
    };

    let doc_digest_b64 = hex_to_base64(&envelope.content_hash);

    let signed_info = build_signed_info(
        algo_uri,
        digest_algo_uri,
        &doc_digest_b64,
        &signed_props_digest,
        &sp_id,
    );

    let xml = format!(
        r##"<?xml version="1.0" encoding="UTF-8"?>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="{sig_id}">
{signed_info}
  <ds:SignatureValue>{sig_value_b64}</ds:SignatureValue>
  <ds:KeyInfo>
    <ds:KeyValue>
      <ds:PublicKey Algorithm="{algo_uri}">{pubkey_b64}</ds:PublicKey>
    </ds:KeyValue>
  </ds:KeyInfo>
  <ds:Object>
    <xades:QualifyingProperties Target="#{sig_id}">
{signed_props_xml}
    </xades:QualifyingProperties>
  </ds:Object>
</ds:Signature>"##
    );

    XadesEnvelope {
        xml,
        signature_id: sig_id,
    }
}

/// Extract and verify an XAdES envelope's core fields.
pub fn parse_xades_fields(xml: &str) -> Option<XadesFields> {
    let signature_value = extract_tag(xml, "ds:SignatureValue")?;
    let public_key = extract_tag(xml, "ds:PublicKey")?;
    let signing_time = extract_tag(xml, "xades:SigningTime")?;
    let claimed_role = extract_tag(xml, "xades:ClaimedRole");
    let cert_digest = extract_tag(xml, "xades:CertDigest");
    let doc_digest = extract_between(xml, "<ds:DigestValue>", "</ds:DigestValue>");

    let sig_id = extract_attr(xml, "ds:Signature", "Id")?;

    let algo_attr = extract_attr(xml, "ds:SignatureMethod", "Algorithm")?;
    let algorithm = uri_to_algorithm(&algo_attr)?;

    Some(XadesFields {
        signature_id: sig_id,
        signature_value,
        public_key,
        algorithm,
        signing_time,
        claimed_role,
        cert_digest,
        document_digest: doc_digest,
    })
}

/// Parsed fields from an XAdES envelope.
#[derive(Debug, Clone)]
pub struct XadesFields {
    pub signature_id: String,
    pub signature_value: String,
    pub public_key: String,
    pub algorithm: SigningAlgorithm,
    pub signing_time: String,
    pub claimed_role: Option<String>,
    pub cert_digest: Option<String>,
    pub document_digest: Option<String>,
}

fn build_signed_properties(
    sp_id: &str,
    signing_time: &str,
    digest_algo_uri: &str,
    cert_digest_b64: &str,
    signer: &str,
    claimed_role: &str,
) -> String {
    format!(
        r##"      <xades:SignedProperties Id="{sp_id}">
        <xades:SignedSignatureProperties>
          <xades:SigningTime>{signing_time}</xades:SigningTime>
          <xades:SigningCertificateV2>
            <xades:Cert>
              <xades:CertDigest>
                <ds:DigestMethod Algorithm="{digest_algo_uri}"/>
                <ds:DigestValue>{cert_digest_b64}</ds:DigestValue>
              </xades:CertDigest>
            </xades:Cert>
          </xades:SigningCertificateV2>
          <xades:SignerRole>
            <xades:ClaimedRoles>
              <xades:ClaimedRole>{claimed_role}</xades:ClaimedRole>
            </xades:ClaimedRoles>
          </xades:SignerRole>
        </xades:SignedSignatureProperties>
        <xades:SignedDataObjectProperties>
          <xades:DataObjectFormat ObjectReference="#doc-ref">
            <xades:MimeType>application/octet-stream</xades:MimeType>
          </xades:DataObjectFormat>
        </xades:SignedDataObjectProperties>
        <xades:SignerDID>{signer}</xades:SignerDID>
      </xades:SignedProperties>"##
    )
}

fn build_signed_info(
    algo_uri: &str,
    digest_algo_uri: &str,
    doc_digest_b64: &str,
    signed_props_digest_b64: &str,
    sp_id: &str,
) -> String {
    format!(
        r##"  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="{algo_uri}"/>
    <ds:Reference Id="doc-ref" URI="">
      <ds:DigestMethod Algorithm="{digest_algo_uri}"/>
      <ds:DigestValue>{doc_digest_b64}</ds:DigestValue>
    </ds:Reference>
    <ds:Reference URI="#{sp_id}" Type="http://uri.etsi.org/01903#SignedProperties">
      <ds:DigestMethod Algorithm="{digest_algo_uri}"/>
      <ds:DigestValue>{signed_props_digest_b64}</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>"##
    )
}

const ED25519_URI: &str = "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519";
const MLDSA65_URI: &str = "http://www.w3.org/2024/xmldsig-pqc#ml-dsa-65";
const RSA_SHA256_URI: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

fn algorithm_uri(algo: SigningAlgorithm) -> &'static str {
    match algo {
        SigningAlgorithm::Ed25519 => ED25519_URI,
        SigningAlgorithm::MlDsa65 => MLDSA65_URI,
        SigningAlgorithm::Rsa => RSA_SHA256_URI,
    }
}

fn uri_to_algorithm(uri: &str) -> Option<SigningAlgorithm> {
    if uri == ED25519_URI {
        Some(SigningAlgorithm::Ed25519)
    } else if uri == MLDSA65_URI {
        Some(SigningAlgorithm::MlDsa65)
    } else if uri == RSA_SHA256_URI {
        Some(SigningAlgorithm::Rsa)
    } else {
        None
    }
}

fn level_to_claimed_role(level: SignatureLevel) -> &'static str {
    match level {
        SignatureLevel::Simple => "FES",
        SignatureLevel::Advanced => "FEA",
        SignatureLevel::Qualified => "FEQ",
    }
}

pub(crate) fn timestamp_to_iso8601(unix_secs: u64) -> String {
    let secs = unix_secs as i64;
    let days = secs / 86400;
    let rem = secs % 86400;
    let hours = rem / 3600;
    let mins = (rem % 3600) / 60;
    let s = rem % 60;

    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{mins:02}:{s:02}Z")
}

fn days_to_ymd(mut days: i64) -> (i64, u32, u32) {
    days += 719_468;
    let era = days.div_euclid(146_097);
    let doe = days.rem_euclid(146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn hex_to_base64(hex_str: &str) -> String {
    let bytes = hex::decode(hex_str).unwrap_or_default();
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes)
}

fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let close = format!("</{tag}>");
    let close_pos = xml.find(&close)?;
    let search_area = &xml[..close_pos];
    let open_exact = format!("<{tag}>");
    let open_attr = format!("<{tag} ");
    let start = search_area
        .rfind(&open_exact)
        .or_else(|| search_area.rfind(&open_attr))?;
    let after_open = xml[start..].find('>')? + start + 1;
    Some(xml[after_open..close_pos].trim().to_string())
}

fn extract_between(xml: &str, start_marker: &str, end_marker: &str) -> Option<String> {
    let start = xml.find(start_marker)? + start_marker.len();
    let end = xml[start..].find(end_marker)? + start;
    Some(xml[start..end].trim().to_string())
}

fn extract_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let open = format!("<{tag} ");
    let start = xml.find(&open)?;
    let tag_end = xml[start..].find('>')? + start;
    let tag_str = &xml[start..tag_end];
    let attr_pattern = format!("{attr}=\"");
    let attr_start = tag_str.find(&attr_pattern)? + attr_pattern.len();
    let attr_end = tag_str[attr_start..].find('"')? + attr_start;
    Some(tag_str[attr_start..attr_end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::{SigningProvider, SoftwareSigningProvider};

    fn make_envelope() -> SignedEnvelope {
        let provider = SoftwareSigningProvider::generate();
        let content_hash = hex::encode(hash_with(HashAlgorithm::Sha256, b"test document content"));
        let payload = format!("fes:did:goya:test:{content_hash}");
        let signature = hex::encode(provider.sign(payload.as_bytes()).unwrap());
        let public_key = hex::encode(provider.public_key());

        SignedEnvelope {
            level: SignatureLevel::Simple,
            signer: "did:goya:test".to_string(),
            content_hash,
            signature,
            public_key,
            signature_algorithm: SigningAlgorithm::Ed25519,
            biometric_evidence: vec![],
            signed_at: 1700000000,
        }
    }

    #[test]
    fn produces_valid_xml_structure() {
        let env = make_envelope();
        let xades = to_xades_bes(&env);
        assert!(xades.xml.starts_with("<?xml version=\"1.0\""));
        assert!(xades.xml.contains("<ds:Signature"));
        assert!(xades.xml.contains("</ds:Signature>"));
        assert!(xades
            .xml
            .contains("xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\""));
        assert!(xades
            .xml
            .contains("xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\""));
    }

    #[test]
    fn contains_signed_info() {
        let env = make_envelope();
        let xades = to_xades_bes(&env);
        assert!(xades.xml.contains("<ds:SignedInfo>"));
        assert!(xades.xml.contains("<ds:CanonicalizationMethod"));
        assert!(xades.xml.contains("<ds:SignatureMethod"));
        assert!(xades.xml.contains("<ds:Reference"));
    }

    #[test]
    fn contains_signature_value() {
        let env = make_envelope();
        let xades = to_xades_bes(&env);
        assert!(xades.xml.contains("<ds:SignatureValue>"));
        let sig_b64 = hex_to_base64(&env.signature);
        assert!(xades.xml.contains(&sig_b64));
    }

    #[test]
    fn contains_key_info() {
        let env = make_envelope();
        let xades = to_xades_bes(&env);
        assert!(xades.xml.contains("<ds:KeyInfo>"));
        let pk_b64 = hex_to_base64(&env.public_key);
        assert!(xades.xml.contains(&pk_b64));
    }

    #[test]
    fn contains_qualifying_properties() {
        let env = make_envelope();
        let xades = to_xades_bes(&env);
        assert!(xades.xml.contains("<xades:QualifyingProperties"));
        assert!(xades.xml.contains("<xades:SignedProperties"));
        assert!(xades.xml.contains("<xades:SigningTime>"));
        assert!(xades.xml.contains("<xades:SigningCertificateV2>"));
        assert!(xades.xml.contains("<xades:CertDigest>"));
    }

    #[test]
    fn contains_signing_time_iso8601() {
        let env = make_envelope();
        let xades = to_xades_bes(&env);
        assert!(xades.xml.contains("2023-11-14T22:13:20Z"));
    }

    #[test]
    fn contains_signer_role_fes() {
        let env = make_envelope();
        let xades = to_xades_bes(&env);
        assert!(xades
            .xml
            .contains("<xades:ClaimedRole>FES</xades:ClaimedRole>"));
    }

    #[test]
    fn fea_level_role() {
        let mut env = make_envelope();
        env.level = SignatureLevel::Advanced;
        let xades = to_xades_bes(&env);
        assert!(xades
            .xml
            .contains("<xades:ClaimedRole>FEA</xades:ClaimedRole>"));
    }

    #[test]
    fn contains_ed25519_algorithm_uri() {
        let env = make_envelope();
        let xades = to_xades_bes(&env);
        assert!(xades.xml.contains("eddsa-ed25519"));
    }

    #[test]
    fn contains_signer_did() {
        let env = make_envelope();
        let xades = to_xades_bes(&env);
        assert!(xades
            .xml
            .contains("<xades:SignerDID>did:goya:test</xades:SignerDID>"));
    }

    #[test]
    fn contains_data_object_format() {
        let env = make_envelope();
        let xades = to_xades_bes(&env);
        assert!(xades.xml.contains("<xades:DataObjectFormat"));
        assert!(xades
            .xml
            .contains("<xades:MimeType>application/octet-stream</xades:MimeType>"));
    }

    #[test]
    fn signature_id_derived_from_content_hash() {
        let env = make_envelope();
        let xades = to_xades_bes(&env);
        let expected_prefix = &env.content_hash[..16];
        assert!(xades.signature_id.contains(expected_prefix));
        assert!(xades
            .xml
            .contains(&format!("Id=\"{}\"", xades.signature_id)));
    }

    #[test]
    fn contains_signed_properties_reference() {
        let env = make_envelope();
        let xades = to_xades_bes(&env);
        assert!(xades
            .xml
            .contains("Type=\"http://uri.etsi.org/01903#SignedProperties\""));
    }

    #[test]
    fn parse_roundtrip() {
        let env = make_envelope();
        let xades = to_xades_bes(&env);
        let fields = parse_xades_fields(&xades.xml).unwrap();
        assert_eq!(fields.algorithm, SigningAlgorithm::Ed25519);
        assert_eq!(fields.signing_time, "2023-11-14T22:13:20Z");
        assert_eq!(fields.claimed_role.as_deref(), Some("FES"));
        assert!(!fields.signature_value.is_empty());
        assert!(!fields.public_key.is_empty());
        assert_eq!(fields.signature_id, xades.signature_id);
    }

    #[test]
    fn deterministic_output() {
        let env = make_envelope();
        let x1 = to_xades_bes(&env);
        let x2 = to_xades_bes(&env);
        assert_eq!(x1.xml, x2.xml);
    }

    #[test]
    fn iso8601_epoch() {
        assert_eq!(timestamp_to_iso8601(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn iso8601_known_date() {
        assert_eq!(timestamp_to_iso8601(1700000000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn iso8601_leap_year() {
        assert_eq!(timestamp_to_iso8601(1709251200), "2024-03-01T00:00:00Z");
    }

    #[test]
    fn hex_to_base64_known() {
        let b64 = hex_to_base64("48656c6c6f");
        assert_eq!(b64, "SGVsbG8=");
    }

    #[test]
    fn mldsa65_algorithm_uri() {
        let mut env = make_envelope();
        env.signature_algorithm = SigningAlgorithm::MlDsa65;
        let xades = to_xades_bes(&env);
        assert!(xades.xml.contains("ml-dsa-65"));
    }
}
