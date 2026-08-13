//! ETSI TS 119 612 Trusted List Client.
//!
//! Parses EU Trusted Lists (XML) to verify QTSP status.
//! Supports both LOTL (List of Trusted Lists) and country-level TLs.
//!
//! EU LOTL URL: `https://ec.europa.eu/tools/lotl/eu-lotl.xml`

use serde::{Deserialize, Serialize};

/// ETSI service status URIs.
pub const STATUS_GRANTED: &str = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
pub const STATUS_WITHDRAWN: &str = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn";
pub const STATUS_RECOGNISED: &str =
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel";

/// ETSI service type URIs.
pub const STYPE_CA_QC: &str = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
pub const STYPE_TSA_QTST: &str = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST";
pub const STYPE_OCSP_QC: &str = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC";
pub const STYPE_EDS_Q: &str = "http://uri.etsi.org/TrstSvc/Svctype/EDS/Q";
pub const STYPE_PSES_Q: &str = "http://uri.etsi.org/TrstSvc/Svctype/PSES/Q";

/// A Trust Service Provider entry from a Trusted List.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TspEntry {
    pub name: String,
    pub country: String,
    pub services: Vec<TspService>,
}

/// A single service offered by a TSP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TspService {
    pub service_type: String,
    pub service_name: String,
    pub status: String,
    pub status_starting_time: String,
}

impl TspService {
    pub fn is_qualified(&self) -> bool {
        self.status == STATUS_GRANTED
    }

    pub fn is_withdrawn(&self) -> bool {
        self.status == STATUS_WITHDRAWN
    }
}

/// A pointer to a country TL from the LOTL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlPointer {
    pub territory: String,
    pub tl_url: String,
}

/// Parsed Trusted List.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedList {
    pub version: String,
    pub territory: String,
    pub tsp_entries: Vec<TspEntry>,
    /// Only present in LOTL.
    pub tl_pointers: Vec<TlPointer>,
}

/// Parse a Trusted List XML string (LOTL or country TL).
pub fn parse_trusted_list(xml: &str) -> Result<TrustedList, String> {
    let version = extract_tl_tag(xml, "TSLVersionIdentifier").unwrap_or_else(|| "6".to_string());
    let territory = extract_tl_tag(xml, "SchemeTerritory").unwrap_or_else(|| "unknown".to_string());

    let tl_pointers = parse_tl_pointers(xml);
    let tsp_entries = parse_tsp_entries(xml, &territory);

    Ok(TrustedList {
        version,
        territory,
        tsp_entries,
        tl_pointers,
    })
}

/// Check if a TSP with a given name has a qualified service of a given type.
pub fn is_qualified_tsp(tl: &TrustedList, tsp_name: &str, service_type: &str) -> bool {
    tl.tsp_entries.iter().any(|tsp| {
        tsp.name.contains(tsp_name)
            && tsp
                .services
                .iter()
                .any(|s| s.service_type == service_type && s.is_qualified())
    })
}

/// Find all qualified services of a given type across all TSPs.
pub fn find_qualified_services<'a>(
    tl: &'a TrustedList,
    service_type: &str,
) -> Vec<(&'a TspEntry, &'a TspService)> {
    let mut results = Vec::new();
    for tsp in &tl.tsp_entries {
        for svc in &tsp.services {
            if svc.service_type == service_type && svc.is_qualified() {
                results.push((tsp, svc));
            }
        }
    }
    results
}

// ── TL Signature Verification (ETSI TS 119 612 §5.3) ─────────────────────

/// Result of verifying a Trusted List's XAdES signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlSignatureResult {
    pub signed: bool,
    pub signature_valid: bool,
    pub signer_algorithm: Option<String>,
    pub signing_time: Option<String>,
}

/// Verify the XAdES signature embedded in a Trusted List XML.
///
/// ETSI TS 119 612 §5.3 requires TLs to be signed with XAdES-BES.
/// Returns verification result; `signed: false` if no `<ds:Signature>` found.
pub fn verify_tl_signature(xml: &str) -> TlSignatureResult {
    let sig_start = match xml.find("<ds:Signature") {
        Some(pos) => pos,
        None => {
            return TlSignatureResult {
                signed: false,
                signature_valid: false,
                signer_algorithm: None,
                signing_time: None,
            };
        }
    };
    let sig_end_marker = "</ds:Signature>";
    let sig_end = match xml.find(sig_end_marker) {
        Some(pos) => pos + sig_end_marker.len(),
        None => {
            return TlSignatureResult {
                signed: true,
                signature_valid: false,
                signer_algorithm: None,
                signing_time: None,
            };
        }
    };
    let sig_xml = &xml[sig_start..sig_end];

    let fields = crate::signature::xades::parse_xades_fields(sig_xml);
    let (algorithm, signing_time) = match &fields {
        Some(f) => (
            Some(format!("{:?}", f.algorithm)),
            Some(f.signing_time.clone()),
        ),
        None => (None, None),
    };

    let signature_valid = crate::signature::xades::verify_xades_signature(sig_xml).unwrap_or(false);

    TlSignatureResult {
        signed: true,
        signature_valid,
        signer_algorithm: algorithm,
        signing_time,
    }
}

// ── XML parsing helpers ───────────────────────────────────────────────────
// ponytail: no XML crate. Fixed ETSI structure, string extraction.

fn extract_tl_tag(xml: &str, tag: &str) -> Option<String> {
    // Try with tsl: prefix first, then without
    for prefix in ["tsl:", ""] {
        let open = format!("<{prefix}{tag}>");
        let close = format!("</{prefix}{tag}>");
        if let Some(start) = xml.find(&open) {
            let content_start = start + open.len();
            if let Some(end) = xml[content_start..].find(&close) {
                return Some(xml[content_start..content_start + end].trim().to_string());
            }
        }
    }
    None
}

fn parse_tl_pointers(xml: &str) -> Vec<TlPointer> {
    let mut pointers = Vec::new();
    let marker = "OtherTSLPointer";
    let mut search = xml;
    while let Some(start) = search.find(&format!("<tsl:{marker}")) {
        let block_end = search[start..]
            .find(&format!("</tsl:{marker}>"))
            .unwrap_or(search.len() - start);
        let block = &search[start..start + block_end];

        let territory =
            extract_tl_tag(block, "SchemeTerritory").unwrap_or_else(|| "??".to_string());
        let url = extract_tsl_location(block).unwrap_or_default();

        if !url.is_empty() {
            pointers.push(TlPointer {
                territory,
                tl_url: url,
            });
        }
        search = &search[start + block_end..];
    }
    pointers
}

fn extract_tsl_location(block: &str) -> Option<String> {
    for prefix in ["tsl:", ""] {
        let tag = format!("<{prefix}TSLLocation>");
        let close = format!("</{prefix}TSLLocation>");
        if let Some(start) = block.find(&tag) {
            let cs = start + tag.len();
            if let Some(end) = block[cs..].find(&close) {
                return Some(block[cs..cs + end].trim().to_string());
            }
        }
    }
    None
}

fn parse_tsp_entries(xml: &str, territory: &str) -> Vec<TspEntry> {
    let mut entries = Vec::new();
    let marker = "TrustServiceProvider>";
    let mut search = xml;

    while let Some(start) = search.find(marker) {
        let tag_start = search[..start].rfind('<').unwrap_or(start);
        let end_marker = &search[tag_start..start + marker.len()];
        if end_marker.contains('/') {
            search = &search[start + marker.len()..];
            continue;
        }

        let block_end = search[start..]
            .find(&format!(
                "</{}",
                &search[tag_start + 1..start + marker.len()]
            ))
            .unwrap_or(search.len() - start);
        let block = &search[start..start + block_end];

        let name = extract_tl_tag(block, "Name")
            .or_else(|| extract_tl_tag(block, "TSPName"))
            .unwrap_or_else(|| "Unknown TSP".to_string());

        let services = parse_tsp_services(block);

        entries.push(TspEntry {
            name,
            country: territory.to_string(),
            services,
        });

        search = &search[start + block_end..];
    }
    entries
}

fn parse_tsp_services(block: &str) -> Vec<TspService> {
    let mut services = Vec::new();
    let marker = "TSPService>";
    let mut search = block;

    while let Some(start) = search.find(marker) {
        let tag_start = search[..start].rfind('<').unwrap_or(start);
        let end_marker = &search[tag_start..start + marker.len()];
        if end_marker.contains('/') {
            search = &search[start + marker.len()..];
            continue;
        }

        let svc_end = search[start..]
            .find(&format!(
                "</{}",
                &search[tag_start + 1..start + marker.len()]
            ))
            .unwrap_or(search.len() - start);
        let svc_block = &search[start..start + svc_end];

        let service_type = extract_tl_tag(svc_block, "ServiceTypeIdentifier").unwrap_or_default();
        let service_name = extract_tl_tag(svc_block, "ServiceName")
            .or_else(|| extract_tl_tag(svc_block, "Name"))
            .unwrap_or_else(|| "Unnamed".to_string());
        let status = extract_tl_tag(svc_block, "ServiceStatus").unwrap_or_default();
        let status_time = extract_tl_tag(svc_block, "StatusStartingTime").unwrap_or_default();

        if !service_type.is_empty() {
            services.push(TspService {
                service_type,
                service_name,
                status,
                status_starting_time: status_time,
            });
        }

        search = &search[start + svc_end..];
    }
    services
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_country_tl() -> &'static str {
        r#"<?xml version="1.0" encoding="UTF-8"?>
<tsl:TrustServiceStatusList xmlns:tsl="http://uri.etsi.org/02231/v2#">
  <tsl:SchemeInformation>
    <tsl:TSLVersionIdentifier>6</tsl:TSLVersionIdentifier>
    <tsl:SchemeTerritory>ES</tsl:SchemeTerritory>
  </tsl:SchemeInformation>
  <tsl:TrustServiceProviderList>
    <tsl:TrustServiceProvider>
      <tsl:TSPInformation>
        <tsl:TSPName><tsl:Name>FNMT-RCM</tsl:Name></tsl:TSPName>
      </tsl:TSPInformation>
      <tsl:TSPServices>
        <tsl:TSPService>
          <tsl:ServiceInformation>
            <tsl:ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</tsl:ServiceTypeIdentifier>
            <tsl:ServiceName><tsl:Name>FNMT Qualified CA</tsl:Name></tsl:ServiceName>
            <tsl:ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</tsl:ServiceStatus>
            <tsl:StatusStartingTime>2024-01-01T00:00:00Z</tsl:StatusStartingTime>
          </tsl:ServiceInformation>
        </tsl:TSPService>
        <tsl:TSPService>
          <tsl:ServiceInformation>
            <tsl:ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST</tsl:ServiceTypeIdentifier>
            <tsl:ServiceName><tsl:Name>FNMT Qualified TSA</tsl:Name></tsl:ServiceName>
            <tsl:ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</tsl:ServiceStatus>
            <tsl:StatusStartingTime>2024-01-01T00:00:00Z</tsl:StatusStartingTime>
          </tsl:ServiceInformation>
        </tsl:TSPService>
      </tsl:TSPServices>
    </tsl:TrustServiceProvider>
    <tsl:TrustServiceProvider>
      <tsl:TSPInformation>
        <tsl:TSPName><tsl:Name>Withdrawn Corp</tsl:Name></tsl:TSPName>
      </tsl:TSPInformation>
      <tsl:TSPServices>
        <tsl:TSPService>
          <tsl:ServiceInformation>
            <tsl:ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</tsl:ServiceTypeIdentifier>
            <tsl:ServiceName><tsl:Name>Old CA</tsl:Name></tsl:ServiceName>
            <tsl:ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</tsl:ServiceStatus>
            <tsl:StatusStartingTime>2023-06-01T00:00:00Z</tsl:StatusStartingTime>
          </tsl:ServiceInformation>
        </tsl:TSPService>
      </tsl:TSPServices>
    </tsl:TrustServiceProvider>
  </tsl:TrustServiceProviderList>
</tsl:TrustServiceStatusList>"#
    }

    fn sample_lotl() -> &'static str {
        r#"<?xml version="1.0" encoding="UTF-8"?>
<tsl:TrustServiceStatusList xmlns:tsl="http://uri.etsi.org/02231/v2#">
  <tsl:SchemeInformation>
    <tsl:TSLVersionIdentifier>6</tsl:TSLVersionIdentifier>
    <tsl:SchemeTerritory>EU</tsl:SchemeTerritory>
    <tsl:PointersToOtherTSL>
      <tsl:OtherTSLPointer>
        <tsl:TSLLocation>https://sede.minetur.gob.es/Prestadores/TSL/TSL.xml</tsl:TSLLocation>
        <tsl:SchemeTerritory>ES</tsl:SchemeTerritory>
      </tsl:OtherTSLPointer>
      <tsl:OtherTSLPointer>
        <tsl:TSLLocation>https://ec.europa.eu/tools/lotl/de-tl.xml</tsl:TSLLocation>
        <tsl:SchemeTerritory>DE</tsl:SchemeTerritory>
      </tsl:OtherTSLPointer>
    </tsl:PointersToOtherTSL>
  </tsl:SchemeInformation>
</tsl:TrustServiceStatusList>"#
    }

    #[test]
    fn parse_country_tl() {
        let tl = parse_trusted_list(sample_country_tl()).unwrap();
        assert_eq!(tl.territory, "ES");
        assert_eq!(tl.version, "6");
        assert_eq!(tl.tsp_entries.len(), 2);
        assert_eq!(tl.tsp_entries[0].name, "FNMT-RCM");
        assert_eq!(tl.tsp_entries[0].services.len(), 2);
    }

    #[test]
    fn parse_lotl_pointers() {
        let tl = parse_trusted_list(sample_lotl()).unwrap();
        assert_eq!(tl.territory, "EU");
        assert_eq!(tl.tl_pointers.len(), 2);
        assert_eq!(tl.tl_pointers[0].territory, "ES");
        assert!(tl.tl_pointers[0].tl_url.contains("minetur"));
        assert_eq!(tl.tl_pointers[1].territory, "DE");
    }

    #[test]
    fn qualified_tsp_check() {
        let tl = parse_trusted_list(sample_country_tl()).unwrap();
        assert!(is_qualified_tsp(&tl, "FNMT", STYPE_CA_QC));
        assert!(is_qualified_tsp(&tl, "FNMT", STYPE_TSA_QTST));
        assert!(!is_qualified_tsp(&tl, "Withdrawn", STYPE_CA_QC));
        assert!(!is_qualified_tsp(&tl, "NonExistent", STYPE_CA_QC));
    }

    #[test]
    fn find_qualified_ca_services() {
        let tl = parse_trusted_list(sample_country_tl()).unwrap();
        let cas = find_qualified_services(&tl, STYPE_CA_QC);
        assert_eq!(cas.len(), 1);
        assert_eq!(cas[0].0.name, "FNMT-RCM");
    }

    #[test]
    fn find_qualified_tsa_services() {
        let tl = parse_trusted_list(sample_country_tl()).unwrap();
        let tsas = find_qualified_services(&tl, STYPE_TSA_QTST);
        assert_eq!(tsas.len(), 1);
    }

    #[test]
    fn withdrawn_service_not_qualified() {
        let tl = parse_trusted_list(sample_country_tl()).unwrap();
        let withdrawn = &tl.tsp_entries[1].services[0];
        assert!(!withdrawn.is_qualified());
        assert!(withdrawn.is_withdrawn());
    }

    #[test]
    fn service_status_constants() {
        assert!(STATUS_GRANTED.contains("granted"));
        assert!(STATUS_WITHDRAWN.contains("withdrawn"));
        assert!(STYPE_CA_QC.contains("CA/QC"));
        assert!(STYPE_TSA_QTST.contains("TSA/QTST"));
    }

    #[test]
    fn empty_xml_returns_defaults() {
        let tl = parse_trusted_list("<root></root>").unwrap();
        assert_eq!(tl.territory, "unknown");
        assert!(tl.tsp_entries.is_empty());
        assert!(tl.tl_pointers.is_empty());
    }

    #[test]
    fn tl_without_signature_returns_unsigned() {
        let result = verify_tl_signature(sample_country_tl());
        assert!(!result.signed);
        assert!(!result.signature_valid);
    }

    #[test]
    fn tl_with_valid_xades_signature() {
        use crate::crypto::hasher::{hash_with, HashAlgorithm};
        use crate::identity::signing::{
            SigningAlgorithm, SigningProvider, SoftwareSigningProvider,
        };
        use crate::signature::{SignatureLevel, SignedEnvelope};

        let provider = SoftwareSigningProvider::generate();
        let tl_content = sample_country_tl();
        let content_hash = hex::encode(hash_with(HashAlgorithm::Sha256, tl_content.as_bytes()));

        let env = SignedEnvelope {
            level: SignatureLevel::Simple,
            signer: "did:goya:tl-signer".to_string(),
            content_hash,
            signature: String::new(),
            public_key: hex::encode(provider.public_key()),
            signature_algorithm: SigningAlgorithm::Ed25519,
            biometric_evidence: vec![],
            signed_at: 1700000000,
        };

        let xades = crate::signature::xades::to_xades_bes_signed(&env, &provider).unwrap();

        // Embed the XAdES signature into the TL XML
        let signed_tl = tl_content.replace(
            "</tsl:TrustServiceStatusList>",
            &format!("{}\n</tsl:TrustServiceStatusList>", xades.xml),
        );

        let result = verify_tl_signature(&signed_tl);
        assert!(result.signed);
        assert!(result.signature_valid);
        assert_eq!(result.signer_algorithm.as_deref(), Some("Ed25519"));
        assert!(result.signing_time.is_some());
    }

    #[test]
    fn tl_with_tampered_xades_signature() {
        use crate::crypto::hasher::{hash_with, HashAlgorithm};
        use crate::identity::signing::{
            SigningAlgorithm, SigningProvider, SoftwareSigningProvider,
        };
        use crate::signature::{SignatureLevel, SignedEnvelope};

        let provider = SoftwareSigningProvider::generate();
        let tl_content = sample_country_tl();
        let content_hash = hex::encode(hash_with(HashAlgorithm::Sha256, tl_content.as_bytes()));

        let env = SignedEnvelope {
            level: SignatureLevel::Simple,
            signer: "did:goya:tl-signer".to_string(),
            content_hash,
            signature: String::new(),
            public_key: hex::encode(provider.public_key()),
            signature_algorithm: SigningAlgorithm::Ed25519,
            biometric_evidence: vec![],
            signed_at: 1700000000,
        };

        let xades = crate::signature::xades::to_xades_bes_signed(&env, &provider).unwrap();
        let tampered_sig = xades
            .xml
            .replace("<ds:DigestValue>", "<ds:DigestValue>TAMPERED");
        let signed_tl = tl_content.replace(
            "</tsl:TrustServiceStatusList>",
            &format!("{tampered_sig}\n</tsl:TrustServiceStatusList>"),
        );

        let result = verify_tl_signature(&signed_tl);
        assert!(result.signed);
        assert!(!result.signature_valid);
    }

    #[test]
    fn tl_with_incomplete_signature() {
        let xml = r#"<root><ds:Signature Id="test">incomplete</root>"#;
        let result = verify_tl_signature(xml);
        assert!(result.signed);
        assert!(!result.signature_valid);
    }
}
