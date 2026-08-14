# UAE Regulatory Compliance

Legal alignment mapping for the GOYA Ledger platform against United Arab Emirates regulation.

Covers: electronic signatures, blockchain/DLT, digital identity, data protection, and smart contracts.

> **Disclaimer:** This document is a **self-assessment** mapping code features to legal requirements. It is not a certification, legal opinion, or formal audit result. No third-party auditor, TDRA, or UAE legal authority has validated these claims. Organizations should seek independent legal counsel before relying on these mappings for compliance purposes.

---

## Federal Decree-Law No. 46/2021 — Electronic Transactions and Trust Services

Replaced Federal Law No. 1/2006. Effective February 2022.

### Art. 1 — Definitions

| Legal concept | GOYA implementation | Status |
|---|---|---|
| **Electronic signature**: letters, numbers, symbols, voice, or process in electronic form associated with a data message | `SignatureLevel::Simple` — Ed25519 DID-based signature over content hash | Done |
| **Advanced electronic signature**: uniquely linked to signatory, identifies signatory, under sole control, detects subsequent changes | `SignatureLevel::Advanced` — ML-DSA-65 + biometric commitment | Done |
| **Qualified electronic signature**: advanced signature created with QSCD, based on qualified certificate from TDRA-licensed QTSP | `SignatureLevel::Qualified` — reserved for QTSP integration | Planned |

### Art. 11 — Automated Electronic Agents (Smart Contracts)

| Requirement | GOYA compliance |
|---|---|
| A contract formed by interaction of automated electronic agents is valid, enforceable, and legally effective even if no natural person directly intervened | Governance proposals, voting, and inference claims execute via deterministic on-chain logic. Chaincode module provides programmable contract execution |
| Applies to interactions between two automated agents and between an agent and a natural person | API-driven transactions (automated) and wallet-signed transactions (natural person) both produce legally valid on-chain records |

### Art. 19 — Advanced Electronic Signature Requirements

| Requirement | GOYA control | Evidence |
|---|---|---|
| **(a)** Uniquely linked to the signatory | DID (`did:goya:{pubkey}`) + biometric commitment(s) hashed into signing payload | `compute_biometrics_hash()` bound to payload |
| **(b)** Capable of identifying the signatory | Biometric evidence types: fingerprint, facial recognition, Emirates ID, iris, voice, government ID. **Caveat:** identification relies on self-issued DIDs — full Art. 19(b) compliance requires UAE Pass or Emirates ID verification via RA | `BiometricType` enum, `ProofingMethod::UaePass` |
| **(c)** Created using data under sole control of the signatory | ML-DSA-65 private key generated client-side, encrypted with Argon2id + AES-256-GCM | Client-side key management |
| **(d)** Linked to data so that any change is detectable | PQC signature covers signer DID + content hash + biometric hash | Signing payload: `"notarize_fea:{s}:{h}:{bio_hash}"` |

### Art. 20 — Qualified Electronic Signature

| Requirement | Status |
|---|---|
| Based on a qualified certificate issued by a TDRA-licensed QTSP | Planned — `Qualified` level reserved for TDRA-licensed provider integration |
| Created using a QSCD (Qualified Signature Creation Device) | `HsmSigningProvider` (PKCS#11) supports HSM-backed signing. Production deployment requires Common Criteria EAL4+ certified HSM |

### Art. 21 — QSCD Requirements

| Requirement | GOYA readiness |
|---|---|
| Confidentiality of signature creation data | HSM keeps private key in hardware; `SimulatedHsmProvider` enforces session-gated access |
| Protection against use by third parties | PIN/session authentication on `HsmSigningProvider` |
| Signature created once per operation | Atomic signing operation in `SigningProvider::sign()` |
| Data to be signed not altered before signing | Signing payload constructed from immutable inputs, signed in single operation |

### Art. 10 — Record Retention

| Requirement | GOYA implementation |
|---|---|
| Electronic records must be retained for the period specified by law (15 years for trust services) | `UAE_RETENTION_SECS` constant (15 years). `AuditRetentionPolicy::with_min_retention_years(15)` configurable per deployment |
| Records must be accessible and reproducible | `AuditStore::export_json()` with hash chain metadata. RocksDB persistent storage with tamper-evident audit chain |

---

## Cabinet Resolution No. 28/2023 — Executive Regulation

Implements DL 46/2021 with technical requirements.

| Requirement | GOYA compliance |
|---|---|
| TDRA licensing for trust service providers | Operational requirement — code supports QTSP certificate chain validation when provider is licensed |
| ETSI standards adoption | CAdES (ETSI TS 101 733), XAdES (ETSI TS 101 903), PAdES (ETSI TS 102 778), TSA (RFC 3161), OCSP (RFC 6960), CRL (RFC 5280) all implemented |
| Biennial conformity assessment (Art. 35-36) | Audit trail infrastructure supports assessment: tamper-evident hash chain, JSON/CSV export, retention policy |
| Mandatory security breach notification | Audit event categories include security officer actions, system events, and incident-relevant entries (`AuditAction` enum) |

---

## TDRA Trust Service Provider Requirements

| TSP service (Art. 17) | GOYA module | Status |
|---|---|---|
| Electronic signature creation | `SigningProvider` trait (Ed25519, ML-DSA-65, RSA) | Done |
| Qualified certificate issuance | `CaHierarchy` (root + intermediate CA), `pki.rs` | Done |
| QSCD management | `HsmSigningProvider` (PKCS#11, `cryptoki`) | Done |
| Electronic preservation | `NotarizationEntry` on-chain with block height anchoring | Done |
| Validation services | OCSP responder (RFC 6960), CRL distribution (RFC 5280) | Done |
| Electronic seals | `SignatureLevel::Seal` for legal entity signatures | Done |
| Time stamping | `TsaProvider` (RFC 3161), DER-encoded timestamps | Done |
| Qualified electronic delivery | Not implemented | Planned |

---

## Identity — Emirates ID and UAE Pass

### Registration Authority Integration

| Component | Implementation |
|---|---|
| Emirates ID validation | `validate_emirates_id()` — format 784-YYYY-NNNNNNN-C, Luhn check digit |
| UAE Pass verification method | `ProofingMethod::UaePass` in RA module |
| Jurisdiction routing | `Jurisdiction::Uae` dispatches to Emirates ID validation via `validate_national_id()` |
| `IdentityProofing` struct | `national_id` field for Emirates ID, `jurisdiction` field for multi-jurisdiction support |

### Emirates ID Format

```
784-YYYY-NNNNNNN-C
 │    │       │    └─ Luhn check digit
 │    │       └────── 7-digit sequence number
 │    └────────────── Birth year
 └─────────────────── UAE country code (ISO 3166-1)
```

Validation: country code `784`, year range 1900-2100, Luhn-10 check digit.

---

## Data Protection — PDPL (Federal Decree-Law No. 45/2021)

| Requirement | GOYA compliance |
|---|---|
| Lawful basis for processing personal data | Application layer responsibility. Biometric commitments are SHA-256 hashes (derived data, not raw biometric) |
| Cross-border data transfer requires adequate protection or contractual safeguards | Deployment configuration — node can be deployed within UAE for data residency. No code-level enforcement |
| Data subject rights (access, correction, deletion) | DID-based identity allows subject identification. Deletion constrained by blockchain immutability and 15-year retention requirement |
| CBUAE requirement: financial data stored within UAE | Deployment constraint — RocksDB data directory configurable via `GOYA_DATA_DIR` |

### Biometric Data Under PDPL

| Aspect | Assessment |
|---|---|
| Classification | SHA-256 commitments are derived data. Conservative treatment: sensitive personal data |
| Storage | Commitment-only architecture — no raw biometric data enters the system |
| Consent | Required for biometric processing. Application layer responsibility |
| Purpose limitation | Commitments used exclusively for signature binding |

---

## DLT/Blockchain Regulatory Landscape

### VARA — Dubai (Law No. 4/2022)

| Requirement | Relevance to GOYA |
|---|---|
| VASP licensing for virtual asset activities | Applies if GOYA tokens are classified as virtual assets in Dubai |
| 4 mandatory rulebooks + 7 activity-specific | Compliance depends on deployment use case (custody, exchange, etc.) |
| AML/CFT compliance | KYC via RA module (Emirates ID + UAE Pass). Travel Rule integration is application-layer concern |

### ADGM — Abu Dhabi (DLT Foundations Regulations 2023)

| Requirement | Relevance to GOYA |
|---|---|
| First DLT Foundations and DAO regime worldwide | GOYA governance module (proposals, voting, quorum) aligns with DAO governance requirements |
| FSRA licensing for financial services on DLT | Required if GOYA deployed for regulated financial services in ADGM |

### Federal — SCA and CBUAE

| Regulator | Scope | GOYA relevance |
|---|---|---|
| SCA | Virtual assets at federal level | Token classification determines applicability |
| CBUAE | Payment tokens (Payment Token Services Regulation 2024) | Applies if GOYA token used as payment instrument |

---

## Cryptographic Alignment

| Requirement | GOYA implementation |
|---|---|
| Technology-neutral (no algorithm mandates) | Ed25519, ML-DSA-65 (FIPS 204), RSA-2048 supported |
| ETSI-referenced standards (implicit RSA 2048+ or ECDSA P-256+) | RSA-2048 PKCS#1 v1.5 via `RsaSigningProvider`. Ed25519 exceeds ECDSA P-256 security level |
| HSM for QSCD (Common Criteria EAL4+) | `HsmSigningProvider` via PKCS#11/cryptoki. Production requires certified HSM hardware |
| Post-quantum readiness | ML-DSA-65 deployed — UAE law does not prohibit PQC algorithms |

---

## Language and Localization

| Requirement | Status |
|---|---|
| Arabic language support in interfaces and RTL | Application/frontend concern. API responses are JSON (language-neutral) |
| Arabic or bilingual documents | Certificate policies (`CertificatePolicy`, `CPS`) support configurable text. Arabic content requires deployment configuration |
| 2023 amendments reinforce Arabic support | Tauri desktop app and web frontends would need Arabic/RTL UI layer |

---

## Jurisdictional Comparison

| Feature | Chile (Ley 19.799) | EU (eIDAS) | UAE (DL 46/2021) | GOYA |
|---|---|---|---|---|
| Signature tiers | 2 (FES/FEA) | 3 (simple/advanced/qualified) | 3 (simple/advanced/qualified) | 3 (`Simple`/`Advanced`/`Qualified`) |
| Qualified requires TSP | PSC acreditado | QTSP in EU Trusted List | QTSP licensed by TDRA | `Qualified` reserved for TSP integration |
| National ID | RUT (modulo 11) | Per member state | Emirates ID (Luhn) | `validate_national_id()` dispatches by `Jurisdiction` |
| Identity proofing | Ley 19.799 Art. 15 | eIDAS Art. 24 | DL 46/2021 + UAE Pass | `RaStore` with `ProofingMethod` variants |
| Retention period | 7 years (DS 181) | Varies by member state | 15 years (Art. 10) | Configurable: `DEFAULT_RETENTION_SECS` / `UAE_RETENTION_SECS` |
| Smart contract recognition | No explicit law | No explicit recognition | Art. 11 — explicitly valid | Governance + chaincode modules |
| Data residency | No explicit mandate | GDPR (adequate protection) | PDPL + CBUAE mandate | Deployment configuration |
| PQC stance | No position | eIDAS 2.0 recommends readiness | Technology-neutral | ML-DSA-65 deployed |

---

## Gaps and Roadmap

| Gap | Severity | Path to close |
|---|---|---|
| TDRA QTSP licensing | Blocker for `Qualified` | Legal/operational — apply to TDRA when ready |
| UAE Pass integration (live API) | Medium | Integrate UAE Pass OAuth/OIDC for real-time identity verification |
| Arabic UI/RTL | Medium | Frontend localization layer in Tauri app and web interfaces |
| CBUAE data residency enforcement | Low | Deployment documentation for UAE-hosted nodes |
| VARA/ADGM licensing | Conditional | Depends on token classification and deployment jurisdiction |
| Qualified electronic delivery | Low | Not core to DLT use case |

---

## References

- [Federal Decree-Law No. 46/2021 — Electronic Transactions and Trust Services](https://legaladviceme.com/legislation/160/uae-federal-decree-law-46-2021-electronic-transactions-trust-services)
- [Cabinet Resolution No. 28/2023 — Executive Regulation](https://tdra.gov.ae/-/media/About/Trust-Services/Laws-and-regulations/Cabinet-Resolution-No-28-of-2023-Regarding-the-Executive-Regulation-of-the-Federal-Decree-Law-EN.ashx)
- [TDRA — Trust Services Laws and Regulations](https://tdra.gov.ae/en/About/tdra-sectors/information-and-digital-government/policy-and-programs-department/trust-services/laws-and-regulations)
- [Federal Decree-Law No. 45/2021 — Personal Data Protection Law](https://u.ae/en/about-the-uae/digital-uae/data/data-protection-laws)
- [Law No. 4/2022 — VARA (Dubai)](https://rulebooks.vara.ae/rulebook/law-no-4-2022-regulating-virtual-assets-emirate-dubai)
- [ADGM DLT Foundations Regulations 2023](https://www.adgm.com/media/announcements/adgm-introduces-the-worlds-first-dlt-foundations-regime)
- [CBUAE Payment Token Services Regulation 2024](https://www.centralbank.ae)
