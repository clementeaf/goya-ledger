# Cross-Certification Strategy

**Document ID:** GOYA-XCERT-001
**Version:** 1.0
**Status:** Draft
**Last Updated:** 2026-08-05
**Owner:** PKI Administrator

## 1. Purpose

Define the strategy for establishing cross-certification relationships with external CAs and PSC providers, enabling Goya Ledger certificates to be trusted by third parties and vice versa.

## 2. Context

Cross-certification is required for:
- Interoperability with other Chilean PSC acreditados
- International recognition (DS 261/2019 — mutual recognition with Argentina)
- Integration with government PKI infrastructure (ClaveÚnica, Registro Civil)
- Trust chain bridging between Goya's post-quantum algorithms and legacy CAs

## 3. Cross-Certification Models

### 3.1 Bilateral Cross-Certification
Two CAs issue cross-certificates for each other's root. Each CA trusts the other's subscribers.

```
Goya Root CA ←→ External CA
     ↓                ↓
Goya Intermediate    External Intermediate
     ↓                ↓
Subscribers          Subscribers (mutually trusted)
```

**Use case:** Partnership with another Chilean PSC.

### 3.2 Bridge CA Model
A neutral bridge CA cross-certifies multiple CAs, creating a hub-and-spoke trust model.

```
        Bridge CA
       /    |    \
  Goya CA  PSC-A  PSC-B
```

**Use case:** Government-operated trust bridge for all Chilean PSC.

### 3.3 Trust List Inclusion
Goya's root certificate is included in a trusted list maintained by a government or industry body.

**Use case:** Entidad Acreditadora TSL inclusion after accreditation.

## 4. Prerequisites for Cross-Certification

| Requirement | Status | Notes |
|-------------|--------|-------|
| Accredited PSC status | Pending | Required before any cross-cert |
| CP/CPS published | Implemented | `src/pki_policy.rs`, API at `/policy/cp` |
| CRL in RFC 5280 format | Implemented | `src/msp/crl_rfc5280.rs` |
| OCSP responder operational | Implemented | `src/msp/ocsp.rs` |
| CA hierarchy (root + intermediate) | Implemented | `src/pki.rs` CaHierarchy |
| TSL published | Implemented | `src/tsl.rs`, API at `/tsl` |
| Key ceremony completed | Framework ready | `src/pki_ceremony.rs` |
| FIPS 140-3 validated module | Pending | Requires CMVP lab |
| RSA support for legacy interop | Not implemented | Ed25519/ML-DSA-65 only |

## 5. Target Cross-Certification Partners

### 5.1 Priority 1 — Chilean PSC Acreditados

| PSC | Services | Priority | Rationale |
|-----|----------|----------|-----------|
| E-CERTCHILE | FEA, TSA, Biometría | High | Largest market share |
| ACEPTA.COM | FEA, TSA, Firma Móvil | High | Broadest service set |
| E-SIGN | FEA, TSA, Biometría | Medium | Post-quantum interest |

### 5.2 Priority 2 — International

| Entity | Country | Framework |
|--------|---------|-----------|
| Argentine CAs | Argentina | DS 261/2019 mutual recognition |
| EU Qualified TSPs | EU | eIDAS cross-recognition |

### 5.3 Priority 3 — Government

| Entity | Purpose |
|--------|---------|
| ClaveÚnica | Citizen identity verification integration |
| Registro Civil | RUT verification for RA identity proofing |
| SII | Tax authority document signing |

## 6. Technical Requirements

### 6.1 Certificate Profile Alignment
- Cross-certificates must include `nameConstraints` to limit scope
- Policy mapping between Goya's CP OID and partner's CP OID
- `certificatePolicies` extension with both OIDs

### 6.2 Algorithm Interoperability

| Scenario | Goya Algorithm | Partner Algorithm | Bridge |
|----------|---------------|-------------------|--------|
| Legacy interop | Ed25519 | RSA-2048/4096 | Dual-signed cross-cert |
| PQ migration | ML-DSA-65 | Ed25519/RSA | Hybrid certificate |
| PQ-native | ML-DSA-65 | ML-DSA-65 | Direct cross-cert |

### 6.3 Revocation Interoperability
- Both parties must honor each other's CRL
- OCSP cross-queries for real-time status
- AIA (Authority Information Access) extensions pointing to partner's OCSP

## 7. Process for Establishing Cross-Certification

1. **Initiation:** Formal request between CAs with CP/CPS exchange
2. **Policy Review:** Compare CP/CPS for compatibility; identify policy mappings
3. **Technical Assessment:** Verify interoperability (algorithms, formats, revocation)
4. **Legal Agreement:** Cross-certification agreement covering liability, audit rights, termination
5. **Key Exchange:** Secure exchange of root certificates (in-person or witnessed ceremony)
6. **Cross-Certificate Issuance:** Each CA issues a cross-certificate for the other's root
7. **Publication:** Update TSL, CRL distribution points, and AIA extensions
8. **Testing:** End-to-end certificate chain validation from both sides
9. **Monitoring:** Ongoing compliance monitoring and annual review

## 8. Termination Procedures

1. 90-day advance written notice to partner
2. Revoke cross-certificate
3. Publish updated CRL within 1 hour
4. Update TSL to remove partner
5. Notify affected subscribers
6. Notify Entidad Acreditadora
7. Archive all cross-certification records (7-year retention)

## 9. Regulatory References

- Ley 19.799 Art. 14 — Mutual recognition of electronic signatures
- DS 261/2019 — Mutual recognition agreement with Argentina
- ETSI TS 102 042 §7.1.3 — Cross-certification policy
- RFC 4158 — Internet X.509 PKI: Certification Path Building
- RFC 5280 §4.2.1.4 — Certificate Policies extension

## 10. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-08-05 | PKI Administrator | Initial draft |
