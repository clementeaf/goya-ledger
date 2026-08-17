# Goya Ledger: First Post-Quantum DLT with EUDI Wallet Credential Issuance

**Date:** August 17, 2026
**Author:** Goya Ledger Project
**Status:** Verified — live demonstration

---

## Claim

> Until August 2026, and based on the publicly verifiable state of the art, Goya Ledger is the first DLT with post-quantum capability (FIPS 204 / ML-DSA-65) to publicly demonstrate the successful issuance of a verifiable credential (OID4VCI 1.0) directly to the iOS reference implementation of the EU Digital Identity Wallet.

## Evidence

| Artifact | URL / Reference |
|---|---|
| Issuer metadata | `https://goya-node.fly.dev/.well-known/openid-credential-issuer` |
| OAuth AS metadata | `https://goya-node.fly.dev/.well-known/oauth-authorization-server` |
| JWKS (issuer public key) | `https://goya-node.fly.dev/.well-known/jwt-vc-issuer` |
| Credential format | `dc+sd-jwt` (OID4VCI 1.0 Final) |
| Signing algorithm | ES256 (ECDSA P-256) for EUDI interop; ML-DSA-65 (FIPS 204) available |
| Wallet app | `eu-digital-identity-wallet/eudi-app-ios-wallet-ui` (official EU reference) |
| VCI library | `eu-digital-identity-wallet/eudi-lib-ios-openid4vci-swift` v0.51.0 |
| Wallet Kit | `eu-digital-identity-wallet/eudi-lib-ios-wallet-kit` v0.37.6 |
| Credential type | `urn:eudi:pid:1` (PID — Person Identification Data) |
| Grant type | `urn:ietf:params:oauth:grant-type:pre-authorized_code` |
| Proof type | `attestation` (device-bound key attestation) |

## Competitive Landscape Analysis

### 1. EBSI — European Blockchain Services Infrastructure

- **Operator:** European Commission
- **Crypto:** ECDSA (secp256k1, P-256) — conventional
- **PQC:** None
- **EUDI Wallet interop:** Yes (same ecosystem), but not post-quantum
- **Source:** https://ec.europa.eu/digital-building-blocks/sites/display/EBSI

### 2. QANplatform

- **Claim:** "Quantum-resistant Layer 1 blockchain"
- **Crypto:** Lattice-based (CRYSTALS-Dilithium referenced), not NIST FIPS 204 certified
- **OID4VCI:** No implementation found
- **EUDI Wallet interop:** No public demonstration
- **Source:** https://qanplatform.com

### 3. IOTA / Shimmer

- **Focus:** DAG-based DLT, identity (IOTA Identity)
- **Crypto:** Ed25519 — conventional
- **PQC:** Research only (IOTA 2.0 mentions PQC as future goal)
- **EUDI Wallet interop:** No public OID4VCI demonstration
- **Source:** https://wiki.iota.org

### 4. Hyperledger Aries / Indy / AnonCreds

- **Focus:** Mature SSI/VC ecosystem
- **Crypto:** Ed25519, BLS12-381 — conventional
- **PQC:** None in production
- **OID4VCI 1.0:** Partial (Aries RFC, not OID4VCI 1.0 Final)
- **EUDI Wallet interop:** No direct EUDI reference wallet demonstration
- **Source:** https://www.hyperledger.org/projects/aries

### 5. EU Large Scale Pilots (LSPs)

| Pilot | PQC | Notes |
|---|---|---|
| POTENTIAL | No | ES256 / EdDSA only |
| NOBID | No | Nordic/Baltic pilot, conventional crypto |
| EWC (EU Digital Identity Wallet Consortium) | No | Conventional PKI |
| DC4EU | No | Cross-border services, no PQC |

- **Source:** https://digital-strategy.ec.europa.eu/en/policies/eudi-wallet-toolbox

### 6. Other Post-Quantum Projects

| Project | DLT | OID4VCI | EUDI Wallet |
|---|---|---|---|
| QRL (Quantum Resistant Ledger) | Yes (XMSS) | No | No |
| NIST PQC participants | N/A (standards body) | N/A | N/A |
| Post-Quantum (company) | No (VPN/TLS focus) | No | No |
| IBM Quantum Safe | No (enterprise tooling) | No | No |

### 7. EUDI Issuer Reference Implementations

| Issuer | Operator | PQC | DLT |
|---|---|---|---|
| issuer.eudiw.dev | EU Commission | No (ES256) | No |
| issuer-backend.eudiw.dev | EU Commission | No (ES256) | No |
| National pilots (DE, FR, ES, etc.) | Governments | No | No |

## Technical Implementation

### Protocol Flow (Verified Working)

```
1. QR Scan
   openid-credential-offer://?credential_offer={...}
        ↓
2. Metadata Resolution
   GET /.well-known/openid-credential-issuer → 200
   GET /.well-known/oauth-authorization-server → 200
        ↓
3. Token Exchange (pre-authorized code)
   POST /token → 200 {access_token, expires_in}
        ↓
4. Nonce Acquisition
   POST /nonce → 200 {c_nonce}
        ↓
5. Credential Request (with attestation proof)
   POST /credential → 200 {credential: "<sd-jwt>"}
        ↓
6. Credential Storage
   EUDI Wallet validates:
   ✓ cnf binding key matches device key
   ✓ iss matches credential_issuer
   ✓ kid resolves via /.well-known/jwt-vc-issuer JWKS
   ✓ ES256 signature verified
   ✓ Credential stored in wallet
```

### SD-JWT VC Structure (Issued by Goya)

```
Header:  {"alg":"ES256", "typ":"dc+sd-jwt", "kid":"<key-id>"}
Payload: {
  "iss": "https://goya-node.fly.dev",
  "sub": "holder",
  "iat": <timestamp>,
  "exp": <timestamp>,
  "vct": "urn:eudi:pid:1",
  "_sd_alg": "sha-256",
  "_sd": [...],
  "cnf": {"jwk": {"kty":"EC","crv":"P-256","x":"...","y":"..."}}
}
Signature: <ES256>
~<disclosure1>~<disclosure2>~...~
```

### Post-Quantum Capability

Goya Ledger supports ML-DSA-65 (FIPS 204) as its primary signing algorithm. For EUDI Wallet interop, ES256 is used because the current EUDI reference implementation does not yet support ML-DSA-65 signature verification.

The dual-algorithm architecture allows:
- **ES256** for current EUDI Wallet compatibility
- **ML-DSA-65** for quantum-safe credential issuance (future wallet support)
- Runtime selection via `SIGNING_ALGORITHM` environment variable

```
SIGNING_ALGORITHM=ecdsa-p256  → ES256 (EUDI interop)
SIGNING_ALGORITHM=ml-dsa-65   → ML-DSA-65 (post-quantum, default)
```

## Standards Compliance

| Standard | Status |
|---|---|
| OID4VCI 1.0 Final | ✓ Compliant |
| SD-JWT VC (dc+sd-jwt) | ✓ Compliant |
| RFC 9449 (DPoP) | ✓ Supported |
| RFC 7638 (JWK Thumbprint) | ✓ Used for kid |
| FIPS 204 (ML-DSA-65) | ✓ Implemented |
| eIDAS 2.0 (ARF) | ✓ PID credential type |
| ETSI TS 119 612 (Trusted Lists) | ◐ Partial (not registered) |

## Jurisdictional Coverage

| Jurisdiction | Legal Framework | Status |
|---|---|---|
| European Union | eIDAS 2.0 | Technical interop demonstrated |
| Chile | Ley 19.799 (Firma Electrónica) | Native jurisdiction |
| UAE | Federal Decree-Law No. 46/2021 | Regulatory framework mapped |

## Methodology

This analysis was conducted by:

1. Searching public repositories of the `eu-digital-identity-wallet` GitHub organization for PQC references
2. Reviewing documentation and press releases of known post-quantum blockchain projects
3. Examining the EU LSP pilot specifications for cryptographic algorithm support
4. Verifying the absence of ML-DSA-65 / CRYSTALS-Dilithium / FIPS 204 in any known OID4VCI issuer
5. Live testing the full OID4VCI flow against the EUDI reference wallet iOS app

**Limitation:** This analysis covers publicly available information as of August 2026. Private or classified implementations by EU member states are not included.

## Conclusion

No other DLT project has publicly demonstrated the combination of:

1. Post-quantum cryptographic capability (NIST FIPS 204 / ML-DSA-65)
2. OID4VCI 1.0 compliance
3. Successful credential issuance to the official EU Digital Identity Wallet reference implementation
4. Live, publicly accessible issuer endpoint

Goya Ledger is, to the best of publicly verifiable knowledge, the first to achieve this milestone.
