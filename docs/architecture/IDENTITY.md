# Identity Architecture

Digital identity subsystem: DIDs, credentials, key management, and authentication.

## Module Map

```
src/identity/
├── did.rs            DID derivation: did:goya:{pubkey_hex[..16]}
├── signing.rs        SigningProvider trait + 5 algorithms
├── keys.rs           KeyManager: rotation, migration, DID chain
├── key_recovery.rs   Shamir SSS over GF(256), zero dependencies
├── dual_signing.rs   Classical + PQC dual signatures (migration)
├── hsm.rs            PKCS#11 HSM provider (feature-gated)
├── sd_jwt.rs         SD-JWT VC (RFC 9901 + key binding)
├── mdoc.rs           ISO 18013-5 mDL/PID credentials
├── status_list.rs    IETF Token Status List (revocation)
├── attestation.rs    EUDI ARF v3.0 attestation types
├── ra.rs             Registration Authority (multi-jurisdiction)
├── pqc_policy.rs     PQC enforcement + tag forgery prevention
├── zkp.rs            Commitment proofs (not ZKP — documented)
└── mod.rs            Module re-exports
```

## DID Scheme

Format: `did:goya:{pubkey_hex[..16]}`

- Deterministic: derived from first 8 bytes of public key hex
- Self-verifying: `did_matches_pubkey(did, pubkey_hex)` confirms ownership
- Single method (`did:goya:`), no DID method resolution infrastructure

Canonical derivation: `identity::did::did_from_pubkey_hex()`. All DID generation must use this function.

## Signing Algorithms

| Algorithm | Standard | PK Size | Sig Size | Use |
|-----------|----------|---------|----------|-----|
| Ed25519 | RFC 8032 | 32 B | 64 B | Default, classical |
| ML-DSA-65 | FIPS 204 | 1952 B | 3309 B | Post-quantum primary |
| SLH-DSA-128s | FIPS 205 | 32 B | 7856 B | PQC backup (stateless) |
| RSA-2048 | PKCS#1 v1.5 | 256 B | 256 B | Legacy interop |
| ECDSA P-256 | NIST SP 800-186 | 33/65 B | 64 B | eIDAS / WebAuthn |

All algorithms implement `SigningProvider` trait: `sign()`, `verify()`, `public_key()`, `algorithm()`.

FIPS 140-3 Known Answer Tests run at startup via `run_crypto_self_tests()`.

## Key Lifecycle

```
generate → active → rotate_key (same algo)
                  → rotate_algorithm (cross-algo, e.g. Ed25519 → ML-DSA-65)
                  → migrate_identity (new DID, old DID marked "migrated")
                  → split (Shamir SSS for backup)
```

- `KeyManager` tracks active + retired keys with timestamps
- `migrate_identity()` writes migration chain in store: old DID → "migrated", new DID → "active" with `migrated_from`
- `resolve_identity()` follows migration chain to find current active DID
- `key_recovery::split(secret, threshold, total)` produces N shares; any K reconstruct via Lagrange interpolation over GF(256)

### HSM Support

Behind `hsm` feature flag. `HsmSigningProvider` wraps PKCS#11:
- Config via env vars: `HSM_PKCS11_LIB`, `HSM_SLOT_ID`, `HSM_PIN`, `HSM_KEY_LABEL`
- `SimulatedHsmProvider` for testing without hardware
- Session management: open/close/reopen with PIN

## Credential Formats

### SD-JWT VC (RFC 9901)

- Selective disclosure via SHA-256 disclosure hashing
- Holder key binding: `cnf.jkt` (JWK thumbprint, RFC 7638)
- KB-JWT verification with `sd_hash` binding
- JWT algorithm mapping for all 5 signing algorithms

### mdoc (ISO 18013-5)

- CBOR-encoded Mobile Security Object with per-element SHA-256 digests
- COSE_Sign1 issuer authentication
- Device authentication via `DeviceAuth` + `SessionTranscript`
- Selective disclosure by namespace/element

### Revocation

IETF Token Status List (draft-ietf-oauth-status-list):
- 2-bit per entry: Valid (0x00), Invalid (0x01), Suspended (0x02)
- Random index allocation (prevents correlation)
- JWT-signed status list with ZLIB compression
- SHA-256 anchor hash for DLT anchoring

## Authentication

### DID Auth (challenge-response)

```
Client                          Server
  │                                │
  ├─ POST /identity/auth/challenge │
  │  { did }                       │
  │                                ├─ verify DID exists
  │                ← challenge ────┤  generate nonce (UUID v4)
  │                                │  store with 5 min TTL
  │                                │
  ├─ POST /identity/auth/verify    │
  │  { did, challenge, signature } │
  │                                ├─ remove nonce (single-use)
  │                                ├─ read IdentityRecord
  │                                ├─ verify signature vs public_key
  │          ← authenticated ──────┤
```

- Algorithm resolved from `IdentityRecord.signature_algorithm`
- Supports Ed25519 and ML-DSA-65

### ACL System

`src/acl/` — resource-based access control enforced via `enforce_acl()` on protected endpoints.

## W3C Interoperability

### DID Resolution

`GET /api/v1/did/{did}` returns W3C DID Core compliant document:

- `@context` includes algorithm-appropriate security suite
- `verificationMethod` with correct type per algorithm
- `authentication` and `assertionMethod` as references
- Content-Type: `application/did+ld+json`

### VC Export

`GET /api/v1/credentials/{id}/vc` returns W3C VC Data Model 2.0:

- Proof type resolved from issuer's `signature_algorithm`
- `proofPurpose: assertionMethod`

## Registration Authority

Multi-jurisdiction identity proofing in `ra.rs`:

| Jurisdiction | Validation | Standard |
|-------------|------------|----------|
| Chile | RUT modulo 11 | Ley 19.799 |
| UAE | Emirates ID + Luhn | Federal Law No. 46/2021 |
| EU | eIDAS LoA (Low/Substantial/High) | eIDAS Art. 24 |

External verification via `IdentityVerificationProvider` trait. Smart-ID integration for Estonian e-ID.

## EUDI Compliance

`attestation.rs` implements ARF v3.0:
- Attestation types: PID, EAA, QEAA, PuB-EAA
- Issuer roles: PidProvider, TSP, QTSP, PublicBody
- PID prerequisite enforcement (CIR 2024/2977)
- Fail-closed 6-step authorization check

## Storage

`IdentityRecord` in `storage/traits.rs`:

| Field | Type | Description |
|-------|------|-------------|
| did | String | `did:goya:{...}` |
| public_key | String | Hex-encoded public key |
| signature_algorithm | Option\<String\> | Ed25519, MlDsa65, etc. |
| status | String | active, migrated, revoked |
| migrated_from | Option\<String\> | Previous DID (migration chain) |
| created_at | u64 | Unix timestamp |
| updated_at | u64 | Unix timestamp |

Light client: `LocalIdentityStore` persists identities as JSON in `~/.goya/identities.json`.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /identity/create | Create DID + keypair |
| GET | /identity/{did} | Fetch identity |
| POST | /identity/{did}/rotate-key | Key rotation |
| POST | /identity/{did}/verify-signature | Verify signature |
| POST | /identity/{did}/migrate | PQC migration |
| POST | /identity/auth/challenge | DID Auth: get nonce |
| POST | /identity/auth/verify | DID Auth: verify signature |
| GET | /did/{did} | W3C DID Resolution |
| POST | /credentials/issue | Issue credential |
| GET | /credentials/{id} | Fetch credential |
| GET | /credentials/{id}/vc | W3C VC export |
| POST | /credentials/{id}/verify | Verify credential |
| POST | /credentials/{id}/revoke | Revoke credential |

OpenID4VCI and OpenID4VP endpoints in `oid4vci.rs` and `oid4vp.rs`.

## Stats

- 14 source files, ~7000 lines
- 285 unit tests in identity module
- 5 cryptographic algorithms with FIPS KAT
- 3 credential formats (SD-JWT VC, mdoc, status list)
- 3 jurisdictions (Chile, UAE, EU)
