# OID Registry — Goya Ledger

## Current OID namespace (placeholder)

All OIDs use the placeholder arc `1.3.6.1.4.1.99999` pending IANA PEN assignment.

| OID | Purpose | Source |
|-----|---------|--------|
| `1.3.6.1.4.1.99999` | Root arc | `src/pki_policy.rs:GOYA_OID_ROOT` |
| `1.3.6.1.4.1.99999.1.1` | TSA Policy | `src/pki_policy.rs:TSA_POLICY_OID` |
| `1.3.6.1.4.1.99999.2.1` | Certificate Policy (CP) | `src/pki_policy.rs:CP_OID` |
| `1.3.6.1.4.1.99999.2.2` | Certification Practice Statement (CPS) | `src/pki_policy.rs:CPS_OID` |
| `1.3.6.1.4.1.99999.3.1` | Signature Policy (Decreto 24) | `src/pki_policy.rs:SIGNATURE_POLICY_OID` |

## How to obtain a real PEN

IANA assigns Private Enterprise Numbers (PEN) under arc `1.3.6.1.4.1`.

1. Go to https://www.iana.org/assignments/enterprise-numbers/
2. Click "Request a PEN" or go directly to https://pen.iana.org/pen/PenApplication.page
3. Fill in:
   - **Company/Organization**: Goya Ledger (or your legal entity name)
   - **Contact name**: responsible person
   - **Contact email**: official email
   - **Description**: "Trust Service Provider for electronic signatures, PKI, and timestamping under Chilean Ley 19.799 and EU eIDAS"
4. Submit. Assignment typically takes 5-10 business days.
5. You will receive a number like `1.3.6.1.4.1.XXXXX`.

Cost: **free**.

## How to replace the placeholder

Once you receive your PEN (e.g., `1.3.6.1.4.1.61234`):

### Step 1: Update source constants

Edit `src/pki_policy.rs` — single file, 5 constants:

```rust
pub const GOYA_OID_ROOT: &str = "1.3.6.1.4.1.61234";
pub const CP_OID: &str = "1.3.6.1.4.1.61234.2.1";
pub const CPS_OID: &str = "1.3.6.1.4.1.61234.2.2";
pub const TSA_POLICY_OID: &str = "1.3.6.1.4.1.61234.1.1";
pub const SIGNATURE_POLICY_OID: &str = "1.3.6.1.4.1.61234.3.1";
```

### Step 2: Update TSA module

Edit `src/tsa/mod.rs`:

```rust
pub const TSA_POLICY_OID: &str = "1.3.6.1.4.1.61234.1.1";
```

### Step 3: Verify

```bash
grep -rn "99999" src/ --include="*.rs"   # should return 0 matches
cargo fmt --check
cargo clippy -- -D warnings
cargo test --lib
```

### Step 4: Update policy documents

```bash
find docs/policy/ -name "*.md" -exec sed -i '' 's/1\.3\.6\.1\.4\.1\.99999/1.3.6.1.4.1.61234/g' {} +
```

### Step 5: Re-issue certificates

All certificates issued with the placeholder OID are **invalid** for certification purposes. After replacing the PEN:

1. Execute key ceremony with the new OID
2. Re-issue CA certificates
3. Re-issue all subscriber certificates
4. Publish new CRL

## OID sub-arc structure

```
1.3.6.1.4.1.{PEN}
  .1       — Timestamping
    .1     — TSA Policy
  .2       — Certificates
    .1     — Certificate Policy (CP)
    .2     — Certification Practice Statement (CPS)
  .3       — Signatures
    .1     — Signature Policy (Decreto 24)
```

This structure allows future expansion (e.g., `.4` for OCSP policies, `.5` for RA policies) without conflicts.
