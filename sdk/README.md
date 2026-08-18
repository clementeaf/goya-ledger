# goya-sdk

TypeScript SDK for Goya Ledger — deploy and sign legal contracts with post-quantum cryptography.

## Install

```bash
npm install goya-sdk
```

## Quick Start

```typescript
import { GoyaClient, generateKeypair } from 'goya-sdk'

const client = new GoyaClient('https://goya-node.fly.dev')

// Generate Ed25519 keypairs
const alice = await generateKeypair()
const bob = await generateKeypair()

// Register identities on-chain
await client.registerIdentity(alice)
await client.registerIdentity(bob)

// Deploy NDA from template
const contract = await client.deploy({
  template: 'nda',
  parties: {
    discloser: alice.did,
    recipient: bob.did,
  },
  payload: { scope: 'Project X' },
})

// Sign as both parties
await client.signWithKeypair(contract.id, alice, contract.content_hash)
await client.signWithKeypair(contract.id, bob, contract.content_hash)

// Check result
const result = await client.getContract(contract.id)
console.log(result.state) // 'fully_signed' or 'notarized'
```

## API

### `generateKeypair(): Promise<Keypair>`

Generate an Ed25519 keypair with a `did:goya:` identifier.

### `client.registerIdentity(keypair): Promise<void>`

Register a DID on the node's identity store.

### `client.deploy(request): Promise<LexContract>`

Deploy a contract. Accepts a full `ContractDefinition` or a template reference:

```typescript
// From template
await client.deploy({
  template: 'service_agreement',
  parties: { provider: alice.did, client: bob.did },
  payload: { terms: '6-month engagement' },
})

// Full definition
await client.deploy({
  type: 'custom_agreement',
  parties: [
    { role: 'seller', did: alice.did, signature_level: 'simple' },
    { role: 'buyer', did: bob.did, signature_level: 'advanced' },
  ],
  payload: { price: 50000 },
  require_notarization: true,
  deadline_secs: 259200, // 72 hours
  webhook_url: 'https://app.com/hooks',
})
```

### `client.signWithKeypair(contractId, keypair, contentHash, biometrics?): Promise<LexContract>`

Sign a contract with a keypair. Constructs the FES/FEA payload automatically.

For FEA (Advanced), pass biometric evidence:

```typescript
await client.signWithKeypair(contract.id, keypair, contract.content_hash, [
  {
    evidence_type: 'fingerprint',
    commitment: sha256hex(biometricTemplate),
    captured_at: Math.floor(Date.now() / 1000),
    capture_device: 'scanner-v2',
  },
])
```

### `client.sign(contractId, request): Promise<LexContract>`

Sign with a pre-computed signature (for ML-DSA-65 PQC signatures via `goya-sign` CLI).

### `client.getContract(id): Promise<LexContract>`

Get contract state including all signatures, TSA token, and block height.

### `client.listContracts(): Promise<LexContract[]>`

### `client.listTemplates(): Promise<ContractTemplate[]>`

## Built-in Templates

| Template | Roles | Signature | Notarization | Deadline |
|---|---|---|---|---|
| `nda` | discloser, recipient | FES | No | 7 days |
| `service_agreement` | provider, client | FES | Yes | 72 hours |
| `power_of_attorney` | grantor, attorney | FEA | Yes | 48 hours |

## PQC Signing (ML-DSA-65)

For post-quantum signatures, use the `goya-sign` CLI to generate keypairs and sign:

```bash
# Generate ML-DSA-65 keypair
goya-sign keygen ml-dsa-65

# Sign a payload
goya-sign sign ml-dsa-65 <private_key_hex> <payload>
```

Then pass the signature via `client.sign()`:

```typescript
await client.sign(contract.id, {
  did: 'did:goya:...',
  signature: mldsaSignatureHex,
  public_key: mldsaPublicKeyHex,
  biometric_evidence: [...],
})
```
