# GOYA Ledger

[![CI](https://github.com/clementeaf/goya-ledger/actions/workflows/ci.yml/badge.svg)](https://github.com/clementeaf/goya-ledger/actions/workflows/ci.yml)

Blockchain platform with post-quantum cryptography. Create digital identities, notarize documents, and verify proofs — all from a desktop app.

## Download

| Platform | Download |
|----------|----------|
| macOS (Apple Silicon) | [GOYA-ledger_0.2.0_aarch64.dmg](https://github.com/clementeaf/goya-ledger/releases/tag/v0.2.0) |
| Windows | Coming soon |

## What can you do?

### 1. Create a digital identity
Generate a `did:goya:` decentralized identity with Ed25519 signing. Your private key is encrypted locally with Argon2id + AES-256-GCM — it never leaves your machine.

### 2. Notarize documents
Drag and drop any file. The app computes its SHA-256 hash locally, signs it with your identity, and registers the proof on the GOYA blockchain. The document itself is never uploaded.

### 3. Verify document proofs
Paste a hash to check if it was notarized — get timestamp, signer, and block height.

## How it works

```
Your Mac                           GOYA Network
┌──────────────┐                  ┌──────────────┐
│ Desktop App  │───HTTPS/TLS────▶│  Seed Node   │
│              │                  │  (Fly.io)    │
│ • Identity   │                  │              │
│ • Notarize   │                  │ • Consensus  │
│ • Verify     │                  │ • Storage    │
│              │                  │ • API        │
│ Keys stored  │                  │              │
│ locally in   │                  │ RocksDB      │
│ ~/.goya/     │                  │ persistent   │
└──────────────┘                  └──────────────┘
```

## For developers

### Run a local node

```bash
cargo run --bin rust-bc    # API on :8080, P2P on :8081
```

### Build the desktop app

```bash
cd tauri-app && cargo tauri build
```

### Run tests

```bash
cargo test --lib           # Unit tests
cargo test                 # All tests
```

### API

66+ REST endpoints under `/api/v1`. Key endpoints for the free service:

| Endpoint | Description |
|----------|-------------|
| `POST /api/v1/notarize` | Register a signed document hash |
| `GET /api/v1/notarize/verify/{hash}` | Verify a document hash |
| `GET /api/v1/health` | Node health and chain height |
| `GET /api/v1/accounts/{address}` | Account balance and nonce |

### Architecture

Rust/Actix-Web 4 blockchain node with DAG + HotStuff BFT + DPoS consensus. Post-quantum crypto via ML-DSA-65 (FIPS 204). See [`docs/`](docs/) for full architecture and API reference.

## License

[MIT](LICENSE)
