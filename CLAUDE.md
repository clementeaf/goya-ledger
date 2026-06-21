# CLAUDE.md

## Pre-commit quality gate

**All three must pass before every commit.**

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test --lib
```

If any integration test file was modified, also run `cargo test --test <test_name>`.

## Commands

```bash
cargo build                          # Build
cargo test                           # All tests
cargo test --lib storage             # Module tests
cargo test --test bft_e2e            # BFT E2E tests
cargo test -- --nocapture            # With stdout
cargo run --bin rust-bc              # Start server (API :8080, P2P :8081)
cargo clippy -- -D warnings          # Lint
cargo fmt                            # Format
./scripts/try-it.sh                  # Interactive demo
```

## Architecture

Blockchain node (Rust/Actix-Web 4) with HTTP API.

- **Storage** (`src/storage/`): `BlockStore` trait — `MemoryStore` and `RocksDbBlockStore`. Selected via `STORAGE_BACKEND`.
- **Consensus** (`src/consensus/`): DAG + HotStuff BFT + DPoS.
- **Identity** (`src/identity/`): DID + pluggable signing (`Ed25519`, `ML-DSA-65`).
- **API** (`src/api/`): All endpoints under `/api/v1` via `ApiRoutes::register`. Handler modules in `src/api/handlers/`. Response envelope: `ApiResponse<T>` with trace ID. ACL via `enforce_acl`. `api_legacy.rs` only provides the `config_routes` entry point.
- **Crypto** (`crates/pqc_crypto_module/`): FIPS-oriented crate. Direct imports of `sha2`, `ed25519_dalek`, etc. in `src/` are forbidden.
- **Network** (`src/network/`): P2P over TCP/TLS. Flow: `SubmitTransaction` → `OrderedBlock` → `StateRequest/StateResponse`. Push-gossip for block propagation.

Other subsystems: bridge, governance, EVM (revm), chaincode, channels, oracles, compliance, tokenomics, intelligence, light client, audit. See `docs/architecture/`.

## Key conventions

- Nightly toolchain (`rust-toolchain.toml`).
- RocksDB keys: zero-padded 12 digits. Secondary index: `{:012}:{id}`.
- Signatures: `Vec<u8>` (not `[u8; 64]`) — supports Ed25519 (64B) and ML-DSA-65 (3309B). Hex-serialized via `vec_hex`.
- Every signed struct carries `signature_algorithm: SigningAlgorithm` with `#[serde(default)]`.
- Crypto boundary enforced by `cargo test --test crypto_boundary`.
- `tempfile::TempDir` for RocksDB test fixtures.

## Configuration

Environment variables control runtime behavior. See [`docs/api/configuration-guide.md`](docs/api/configuration-guide.md).

Essential: `STORAGE_BACKEND`, `ACL_MODE`, `SIGNING_ALGORITHM`, `NETWORK_ID`, `API_PORT`, `P2P_PORT`.

Production (`RUST_BC_ENV=production`): requires `TLS_CERT_PATH`/`TLS_KEY_PATH`, warns on `ACL_MODE=permissive`. Audit log persists to RocksDB when `STORAGE_BACKEND=rocksdb`.

Other: `CORS_ALLOWED_ORIGINS`, `LOG_FORMAT` (`json` for structured), `HTTP_REQUEST_TIMEOUT_SECS`, `MEMPOOL_MAX_SIZE`, `RATE_LIMIT_RPS/RPM/RPH`.

## Deployment

See [`docs/api/DEPLOYMENT.md`](docs/api/DEPLOYMENT.md).

```bash
docker compose up -d          # Multi-node network
./scripts/sandbox.sh          # Sandbox with tunnels
./scripts/bcctl.sh status     # Operator CLI
./scripts/e2e-test.sh         # 71 E2E assertions
```

## Documentation

| Directory | Contents |
|---|---|
| `docs/api/` | API reference, configuration, deployment |
| `docs/architecture/` | Core architecture, benchmarks, security audits |
| `docs/compliance/` | FIPS 140, certification roadmap, PQC enterprise |
| `docs/commercial/` | Enterprise docs, impact studies |
| `docs/dev/` | Developer onboarding, branching strategy |
