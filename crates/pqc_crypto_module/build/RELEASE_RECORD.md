# Release Record — pqc_crypto_module v0.1.0

> Generated: 2026-06-18

---

## Artifact Identification

| Field | Value |
|---|---|
| Version | 0.1.0 |
| Git commit | `24cfef531b91b5a72009e3c3ec40e32d6f35ac36` |
| Artifact | `target/release/libpqc_crypto_module.rlib` |
| Artifact SHA-256 | `06f87b7a985506e57a881ce702d8965c93f1c93a87f755279c827d869bfbe34b` |
| Cargo.lock SHA-256 | `43aefa0deb019219848e3121951ccb8b9d28869591737f589a4665ca264f069b` |

## Build Environment

| Field | Value |
|---|---|
| Rust toolchain | `nightly-2026-04-20` |
| Compiler | `rustc 1.97.0-nightly (e22c616e4 2026-04-19)` |
| LLVM | 22.1.2 |
| Host | `aarch64-apple-darwin` |
| OS | Darwin 25.5.0 arm64 |
| Build date (UTC) | 2026-06-18T14:18:20Z |
| Build command | `RUSTFLAGS="" cargo build --release -p pqc_crypto_module` |

## Reproducibility

Two independent clean builds (`cargo clean && cargo build --release`) produced identical artifact hashes:

- Build 1: `06f87b7a985506e57a881ce702d8965c93f1c93a87f755279c827d869bfbe34b`
- Build 2: `06f87b7a985506e57a881ce702d8965c93f1c93a87f755279c827d869bfbe34b`

## Test Results

| Suite | Result |
|---|---|
| `cargo test --lib` | 1727 passed, 0 failed |
| `cargo test --test crypto_boundary` | 5 passed, 0 failed |
| `cargo test -p pqc_crypto_module` | See module test section |
| `cargo clippy -- -D warnings` | Clean (0 warnings) |
| `cargo fmt --check` | Clean (no diff) |

## FIPS Classification

Non-crypto-affecting (documentation-only release record).
