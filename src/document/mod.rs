//! Document integrity verification — canonical fingerprinting.
//!
//! Verifies **document identity**, not file identity. A re-exported PDF,
//! a printed-and-scanned copy, or a format-converted file can still be
//! verified as "the same document" if its content and structure match.
//!
//! The client decomposes a document into dimensions (text, structure,
//! tables, images) and hashes each one. The merkle root of all dimension
//! hashes becomes the `canonical_hash` — that is what gets signed and
//! stored on the ledger via the notarization API.

mod fingerprint;
pub mod pdf_parser;

pub use fingerprint::{DocumentFingerprint, VerificationVerdict};
