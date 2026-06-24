//! Light client — enables resource-constrained devices (IoT, mobile) to
//! verify blockchain state without running a full node.
//!
//! A light client tracks block headers and validates Merkle proofs against
//! them, trusting the BFT quorum for header authenticity.

pub mod client;
pub mod header;
pub mod local_store;
pub mod mode;
pub mod proxy;
