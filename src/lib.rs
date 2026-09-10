//! Post-quantum private space primitives for storage built on UCAN.
//!
//! Two pieces that travel together in one delegation:
//!
//! 1. [`BioSigner`] and [`BioResolver`], which let a `did:bio` identity
//!    issue and verify pq-ucan tokens in a chain with Ed25519 and ML-DSA-87
//!    (FIPS 204) `did:key` principals.
//! 2. [`WrappedContentKey`], a blob's encryption key encapsulated to the
//!    recipient's ML-KEM-1024 key (FIPS 203) and carried in the
//!    delegation's `meta` map under [`META_KEY`], so no custody service
//!    sits in the path.
//!

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;

pub use error::Error;
