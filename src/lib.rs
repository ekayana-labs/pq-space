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
pub mod principal;
pub mod space;

pub use did_bio_core;
pub use pq_ucan;

pub use error::Error;
pub use principal::{bio_of, did_of, BioDid, BioResolver, BioSigner, Network};
pub use space::{
    SpaceKeyPair, CONTENT_KEY_LEN, ENCAPSULATION_KEY_LEN, META_KEY, ML_KEM_1024_MULTICODEC,
    SPACE_KEY_SERVICE_TYPE, WRAP_ALGORITHM,
};
