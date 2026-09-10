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
//! ```
//! use pq_space::{space_aad, BioResolver, BioSigner, Network, SpaceKeyPair, WrappedContentKey};
//! use pq_ucan::{
//!     command::Command,
//!     crypto::{ml_dsa::MlDsaKeypair, Algorithm, Signer},
//!     delegation::{Delegation, Subject},
//!     nonce::Nonce,
//!     time::Timestamp,
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let researcher = BioSigner::from_seed(Network::Devnet, &[5; 32])?;
//! let device = MlDsaKeypair::from_seed(Algorithm::MlDsa87, &[6; 32])?;
//! let device_kem = SpaceKeyPair::generate()?;
//!
//! let space = researcher.did();
//! let aad = space_aad(space.as_str(), "/space/blob/get");
//! let wrapped =
//!     WrappedContentKey::wrap(&device_kem.encapsulation_key_bytes()?, &[42; 32], &aad)?;
//! let mut meta = std::collections::BTreeMap::new();
//! wrapped.attach_to_meta(&mut meta);
//!
//! let delegation =
//!     Delegation::builder(device.did(), Subject::Did(space), Command::parse("/space/blob/get")?)
//!         .meta(meta)
//!         .nonce(Nonce::from_bytes(&[1; 12]))
//!         .expires_at(Timestamp::from_unix(1_800_000_000)?)
//!         .sign(&researcher)?;
//!
//! delegation.verify(&BioResolver)?;
//! let carried = WrappedContentKey::from_meta(delegation.meta()).expect("attached")?;
//! assert_eq!(carried.unwrap_key(&device_kem, &aad)?, [42; 32]);
//! # Ok(())
//! # }
//! ```

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
    decode_encapsulation_key, encode_encapsulation_key, space_aad, SpaceKeyPair, WrappedContentKey,
    CONTENT_KEY_LEN, ENCAPSULATION_KEY_LEN, META_KEY, ML_KEM_1024_MULTICODEC,
    SPACE_KEY_SERVICE_TYPE, WRAP_ALGORITHM,
};
