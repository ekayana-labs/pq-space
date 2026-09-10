//! Content keys wrapped with ML-KEM, delegated inside UCANs.
//!
//! Each blob is encrypted under a fresh 32 byte content key. Rather than
//! escrow that key with a custody service, it is wrapped to the
//! recipient's ML-KEM-1024 key (FIPS 203) and carried in the delegation's
//! `meta` map, so reading a blob needs both the delegation and the
//! decapsulation key.
//!
//! The wrap is ML-KEM-1024 encapsulation, HKDF-SHA256 under a domain
//! separating label, then AES-256-GCM. Its AAD binds the result to one
//! grant.

use std::collections::BTreeMap;

use aws_lc_rs::aead::{Aad, Nonce, RandomizedNonceKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::hkdf;
use aws_lc_rs::kem;
use pq_ucan::Ipld;

use crate::error::Error;

/// Length in bytes of the key a blob is encrypted under.
pub const CONTENT_KEY_LEN: usize = 32;

/// Length in bytes of an ML-KEM-1024 encapsulation key.
pub const ENCAPSULATION_KEY_LEN: usize = 1568;

/// The registered multicodec code of an ML-KEM-1024 encapsulation key
/// (`mlkem-1024-pub`).
pub const ML_KEM_1024_MULTICODEC: u64 = 0x120d;

/// Algorithm identifier recorded in the wire format.
pub const WRAP_ALGORITHM: &str = "ML-KEM-1024+HKDF-SHA256+A256GCM";

/// The `meta` key under which a wrapped content key rides in a UCAN
/// delegation.
pub const META_KEY: &str = "space/key";

/// The `did:bio` service type under which an owner publishes their
/// encapsulation key.
pub const SPACE_KEY_SERVICE_TYPE: &str = "SpaceEncapsulationKey";

const HKDF_INFO: &[u8] = b"pq-space/v1/content-key-wrap";
/// A recipient's ML-KEM-1024 key pair (FIPS 203).
///
/// The decapsulation key stays with its owner; only the encapsulation key
/// is shared.
#[derive(Debug)]
pub struct SpaceKeyPair {
    decapsulation_key: kem::DecapsulationKey,
}

impl SpaceKeyPair {
    /// Generate a fresh ML-KEM-1024 key pair.
    pub fn generate() -> Result<Self, Error> {
        let decapsulation_key =
            kem::DecapsulationKey::generate(&kem::ML_KEM_1024).map_err(|_| Error::Crypto)?;
        Ok(SpaceKeyPair { decapsulation_key })
    }

    /// Reconstruct from [`SpaceKeyPair::decapsulation_key_bytes`].
    pub fn from_decapsulation_key_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let decapsulation_key =
            kem::DecapsulationKey::new(&kem::ML_KEM_1024, bytes).map_err(|_| Error::Crypto)?;
        Ok(SpaceKeyPair { decapsulation_key })
    }

    /// The raw decapsulation key bytes. Secret, and the only thing that
    /// opens a wrap.
    pub fn decapsulation_key_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self
            .decapsulation_key
            .key_bytes()
            .map_err(|_| Error::Crypto)?
            .as_ref()
            .to_vec())
    }

    /// The raw encapsulation key bytes, 1568 of them, for whoever wraps.
    pub fn encapsulation_key_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self
            .decapsulation_key
            .encapsulation_key()
            .map_err(|_| Error::Crypto)?
            .key_bytes()
            .map_err(|_| Error::Crypto)?
            .as_ref()
            .to_vec())
    }
}
