//! `did:bio` principals for pq-ucan.
//!
//! pq-ucan carries any DID in any position of a chain and turns an issuer
//! into a key through its `Resolver` trait. A `did:bio` principal needs
//! two pieces: a [`BioSigner`] that signs with the subject key and names
//! the `did:bio` identifier as issuer, and a [`BioResolver`] that turns the
//! identifier back into that key. Ed25519 and ML-DSA-87 `did:key`
//! principals need nothing from this crate.

use pq_ucan::crypto::{
    ed25519::Ed25519Keypair, Algorithm, CryptoError, PublicKey, Signature, Signer,
};
use pq_ucan::did::{Did, KeyResolver, ResolveError, Resolver};
use pq_ucan::rng::CryptoRng;

use crate::error::Error;

pub use did_bio_core::{BioDid, Network};

/// The pq-ucan [`Did`] for a `did:bio` identifier.
pub fn did_of(bio: &BioDid) -> Result<Did, Error> {
    Did::parse(&bio.to_string())
        .map_err(|_| Error::InvalidPrincipal("did:bio identifier is not a DID"))
}

/// The `did:bio` identifier inside a pq-ucan [`Did`], if it is one.
#[must_use]
pub fn bio_of(did: &Did) -> Option<BioDid> {
    if did.method() != "bio" {
        return None;
    }
    BioDid::parse(did.base()).ok()
}

/// Resolves `did:bio` from the subject key inside the identifier, and
/// `did:key` through pq-ucan.
///
/// Generative resolution answers with the key the identifier was minted
/// from. A registered `did:bio` may have rotated since. Where that matters,
/// resolve the DID document through `did-bio-core` and build a resolver on
/// it.
#[derive(Debug, Clone, Copy, Default)]
pub struct BioResolver;

impl Resolver for BioResolver {
    fn resolve(&self, did: &Did) -> Result<PublicKey, ResolveError> {
        if did.method() != "bio" {
            return KeyResolver.resolve(did);
        }
        let bio = BioDid::parse(did.base())
            .map_err(|_| ResolveError::Failed("not a did:bio identifier".into()))?;
        PublicKey::new(Algorithm::Ed25519, &bio.subject)
            .map_err(|_| ResolveError::Failed("did:bio subject is not an Ed25519 key".into()))
    }
}

/// Signs as a `did:bio` identifier with its Ed25519 subject key.
#[derive(Debug)]
pub struct BioSigner {
    bio: BioDid,
    did: Did,
    key: Ed25519Keypair,
}

impl BioSigner {
    /// The identity `key` mints on `network`.
    pub fn new(network: Network, key: Ed25519Keypair) -> Result<Self, Error> {
        let subject = key
            .public_key()
            .as_bytes()
            .try_into()
            .map_err(|_| Error::InvalidPrincipal("subject key is not 32 bytes"))?;
        let bio = BioDid::new(network, subject);
        let did = did_of(&bio)?;
        Ok(BioSigner { bio, did, key })
    }

    /// From a 32 byte seed. Deterministic.
    pub fn from_seed(network: Network, seed: &[u8; 32]) -> Result<Self, Error> {
        Self::new(network, Ed25519Keypair::from_seed(seed))
    }

    /// A fresh identity on `network`.
    pub fn generate<R: CryptoRng + ?Sized>(network: Network, rng: &mut R) -> Result<Self, Error> {
        Self::new(network, Ed25519Keypair::generate(rng))
    }

    /// The `did:bio` identifier.
    #[must_use]
    pub const fn bio(&self) -> &BioDid {
        &self.bio
    }

    /// The network the identifier names.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.bio.network
    }
}

impl Signer for BioSigner {
    fn public_key(&self) -> &PublicKey {
        self.key.public_key()
    }

    fn sign(&self, message: &[u8]) -> Result<Signature, CryptoError> {
        self.key.sign(message)
    }

    fn did(&self) -> Did {
        self.did.clone()
    }
}
