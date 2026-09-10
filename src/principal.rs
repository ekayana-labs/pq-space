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

#[cfg(test)]
mod tests {
    use pq_ucan::crypto::ml_dsa::MlDsaKeypair;
    use testresult::TestResult;

    use super::*;

    #[test]
    fn signer_names_its_did_and_the_resolver_finds_its_key() -> TestResult {
        let signer = BioSigner::from_seed(Network::Devnet, &[5u8; 32])?;
        let did = signer.did();
        assert!(did.as_str().starts_with("did:bio:devnet:"));
        assert_eq!(signer.network(), Network::Devnet);
        assert_eq!(bio_of(&did).as_ref(), Some(signer.bio()));
        assert_eq!(did_of(signer.bio())?, did);
        assert_eq!(&BioResolver.resolve(&did)?, signer.public_key());

        // Mainnet identifiers carry no network segment.
        let mainnet = BioSigner::from_seed(Network::Mainnet, &[5u8; 32])?;
        assert_eq!(mainnet.did().as_str().matches(':').count(), 2);
        assert_eq!(
            bio_of(&mainnet.did()).map(|b| b.network),
            Some(Network::Mainnet)
        );
        Ok(())
    }

    #[test]
    fn a_signature_verifies_under_the_resolved_key() -> TestResult {
        let signer = BioSigner::from_seed(Network::Devnet, &[5u8; 32])?;
        let signature = signer.sign(b"msg")?;
        let key = BioResolver.resolve(&signer.did())?;
        key.verify(b"msg", &signature)?;
        assert!(key.verify(b"other", &signature).is_err());
        Ok(())
    }

    #[test]
    fn did_key_still_resolves_through_the_bio_resolver() -> TestResult {
        let classical = Ed25519Keypair::from_seed(&[6u8; 32]);
        assert_eq!(
            &BioResolver.resolve(&classical.did())?,
            classical.public_key()
        );
        let quantum = MlDsaKeypair::from_seed(Algorithm::MlDsa87, &[7u8; 32])?;
        assert_eq!(&BioResolver.resolve(&quantum.did())?, quantum.public_key());
        Ok(())
    }

    #[test]
    fn rejects_what_it_cannot_resolve() -> TestResult {
        let web = Did::parse("did:web:example.com")?;
        assert!(matches!(
            BioResolver.resolve(&web),
            Err(ResolveError::UnsupportedMethod)
        ));
        let short = Did::parse("did:bio:devnet:short")?;
        assert!(matches!(
            BioResolver.resolve(&short),
            Err(ResolveError::Failed(_))
        ));
        assert_eq!(bio_of(&short), None);
        assert_eq!(bio_of(&web), None);
        Ok(())
    }
}
