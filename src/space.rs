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

    /// The encapsulation key in the form a DID document carries under
    /// [`SPACE_KEY_SERVICE_TYPE`].
    pub fn encapsulation_key_multibase(&self) -> Result<String, Error> {
        Ok(encode_encapsulation_key(&self.encapsulation_key_bytes()?))
    }
}

/// Append `value` to `out` as an unsigned varint (multiformats LEB128).
fn write_uvarint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Read an unsigned varint, returning the value and its length.
fn read_uvarint(bytes: &[u8]) -> Result<(u64, usize), Error> {
    for (i, &byte) in bytes.iter().enumerate().take(9) {
        if byte & 0x80 == 0 {
            let mut value: u64 = 0;
            for (j, &b) in bytes[..=i].iter().enumerate() {
                value |= u64::from(b & 0x7f) << (7 * j);
            }
            return Ok((value, i + 1));
        }
    }
    Err(Error::Encoding("malformed multicodec varint"))
}

/// Encode an ML-KEM-1024 encapsulation key as base58btc over its
/// multicodec prefix, the shape a `Multikey` uses.
///
/// ```
/// use pq_space::{encode_encapsulation_key, ENCAPSULATION_KEY_LEN};
///
/// let encoded = encode_encapsulation_key(&[0u8; ENCAPSULATION_KEY_LEN]);
/// assert!(encoded.starts_with('z'));
/// ```
#[must_use]
pub fn encode_encapsulation_key(key: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(2 + key.len());
    write_uvarint(&mut bytes, ML_KEM_1024_MULTICODEC);
    bytes.extend_from_slice(key);
    format!("z{}", bs58::encode(bytes).into_string())
}

/// Decode what [`encode_encapsulation_key`] produced.
///
/// The length check is not redundant: ML-KEM would otherwise reject a
/// malformed key at encapsulation time, far from where it was read.
pub fn decode_encapsulation_key(multibase: &str) -> Result<Vec<u8>, Error> {
    let encoded = multibase
        .strip_prefix('z')
        .ok_or(Error::Encoding("expected multibase `z` (base58btc)"))?;
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| Error::Encoding("invalid base58btc payload"))?;
    let (code, consumed) = read_uvarint(&bytes)?;
    if code != ML_KEM_1024_MULTICODEC {
        return Err(Error::Encoding("not an mlkem-1024-pub multicodec prefix"));
    }
    let key = &bytes[consumed..];
    if key.len() != ENCAPSULATION_KEY_LEN {
        return Err(Error::Encoding("encapsulation key must be 1568 bytes"));
    }
    Ok(key.to_vec())
}

fn derive_wrap_key(shared_secret: &[u8]) -> Result<[u8; 32], Error> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(shared_secret);
    let okm = prk
        .expand(&[HKDF_INFO], &AES_256_GCM)
        .map_err(|_| Error::Crypto)?;
    let mut key = [0u8; 32];
    okm.fill(&mut key).map_err(|_| Error::Crypto)?;
    Ok(key)
}

/// A content key wrapped to one recipient's ML-KEM-1024 key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedContentKey {
    /// The ML-KEM-1024 ciphertext, 1568 bytes.
    pub kem_ciphertext: Vec<u8>,
    /// The AES-256-GCM nonce.
    pub nonce: [u8; NONCE_LEN],
    /// The sealed key: 32 bytes of key, then the 16 byte tag.
    pub sealed_key: Vec<u8>,
}

impl WrappedContentKey {
    /// Wrap `content_key` to the recipient's encapsulation key.
    ///
    /// `aad` must be presented unchanged when unwrapping. Bind at least
    /// the subject and command, as [`space_aad`] does, so a wrap lifted
    /// into another delegation does not open.
    pub fn wrap(
        recipient_encapsulation_key: &[u8],
        content_key: &[u8; CONTENT_KEY_LEN],
        aad: &[u8],
    ) -> Result<Self, Error> {
        let encapsulation_key =
            kem::EncapsulationKey::new(&kem::ML_KEM_1024, recipient_encapsulation_key)
                .map_err(|_| Error::Crypto)?;
        let (ciphertext, shared_secret) =
            encapsulation_key.encapsulate().map_err(|_| Error::Crypto)?;

        let wrap_key = derive_wrap_key(shared_secret.as_ref())?;
        let aead_key =
            RandomizedNonceKey::new(&AES_256_GCM, &wrap_key).map_err(|_| Error::Crypto)?;

        let mut sealed_key = content_key.to_vec();
        let nonce = aead_key
            .seal_in_place_append_tag(Aad::from(aad), &mut sealed_key)
            .map_err(|_| Error::Crypto)?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(nonce.as_ref());

        Ok(WrappedContentKey {
            kem_ciphertext: ciphertext.as_ref().to_vec(),
            nonce: nonce_bytes,
            sealed_key,
        })
    }

    /// Recover the content key, given the same `aad` used to wrap.
    pub fn unwrap_key(
        &self,
        recipient: &SpaceKeyPair,
        aad: &[u8],
    ) -> Result<[u8; CONTENT_KEY_LEN], Error> {
        let shared_secret = recipient
            .decapsulation_key
            .decapsulate(kem::Ciphertext::from(self.kem_ciphertext.as_slice()))
            .map_err(|_| Error::Crypto)?;

        let wrap_key = derive_wrap_key(shared_secret.as_ref())?;
        let aead_key =
            RandomizedNonceKey::new(&AES_256_GCM, &wrap_key).map_err(|_| Error::Crypto)?;

        let nonce = Nonce::try_assume_unique_for_key(&self.nonce).map_err(|_| Error::Crypto)?;
        let mut buffer = self.sealed_key.clone();
        let plaintext = aead_key
            .open_in_place(nonce, Aad::from(aad), &mut buffer)
            .map_err(|_| Error::Crypto)?;

        <[u8; CONTENT_KEY_LEN]>::try_from(&*plaintext).map_err(|_| Error::Crypto)
    }

    /// Encode as IPLD for embedding in a delegation's `meta` map.
    #[must_use]
    pub fn to_ipld(&self) -> Ipld {
        let mut map = BTreeMap::new();
        map.insert("alg".to_string(), Ipld::String(WRAP_ALGORITHM.to_string()));
        map.insert("ct".to_string(), Ipld::Bytes(self.kem_ciphertext.clone()));
        map.insert("iv".to_string(), Ipld::Bytes(self.nonce.to_vec()));
        map.insert("key".to_string(), Ipld::Bytes(self.sealed_key.clone()));
        Ipld::Map(map)
    }

    /// Decode from the IPLD form produced by [`WrappedContentKey::to_ipld`].
    pub fn from_ipld(ipld: &Ipld) -> Result<Self, Error> {
        let Ipld::Map(map) = ipld else {
            return Err(Error::Encoding("wrapped key must be a map"));
        };
        match map.get("alg") {
            Some(Ipld::String(alg)) if alg == WRAP_ALGORITHM => {}
            _ => return Err(Error::Encoding("unsupported wrap algorithm")),
        }
        let Some(Ipld::Bytes(ciphertext)) = map.get("ct") else {
            return Err(Error::Encoding("missing `ct` bytes"));
        };
        let Some(Ipld::Bytes(iv)) = map.get("iv") else {
            return Err(Error::Encoding("missing `iv` bytes"));
        };
        let Some(Ipld::Bytes(sealed_key)) = map.get("key") else {
            return Err(Error::Encoding("missing `key` bytes"));
        };
        let nonce = <[u8; NONCE_LEN]>::try_from(iv.as_slice())
            .map_err(|_| Error::Encoding("`iv` must be 12 bytes"))?;
        Ok(WrappedContentKey {
            kem_ciphertext: ciphertext.clone(),
            nonce,
            sealed_key: sealed_key.clone(),
        })
    }

    /// Insert into a delegation `meta` map under [`META_KEY`].
    pub fn attach_to_meta(&self, meta: &mut BTreeMap<String, Ipld>) {
        meta.insert(META_KEY.to_string(), self.to_ipld());
    }

    /// Extract from a delegation `meta` map, if present.
    pub fn from_meta(meta: &BTreeMap<String, Ipld>) -> Option<Result<Self, Error>> {
        meta.get(META_KEY).map(Self::from_ipld)
    }
}

/// The conventional AAD: the delegation's subject and command.
#[must_use]
pub fn space_aad(subject: &str, command: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(subject.len() + 1 + command.len());
    aad.extend_from_slice(subject.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(command.as_bytes());
    aad
}
