//! Content keys wrapped with ML-KEM, delegated inside UCANs.
//!
//! Each blob is encrypted under a fresh 32 byte content key. Rather than
//! escrow that key with a custody service, it is wrapped to the
//! recipient's ML-KEM-1024 key (FIPS 203) and carried in the delegation's
//! `meta` map, so reading a blob needs both the delegation and the
//! decapsulation key.
//!
//! The wrap is ML-KEM-1024 encapsulation, HKDF-SHA256 under a domain
//! separating label, then AES-256-GCM. Its AAD binds the result to a
//! subject and a command.

use std::collections::BTreeMap;
use std::fmt;

use aws_lc_rs::aead::{Aad, Nonce, RandomizedNonceKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::digest;
use aws_lc_rs::hkdf;
use aws_lc_rs::kem;
use pq_ucan::codec::{put_uvarint, read_uvarint};
use pq_ucan::command::Command;
use pq_ucan::did::Did;
use pq_ucan::Ipld;
use zeroize::Zeroizing;

use crate::error::Error;

/// Length in bytes of the key a blob is encrypted under.
pub const CONTENT_KEY_LEN: usize = 32;

/// Length in bytes of an ML-KEM-1024 encapsulation key.
pub const ENCAPSULATION_KEY_LEN: usize = 1568;

/// Length in bytes of an ML-KEM-1024 decapsulation key.
pub const DECAPSULATION_KEY_LEN: usize = 3168;

/// Length in bytes of an ML-KEM-1024 ciphertext.
pub const KEM_CIPHERTEXT_LEN: usize = 1568;

/// Length in bytes of a sealed content key, the key followed by the
/// AES-256-GCM tag.
pub const SEALED_KEY_LEN: usize = CONTENT_KEY_LEN + 16;

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

// FIPS 203 lays a decapsulation key out as dk_pke || ek || H(ek) || z,
// where H is SHA3-256 and dk_pke is 1536 bytes for ML-KEM-1024. aws-lc-rs
// cannot hand back the encapsulation key of a decapsulation key built
// from raw bytes, so it is read from this slot instead.
const ENCAPSULATION_KEY_START: usize = 1536;
const ENCAPSULATION_KEY_END: usize = ENCAPSULATION_KEY_START + ENCAPSULATION_KEY_LEN;
const ENCAPSULATION_KEY_HASH_END: usize = ENCAPSULATION_KEY_END + 32;

/// A recipient's ML-KEM-1024 key pair (FIPS 203).
///
/// The decapsulation key stays with its owner. Only the encapsulation key
/// is shared.
pub struct SpaceKeyPair {
    decapsulation_key: kem::DecapsulationKey,
    encapsulation_key: Vec<u8>,
}

impl fmt::Debug for SpaceKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpaceKeyPair").finish_non_exhaustive()
    }
}

impl SpaceKeyPair {
    /// Generate a fresh ML-KEM-1024 key pair.
    pub fn generate() -> Result<Self, Error> {
        let decapsulation_key =
            kem::DecapsulationKey::generate(&kem::ML_KEM_1024).map_err(|_| Error::Crypto)?;
        let encapsulation_key = decapsulation_key
            .encapsulation_key()
            .map_err(|_| Error::Crypto)?
            .key_bytes()
            .map_err(|_| Error::Crypto)?
            .as_ref()
            .to_vec();
        Ok(SpaceKeyPair {
            decapsulation_key,
            encapsulation_key,
        })
    }

    /// Reconstruct from [`SpaceKeyPair::decapsulation_key_bytes`].
    ///
    /// The encapsulation key is read from its slot in the FIPS 203 layout
    /// and checked against the hash stored beside it, so a corrupted key
    /// fails here rather than at the first unwrap.
    pub fn from_decapsulation_key_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (encapsulation_key, hash) = match (
            bytes.get(ENCAPSULATION_KEY_START..ENCAPSULATION_KEY_END),
            bytes.get(ENCAPSULATION_KEY_END..ENCAPSULATION_KEY_HASH_END),
        ) {
            (Some(key), Some(hash)) if bytes.len() == DECAPSULATION_KEY_LEN => (key, hash),
            _ => return Err(Error::Encoding("decapsulation key must be 3168 bytes")),
        };
        if digest::digest(&digest::SHA3_256, encapsulation_key).as_ref() != hash {
            return Err(Error::Encoding(
                "decapsulation key fails its encapsulation key hash",
            ));
        }
        let decapsulation_key =
            kem::DecapsulationKey::new(&kem::ML_KEM_1024, bytes).map_err(|_| Error::Crypto)?;
        Ok(SpaceKeyPair {
            decapsulation_key,
            encapsulation_key: encapsulation_key.to_vec(),
        })
    }

    /// The raw decapsulation key, 3168 bytes. It is secret and it is the
    /// only thing that opens a wrap.
    pub fn decapsulation_key_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self
            .decapsulation_key
            .key_bytes()
            .map_err(|_| Error::Crypto)?
            .as_ref()
            .to_vec())
    }

    /// The raw encapsulation key, 1568 bytes, which a wrapper needs.
    pub fn encapsulation_key_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.encapsulation_key.clone())
    }

    /// The encapsulation key in the form a DID document carries under
    /// [`SPACE_KEY_SERVICE_TYPE`].
    pub fn encapsulation_key_multibase(&self) -> Result<String, Error> {
        Ok(encode_encapsulation_key(&self.encapsulation_key))
    }
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
    put_uvarint(ML_KEM_1024_MULTICODEC, &mut bytes);
    bytes.extend_from_slice(key);
    format!("z{}", bs58::encode(bytes).into_string())
}

/// Decode what [`encode_encapsulation_key`] produced.
///
/// The length is checked here so that a malformed key fails where it was
/// read. ML-KEM would otherwise reject it only at encapsulation time.
pub fn decode_encapsulation_key(multibase: &str) -> Result<Vec<u8>, Error> {
    let encoded = multibase
        .strip_prefix('z')
        .ok_or(Error::Encoding("expected multibase `z` (base58btc)"))?;
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| Error::Encoding("invalid base58btc payload"))?;
    // pq-ucan's reader refuses overlong varints, so a key has one text form.
    let (code, consumed) =
        read_uvarint(&bytes).map_err(|_| Error::Encoding("malformed multicodec varint"))?;
    if code != ML_KEM_1024_MULTICODEC {
        return Err(Error::Encoding("not an mlkem-1024-pub multicodec prefix"));
    }
    let key = bytes
        .get(consumed..)
        .ok_or(Error::Encoding("malformed multicodec varint"))?;
    if key.len() != ENCAPSULATION_KEY_LEN {
        return Err(Error::Encoding("encapsulation key must be 1568 bytes"));
    }
    Ok(key.to_vec())
}

fn derive_wrap_key(shared_secret: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(shared_secret);
    let okm = prk
        .expand(&[HKDF_INFO], &AES_256_GCM)
        .map_err(|_| Error::Crypto)?;
    let mut key = Zeroizing::new([0u8; 32]);
    okm.fill(&mut key[..]).map_err(|_| Error::Crypto)?;
    Ok(key)
}

/// A content key wrapped to one recipient's ML-KEM-1024 key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedContentKey {
    /// The ML-KEM-1024 ciphertext, 1568 bytes.
    pub kem_ciphertext: Vec<u8>,
    /// The AES-256-GCM nonce.
    pub nonce: [u8; NONCE_LEN],
    /// The sealed key, 32 bytes of key followed by the 16 byte tag.
    pub sealed_key: Vec<u8>,
}

impl WrappedContentKey {
    /// Wrap `content_key` to the recipient's encapsulation key.
    ///
    /// `aad` must be presented unchanged when unwrapping. Bind at least
    /// the subject and command, as [`space_aad_for`] does, so a wrap
    /// lifted into a delegation for another subject or command does not
    /// open.
    pub fn wrap(
        recipient_encapsulation_key: &[u8],
        content_key: &[u8; CONTENT_KEY_LEN],
        aad: &[u8],
    ) -> Result<Self, Error> {
        if recipient_encapsulation_key.len() != ENCAPSULATION_KEY_LEN {
            return Err(Error::Encoding("encapsulation key must be 1568 bytes"));
        }
        let encapsulation_key =
            kem::EncapsulationKey::new(&kem::ML_KEM_1024, recipient_encapsulation_key)
                .map_err(|_| Error::Crypto)?;
        let (ciphertext, shared_secret) =
            encapsulation_key.encapsulate().map_err(|_| Error::Crypto)?;

        let wrap_key = derive_wrap_key(shared_secret.as_ref())?;
        let aead_key =
            RandomizedNonceKey::new(&AES_256_GCM, &wrap_key[..]).map_err(|_| Error::Crypto)?;

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
            RandomizedNonceKey::new(&AES_256_GCM, &wrap_key[..]).map_err(|_| Error::Crypto)?;

        let nonce = Nonce::try_assume_unique_for_key(&self.nonce).map_err(|_| Error::Crypto)?;
        let mut buffer = Zeroizing::new(self.sealed_key.clone());
        let plaintext = aead_key
            .open_in_place(nonce, Aad::from(aad), &mut buffer[..])
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
    ///
    /// Every field is checked for length, so a truncated entry fails here
    /// with a reason rather than at `unwrap_key` without one.
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
        if ciphertext.len() != KEM_CIPHERTEXT_LEN {
            return Err(Error::Encoding("`ct` must be 1568 bytes"));
        }
        let nonce = <[u8; NONCE_LEN]>::try_from(iv.as_slice())
            .map_err(|_| Error::Encoding("`iv` must be 12 bytes"))?;
        if sealed_key.len() != SEALED_KEY_LEN {
            return Err(Error::Encoding("`key` must be 48 bytes"));
        }
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

/// The conventional AAD, the delegation's subject and command joined by
/// `|`.
///
/// Prefer [`space_aad_for`]. With plain strings, `("a|b", "c")` and
/// `("a", "b|c")` give the same AAD.
#[must_use]
pub fn space_aad(subject: &str, command: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(subject.len() + 1 + command.len());
    aad.extend_from_slice(subject.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(command.as_bytes());
    aad
}

/// The conventional AAD for a typed subject and command.
///
/// The subject's path, query and fragment are dropped, as pq-ucan does
/// when it compares principals. A DID cannot contain `|`, so the first
/// `|` always ends the subject and two different pairs never share an
/// AAD.
#[must_use]
pub fn space_aad_for(subject: &Did, command: &Command) -> Vec<u8> {
    space_aad(subject.base(), command.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use testresult::TestResult;

    #[test]
    fn wrap_unwrap_round_trip() -> TestResult {
        let recipient = SpaceKeyPair::generate()?;
        let content_key = [42u8; CONTENT_KEY_LEN];
        let aad = space_aad("did:bio:devnet:subject", "/space/blob/get");

        let wrapped =
            WrappedContentKey::wrap(&recipient.encapsulation_key_bytes()?, &content_key, &aad)?;
        assert_eq!(wrapped.kem_ciphertext.len(), KEM_CIPHERTEXT_LEN);
        assert_eq!(wrapped.sealed_key.len(), SEALED_KEY_LEN);

        let recovered = wrapped.unwrap_key(&recipient, &aad)?;
        assert_eq!(recovered, content_key);
        Ok(())
    }

    #[test]
    fn wrong_aad_recipient_or_tamper_fails() -> TestResult {
        let recipient = SpaceKeyPair::generate()?;
        let other = SpaceKeyPair::generate()?;
        let content_key = [7u8; CONTENT_KEY_LEN];
        let aad = space_aad("did:bio:devnet:subject", "/space/blob/get");

        let wrapped =
            WrappedContentKey::wrap(&recipient.encapsulation_key_bytes()?, &content_key, &aad)?;

        assert_eq!(
            wrapped.unwrap_key(&recipient, b"different aad"),
            Err(Error::Crypto)
        );
        assert_eq!(wrapped.unwrap_key(&other, &aad), Err(Error::Crypto));

        let mut tampered = wrapped;
        tampered.sealed_key[0] ^= 1;
        assert_eq!(tampered.unwrap_key(&recipient, &aad), Err(Error::Crypto));
        Ok(())
    }

    #[test]
    fn wrap_rejects_a_key_of_the_wrong_length() {
        assert_eq!(
            WrappedContentKey::wrap(&[0u8; 32], &[0u8; CONTENT_KEY_LEN], b"").err(),
            Some(Error::Encoding("encapsulation key must be 1568 bytes"))
        );
    }

    #[test]
    fn decapsulation_key_persists() -> TestResult {
        let recipient = SpaceKeyPair::generate()?;
        let content_key = [3u8; CONTENT_KEY_LEN];
        let wrapped =
            WrappedContentKey::wrap(&recipient.encapsulation_key_bytes()?, &content_key, b"")?;

        let restored =
            SpaceKeyPair::from_decapsulation_key_bytes(&recipient.decapsulation_key_bytes()?)?;
        assert_eq!(wrapped.unwrap_key(&restored, b"")?, content_key);

        // The restored pair gives back the same keys.
        assert_eq!(
            restored.encapsulation_key_bytes()?,
            recipient.encapsulation_key_bytes()?
        );
        assert_eq!(
            restored.encapsulation_key_multibase()?,
            recipient.encapsulation_key_multibase()?
        );
        assert_eq!(
            restored.decapsulation_key_bytes()?,
            recipient.decapsulation_key_bytes()?
        );
        Ok(())
    }

    #[test]
    fn a_restored_key_pair_is_checked_before_use() -> TestResult {
        let recipient = SpaceKeyPair::generate()?;
        let bytes = recipient.decapsulation_key_bytes()?;
        let wrapped = WrappedContentKey::wrap(
            &recipient.encapsulation_key_bytes()?,
            &[5u8; CONTENT_KEY_LEN],
            b"aad",
        )?;

        let length_error = Some(Error::Encoding("decapsulation key must be 3168 bytes"));
        assert_eq!(
            SpaceKeyPair::from_decapsulation_key_bytes(&bytes[..DECAPSULATION_KEY_LEN - 1]).err(),
            length_error
        );
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(
            SpaceKeyPair::from_decapsulation_key_bytes(&long).err(),
            length_error
        );

        let hash_error = Some(Error::Encoding(
            "decapsulation key fails its encapsulation key hash",
        ));
        let mut flipped_key = bytes.clone();
        flipped_key[ENCAPSULATION_KEY_START] ^= 1;
        assert_eq!(
            SpaceKeyPair::from_decapsulation_key_bytes(&flipped_key).err(),
            hash_error
        );
        let mut flipped_hash = bytes.clone();
        flipped_hash[ENCAPSULATION_KEY_END] ^= 1;
        assert_eq!(
            SpaceKeyPair::from_decapsulation_key_bytes(&flipped_hash).err(),
            hash_error
        );

        // A corrupted private half passes the hash check and fails at
        // decapsulation instead.
        let mut flipped_private = bytes;
        flipped_private[0] ^= 1;
        let corrupted = SpaceKeyPair::from_decapsulation_key_bytes(&flipped_private)?;
        assert_eq!(wrapped.unwrap_key(&corrupted, b"aad"), Err(Error::Crypto));
        Ok(())
    }

    #[test]
    fn ipld_round_trip_and_meta() -> TestResult {
        let recipient = SpaceKeyPair::generate()?;
        let wrapped = WrappedContentKey::wrap(
            &recipient.encapsulation_key_bytes()?,
            &[1u8; CONTENT_KEY_LEN],
            b"aad",
        )?;

        let decoded = WrappedContentKey::from_ipld(&wrapped.to_ipld())?;
        assert_eq!(decoded, wrapped);

        let mut meta = BTreeMap::new();
        wrapped.attach_to_meta(&mut meta);
        let from_meta = WrappedContentKey::from_meta(&meta).expect("present")?;
        assert_eq!(from_meta, wrapped);

        assert_eq!(
            WrappedContentKey::from_ipld(&Ipld::String("nope".into())),
            Err(Error::Encoding("wrapped key must be a map"))
        );
        Ok(())
    }

    #[test]
    fn ipld_decoding_checks_every_length() -> TestResult {
        let recipient = SpaceKeyPair::generate()?;
        let wrapped = WrappedContentKey::wrap(
            &recipient.encapsulation_key_bytes()?,
            &[1u8; CONTENT_KEY_LEN],
            b"aad",
        )?;

        let mut short_ciphertext = wrapped.clone();
        short_ciphertext.kem_ciphertext.truncate(10);
        assert_eq!(
            WrappedContentKey::from_ipld(&short_ciphertext.to_ipld()),
            Err(Error::Encoding("`ct` must be 1568 bytes"))
        );

        let mut short_key = wrapped.clone();
        short_key.sealed_key.truncate(CONTENT_KEY_LEN);
        assert_eq!(
            WrappedContentKey::from_ipld(&short_key.to_ipld()),
            Err(Error::Encoding("`key` must be 48 bytes"))
        );

        let Ipld::Map(mut map) = wrapped.to_ipld() else {
            unreachable!()
        };
        map.insert("iv".into(), Ipld::Bytes(vec![0; 16]));
        assert_eq!(
            WrappedContentKey::from_ipld(&Ipld::Map(map.clone())),
            Err(Error::Encoding("`iv` must be 12 bytes"))
        );
        map.insert("alg".into(), Ipld::String("X25519".into()));
        assert_eq!(
            WrappedContentKey::from_ipld(&Ipld::Map(map)),
            Err(Error::Encoding("unsupported wrap algorithm"))
        );
        Ok(())
    }

    #[test]
    fn encapsulation_key_survives_a_did_document() -> TestResult {
        let recipient = SpaceKeyPair::generate()?;
        let published = recipient.encapsulation_key_multibase()?;

        // A wrapper resolves the owner's DID, reads the service entry,
        // decodes the key and wraps to it.
        let decoded = decode_encapsulation_key(&published)?;
        assert_eq!(decoded, recipient.encapsulation_key_bytes()?);
        assert_eq!(decoded.len(), ENCAPSULATION_KEY_LEN);

        let wrapped = WrappedContentKey::wrap(&decoded, &[9u8; CONTENT_KEY_LEN], b"aad")?;
        assert_eq!(
            wrapped.unwrap_key(&recipient, b"aad")?,
            [9u8; CONTENT_KEY_LEN]
        );
        Ok(())
    }

    #[test]
    fn encapsulation_key_decoding_rejects_the_near_misses() -> TestResult {
        let recipient = SpaceKeyPair::generate()?;
        let good = recipient.encapsulation_key_multibase()?;

        assert_eq!(
            decode_encapsulation_key(&good[1..]),
            Err(Error::Encoding("expected multibase `z` (base58btc)"))
        );
        assert_eq!(
            decode_encapsulation_key("z0OIl"),
            Err(Error::Encoding("invalid base58btc payload"))
        );
        assert_eq!(
            decode_encapsulation_key("z"),
            Err(Error::Encoding("malformed multicodec varint"))
        );

        // An Ed25519 Multikey is the value most likely to be pasted into
        // the wrong service entry.
        let mut ed25519 = Vec::new();
        put_uvarint(0xed, &mut ed25519);
        ed25519.extend_from_slice(&[0u8; 32]);
        let ed25519 = format!("z{}", bs58::encode(ed25519).into_string());
        assert_eq!(
            decode_encapsulation_key(&ed25519),
            Err(Error::Encoding("not an mlkem-1024-pub multicodec prefix"))
        );

        // Right prefix, truncated key.
        let mut short = Vec::new();
        put_uvarint(ML_KEM_1024_MULTICODEC, &mut short);
        short.extend_from_slice(&[0u8; 32]);
        let short = format!("z{}", bs58::encode(short).into_string());
        assert_eq!(
            decode_encapsulation_key(&short),
            Err(Error::Encoding("encapsulation key must be 1568 bytes"))
        );

        // The same code spelled in three bytes. A key has one text form.
        let mut overlong = vec![0x8d, 0xa4, 0x00];
        overlong.extend_from_slice(&[0u8; ENCAPSULATION_KEY_LEN]);
        let overlong = format!("z{}", bs58::encode(overlong).into_string());
        assert_eq!(
            decode_encapsulation_key(&overlong),
            Err(Error::Encoding("malformed multicodec varint"))
        );
        Ok(())
    }

    #[test]
    fn multicodec_prefix_matches_the_registry() -> TestResult {
        let encoded = encode_encapsulation_key(&[0u8; ENCAPSULATION_KEY_LEN]);
        let bytes = bs58::decode(&encoded[1..]).into_vec()?;
        assert_eq!(&bytes[..2], [0x8d, 0x24]);
        assert_eq!(bytes.len(), 2 + ENCAPSULATION_KEY_LEN);
        Ok(())
    }

    #[test]
    fn typed_aad_matches_the_string_form_and_drops_the_fragment() -> TestResult {
        let space = Did::parse("did:bio:devnet:8SFqwqnq4whPhs8icwHA2hQg3hUoN1qrCLK1SBx3WKwe")?;
        let command = Command::parse("/space/blob/get")?;
        let aad = space_aad_for(&space, &command);
        assert_eq!(aad, space_aad(space.as_str(), command.as_str()));
        assert_eq!(
            aad,
            b"did:bio:devnet:8SFqwqnq4whPhs8icwHA2hQg3hUoN1qrCLK1SBx3WKwe|/space/blob/get"
        );

        let with_fragment =
            Did::parse("did:bio:devnet:8SFqwqnq4whPhs8icwHA2hQg3hUoN1qrCLK1SBx3WKwe#key-1")?;
        assert_eq!(space_aad_for(&with_fragment, &command), aad);

        // The string form cannot tell these apart. The typed form never
        // sees a subject with `|` in it.
        assert_eq!(space_aad("a|b", "c"), space_aad("a", "b|c"));
        Ok(())
    }
}
