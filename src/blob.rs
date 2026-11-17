//! Blobs sealed under a content key.
//!
//! A sealed blob is a header followed by AES-256-GCM chunks.
//!
//! ```text
//! "PQSB" | version 0x01 | salt (32) | commitment (32) | chunk*
//! ```
//!
//! HKDF-SHA256 over the content key and the salt gives the chunk key and
//! the commitment. AES-GCM alone does not commit to its key, so one
//! ciphertext can be made to open under two keys (Dodis, Grubbs,
//! Ristenpart and Woodage, CRYPTO 2018; Len, Grubbs and Ristenpart, USENIX
//! Security 2021). The commitment is checked before any chunk is opened,
//! so a blob opens under one content key only.
//!
//! The plaintext is cut into 64 KiB chunks, each sealed with its own
//! nonce, a counter followed by a byte that marks the last chunk, as in
//! STREAM (Hoang, Reyhanitabar, Rogaway and Vizar, CRYPTO 2015). Chunks
//! cannot be reordered, dropped or cut off at the end without the open
//! failing.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::{constant_time, hkdf, rand};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::space::CONTENT_KEY_LEN;

/// Length in bytes of the plaintext in every chunk but the last.
pub const BLOB_CHUNK_LEN: usize = 64 * 1024;

/// Length in bytes of the header that precedes the chunks.
pub const BLOB_HEADER_LEN: usize = MAGIC.len() + 1 + SALT_LEN + COMMITMENT_LEN;

const MAGIC: &[u8; 4] = b"PQSB";
const VERSION: u8 = 1;
const SALT_LEN: usize = 32;
const COMMITMENT_LEN: usize = 32;
const TAG_LEN: usize = 16;
const SEALED_CHUNK_LEN: usize = BLOB_CHUNK_LEN + TAG_LEN;

const KEY_INFO: &[u8] = b"pq-space/v1/blob/key";
const COMMITMENT_INFO: &[u8] = b"pq-space/v1/blob/commitment";

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// A fresh content key from the system's random source. It wipes itself
/// when dropped.
pub fn generate_content_key() -> Result<Zeroizing<[u8; CONTENT_KEY_LEN]>, Error> {
    let mut key = Zeroizing::new([0u8; CONTENT_KEY_LEN]);
    rand::fill(&mut key[..]).map_err(|_| Error::Crypto)?;
    Ok(key)
}

fn derive(
    content_key: &[u8; CONTENT_KEY_LEN],
    salt: &[u8],
) -> Result<(LessSafeKey, [u8; COMMITMENT_LEN]), Error> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(content_key);

    let mut key = Zeroizing::new([0u8; 32]);
    prk.expand(&[KEY_INFO], Len(key.len()))
        .and_then(|okm| okm.fill(&mut key[..]))
        .map_err(|_| Error::Crypto)?;
    let mut commitment = [0u8; COMMITMENT_LEN];
    prk.expand(&[COMMITMENT_INFO], Len(COMMITMENT_LEN))
        .and_then(|okm| okm.fill(&mut commitment))
        .map_err(|_| Error::Crypto)?;

    let key = UnboundKey::new(&AES_256_GCM, &key[..]).map_err(|_| Error::Crypto)?;
    Ok((LessSafeKey::new(key), commitment))
}

// The key is fresh for every blob, so the nonce only has to be unique
// within one. It is the chunk's index and the last chunk flag.
fn nonce(index: u64, last: bool) -> Nonce {
    let mut bytes = [0u8; NONCE_LEN];
    bytes[3..11].copy_from_slice(&index.to_be_bytes());
    bytes[11] = u8::from(last);
    Nonce::assume_unique_for_key(bytes)
}

/// Seal `plaintext` under `content_key`.
///
/// `aad` must be presented unchanged when opening. It is not stored in
/// the blob.
pub fn seal_blob(
    content_key: &[u8; CONTENT_KEY_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut salt = [0u8; SALT_LEN];
    rand::fill(&mut salt).map_err(|_| Error::Crypto)?;
    let (key, commitment) = derive(content_key, &salt)?;

    let chunks = plaintext.len().div_ceil(BLOB_CHUNK_LEN).max(1);
    let mut sealed = Vec::with_capacity(BLOB_HEADER_LEN + plaintext.len() + chunks * TAG_LEN);
    sealed.extend_from_slice(MAGIC);
    sealed.push(VERSION);
    sealed.extend_from_slice(&salt);
    sealed.extend_from_slice(&commitment);

    // An empty blob is one empty chunk, so it still carries a tag.
    let mut rest = plaintext;
    for index in 0..chunks {
        let (chunk, tail) = rest.split_at(rest.len().min(BLOB_CHUNK_LEN));
        rest = tail;
        let start = sealed.len();
        sealed.extend_from_slice(chunk);
        let tag = key
            .seal_in_place_separate_tag(
                nonce(index as u64, index + 1 == chunks),
                Aad::from(aad),
                &mut sealed[start..],
            )
            .map_err(|_| Error::Crypto)?;
        sealed.extend_from_slice(tag.as_ref());
    }
    Ok(sealed)
}

/// Open what [`seal_blob`] produced, given the same `aad`.
///
/// Nothing is returned unless every chunk opens.
pub fn open_blob(
    content_key: &[u8; CONTENT_KEY_LEN],
    sealed: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    let Some((header, body)) = sealed.split_at_checked(BLOB_HEADER_LEN) else {
        return Err(Error::Encoding("sealed blob is shorter than its header"));
    };
    let (magic, header) = header.split_at(MAGIC.len());
    if magic != MAGIC {
        return Err(Error::Encoding("not a sealed blob"));
    }
    if header[0] != VERSION {
        return Err(Error::Encoding("unsupported sealed blob version"));
    }
    let (salt, commitment) = header[1..].split_at(SALT_LEN);
    // Every chunk ends in a tag, and only the first may be otherwise empty.
    let last_len = body.len() % SEALED_CHUNK_LEN;
    if body.is_empty() || (last_len != 0 && last_len < TAG_LEN) {
        return Err(Error::Encoding("sealed blob has a truncated chunk"));
    }
    if last_len == TAG_LEN && body.len() != TAG_LEN {
        return Err(Error::Encoding("sealed blob has an empty last chunk"));
    }

    let (key, expected) = derive(content_key, salt)?;
    constant_time::verify_slices_are_equal(commitment, &expected).map_err(|_| Error::Crypto)?;

    let chunks = body.len().div_ceil(SEALED_CHUNK_LEN);
    let mut plaintext = Zeroizing::new(Vec::with_capacity(body.len() - chunks * TAG_LEN));
    let mut buffer = Zeroizing::new(Vec::with_capacity(SEALED_CHUNK_LEN.min(body.len())));
    for (index, chunk) in body.chunks(SEALED_CHUNK_LEN).enumerate() {
        buffer.clear();
        buffer.extend_from_slice(chunk);
        let opened = key
            .open_in_place(
                nonce(index as u64, index + 1 == chunks),
                Aad::from(aad),
                &mut buffer[..],
            )
            .map_err(|_| Error::Crypto)?;
        plaintext.extend_from_slice(opened);
    }
    Ok(std::mem::take(&mut *plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use testresult::TestResult;

    const KEY: [u8; CONTENT_KEY_LEN] = [7; CONTENT_KEY_LEN];

    #[test]
    fn a_blob_of_any_length_round_trips() -> TestResult {
        for len in [
            0,
            1,
            BLOB_CHUNK_LEN - 1,
            BLOB_CHUNK_LEN,
            BLOB_CHUNK_LEN + 1,
            3 * BLOB_CHUNK_LEN,
        ] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let sealed = seal_blob(&KEY, &plaintext, b"aad")?;
            let chunks = len.div_ceil(BLOB_CHUNK_LEN).max(1);
            assert_eq!(sealed.len(), BLOB_HEADER_LEN + len + chunks * TAG_LEN);
            assert_eq!(open_blob(&KEY, &sealed, b"aad")?, plaintext);
        }
        Ok(())
    }

    #[test]
    fn sealing_twice_gives_different_bytes() -> TestResult {
        assert_ne!(
            seal_blob(&KEY, b"data", b"")?,
            seal_blob(&KEY, b"data", b"")?
        );
        Ok(())
    }

    #[test]
    fn the_wrong_key_or_aad_does_not_open() -> TestResult {
        let sealed = seal_blob(&KEY, b"data", b"aad")?;
        assert_eq!(
            open_blob(&[8; CONTENT_KEY_LEN], &sealed, b"aad"),
            Err(Error::Crypto)
        );
        assert_eq!(open_blob(&KEY, &sealed, b"other"), Err(Error::Crypto));
        Ok(())
    }

    #[test]
    fn any_flipped_byte_fails() -> TestResult {
        let sealed = seal_blob(&KEY, b"some data", b"")?;
        for index in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[index] ^= 1;
            assert!(open_blob(&KEY, &tampered, b"").is_err(), "byte {index}");
        }
        Ok(())
    }

    #[test]
    fn chunks_cannot_be_dropped_reordered_or_cut_off() -> TestResult {
        let plaintext = vec![1u8; 3 * BLOB_CHUNK_LEN];
        let sealed = seal_blob(&KEY, &plaintext, b"")?;
        let (header, body) = sealed.split_at(BLOB_HEADER_LEN);
        let chunks: Vec<&[u8]> = body.chunks(SEALED_CHUNK_LEN).collect();
        let build = |order: &[usize]| {
            let mut blob = header.to_vec();
            for index in order {
                blob.extend_from_slice(chunks[*index]);
            }
            blob
        };

        assert_eq!(open_blob(&KEY, &build(&[0, 1, 2]), b"")?, plaintext);
        // Without the last chunk the blob ends on a chunk not marked last.
        assert_eq!(open_blob(&KEY, &build(&[0, 1]), b""), Err(Error::Crypto));
        assert_eq!(open_blob(&KEY, &build(&[1, 0, 2]), b""), Err(Error::Crypto));
        assert_eq!(open_blob(&KEY, &build(&[0, 2]), b""), Err(Error::Crypto));
        assert_eq!(
            open_blob(&KEY, &build(&[0, 1, 2, 2]), b""),
            Err(Error::Crypto)
        );
        Ok(())
    }

    #[test]
    fn a_malformed_blob_fails_with_a_reason() -> TestResult {
        let sealed = seal_blob(&KEY, b"data", b"")?;

        assert_eq!(
            open_blob(&KEY, &sealed[..BLOB_HEADER_LEN - 1], b""),
            Err(Error::Encoding("sealed blob is shorter than its header"))
        );
        let mut magic = sealed.clone();
        magic[0] = b'X';
        assert_eq!(
            open_blob(&KEY, &magic, b""),
            Err(Error::Encoding("not a sealed blob"))
        );
        let mut version = sealed.clone();
        version[MAGIC.len()] = 2;
        assert_eq!(
            open_blob(&KEY, &version, b""),
            Err(Error::Encoding("unsupported sealed blob version"))
        );
        let truncated = Err(Error::Encoding("sealed blob has a truncated chunk"));
        assert_eq!(open_blob(&KEY, &sealed[..BLOB_HEADER_LEN], b""), truncated);
        assert_eq!(
            open_blob(&KEY, &sealed[..BLOB_HEADER_LEN + TAG_LEN - 1], b""),
            truncated
        );

        // A full chunk followed by an empty one is not something seal makes.
        let mut padded = seal_blob(&KEY, &vec![0u8; BLOB_CHUNK_LEN], b"")?;
        padded.extend_from_slice(&[0u8; TAG_LEN]);
        assert_eq!(
            open_blob(&KEY, &padded, b""),
            Err(Error::Encoding("sealed blob has an empty last chunk"))
        );
        Ok(())
    }

    #[test]
    fn a_generated_content_key_is_fresh() -> TestResult {
        assert_ne!(*generate_content_key()?, *generate_content_key()?);
        Ok(())
    }
}
