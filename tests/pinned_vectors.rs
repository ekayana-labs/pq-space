//! Vectors generated once and kept under `tests/fixtures`. A round trip
//! test passes against itself when the wrap format drifts. These fail.
//!
//! The wrapped keys were produced for the content key `[42; 32]` with the
//! AAD `space_aad_for` builds from the `did:bio` of seed `[5; 32]` on
//! devnet and the command `/space/blob/get`. The blob is sealed under the
//! same key and AAD and holds `i % 251` for `i` up to one chunk and 100
//! bytes.

use pq_space::{
    decode_encapsulation_key, open_blob, space_aad_for, SpaceKeyPair, WrappedContentKey,
    BLOB_CHUNK_LEN, CONTENT_KEY_LEN, WRAP_ALGORITHM, WRAP_ALGORITHM_V1,
};
use pq_ucan::{codec, command::Command, did::Did};
use testresult::TestResult;

const DECAPSULATION_KEY: &[u8] = include_bytes!("fixtures/ml-kem-1024.dk");
const ENCAPSULATION_KEY: &[u8] = include_bytes!("fixtures/ml-kem-1024.ek");
const WRAPPED_CONTENT_KEY_V1: &[u8] = include_bytes!("fixtures/wrapped-content-key.cbor");
const WRAPPED_CONTENT_KEY: &[u8] = include_bytes!("fixtures/wrapped-content-key-v2.cbor");
const SEALED_BLOB: &[u8] = include_bytes!("fixtures/sealed-blob.bin");

const SPACE: &str = "did:bio:devnet:8SFqwqnq4whPhs8icwHA2hQg3hUoN1qrCLK1SBx3WKwe";

#[test]
fn a_stored_key_pair_still_publishes_the_same_encapsulation_key() -> TestResult {
    let owner = SpaceKeyPair::from_decapsulation_key_bytes(DECAPSULATION_KEY)?;
    assert_eq!(owner.encapsulation_key_bytes(), ENCAPSULATION_KEY);
    assert_eq!(*owner.decapsulation_key_bytes()?, DECAPSULATION_KEY);

    let published = owner.encapsulation_key_multibase();
    assert_eq!(decode_encapsulation_key(&published)?, ENCAPSULATION_KEY);
    Ok(())
}

#[test]
fn a_stored_wrap_still_opens() -> TestResult {
    let owner = SpaceKeyPair::from_decapsulation_key_bytes(DECAPSULATION_KEY)?;
    let aad = space_aad_for(&Did::parse(SPACE)?, &Command::parse("/space/blob/get")?);

    for (stored, algorithm) in [
        (WRAPPED_CONTENT_KEY_V1, WRAP_ALGORITHM_V1),
        (WRAPPED_CONTENT_KEY, WRAP_ALGORITHM),
    ] {
        let wrapped = WrappedContentKey::from_ipld(&codec::decode(stored)?)?;
        assert_eq!(wrapped.algorithm(), algorithm);

        // The IPLD layout is part of the format.
        assert_eq!(codec::encode(&wrapped.to_ipld())?, stored);
        assert_eq!(*wrapped.unwrap_key(&owner, &aad)?, [42u8; CONTENT_KEY_LEN]);
    }
    Ok(())
}

#[test]
fn a_stored_blob_still_opens() -> TestResult {
    let aad = space_aad_for(&Did::parse(SPACE)?, &Command::parse("/space/blob/get")?);
    let plaintext: Vec<u8> = (0..BLOB_CHUNK_LEN + 100).map(|i| (i % 251) as u8).collect();
    assert_eq!(
        open_blob(&[42u8; CONTENT_KEY_LEN], SEALED_BLOB, &aad)?,
        plaintext
    );
    Ok(())
}
