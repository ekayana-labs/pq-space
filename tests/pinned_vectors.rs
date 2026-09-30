//! Vectors generated once and kept under `tests/fixtures`. A round trip
//! test passes against itself when the wrap format drifts. These fail.
//!
//! The wrapped key was produced for the content key `[42; 32]` with the
//! AAD `space_aad_for` builds from the `did:bio` of seed `[5; 32]` on
//! devnet and the command `/space/blob/get`.

use pq_space::{
    decode_encapsulation_key, space_aad_for, SpaceKeyPair, WrappedContentKey, CONTENT_KEY_LEN,
};
use pq_ucan::{codec, command::Command, did::Did};
use testresult::TestResult;

const DECAPSULATION_KEY: &[u8] = include_bytes!("fixtures/ml-kem-1024.dk");
const ENCAPSULATION_KEY: &[u8] = include_bytes!("fixtures/ml-kem-1024.ek");
const WRAPPED_CONTENT_KEY: &[u8] = include_bytes!("fixtures/wrapped-content-key.cbor");

const SPACE: &str = "did:bio:devnet:8SFqwqnq4whPhs8icwHA2hQg3hUoN1qrCLK1SBx3WKwe";

#[test]
fn a_stored_key_pair_still_publishes_the_same_encapsulation_key() -> TestResult {
    let owner = SpaceKeyPair::from_decapsulation_key_bytes(DECAPSULATION_KEY)?;
    assert_eq!(owner.encapsulation_key_bytes()?, ENCAPSULATION_KEY);
    assert_eq!(owner.decapsulation_key_bytes()?, DECAPSULATION_KEY);

    let published = owner.encapsulation_key_multibase()?;
    assert_eq!(decode_encapsulation_key(&published)?, ENCAPSULATION_KEY);
    Ok(())
}

#[test]
fn a_stored_wrap_still_opens() -> TestResult {
    let owner = SpaceKeyPair::from_decapsulation_key_bytes(DECAPSULATION_KEY)?;
    let wrapped = WrappedContentKey::from_ipld(&codec::decode(WRAPPED_CONTENT_KEY)?)?;

    // The IPLD layout is part of the format.
    assert_eq!(codec::encode(&wrapped.to_ipld())?, WRAPPED_CONTENT_KEY);

    let aad = space_aad_for(&Did::parse(SPACE)?, &Command::parse("/space/blob/get")?);
    assert_eq!(wrapped.unwrap_key(&owner, &aad)?, [42u8; CONTENT_KEY_LEN]);
    Ok(())
}
