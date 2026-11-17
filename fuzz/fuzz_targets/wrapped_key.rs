//! A wrapped key from a delegation's `meta` map, decoded, re-encoded and opened.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use pq_space::pq_ucan::codec;
use pq_space::{SpaceKeyPair, WrappedContentKey};

fn recipient() -> &'static SpaceKeyPair {
    static RECIPIENT: OnceLock<SpaceKeyPair> = OnceLock::new();
    RECIPIENT.get_or_init(|| {
        SpaceKeyPair::from_decapsulation_key_bytes(include_bytes!(
            "../../tests/fixtures/ml-kem-1024.dk"
        ))
        .unwrap()
    })
}

fuzz_target!(|bytes: &[u8]| {
    let Ok(ipld) = codec::decode(bytes) else {
        return;
    };
    let Ok(wrapped) = WrappedContentKey::from_ipld(&ipld) else {
        return;
    };
    // What is accepted is what is emitted, apart from fields the format ignores.
    assert_eq!(
        WrappedContentKey::from_ipld(&wrapped.to_ipld()).unwrap(),
        wrapped
    );
    let _ = wrapped.unwrap_key(recipient(), b"aad");
});
