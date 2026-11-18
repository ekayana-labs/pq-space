//! An encapsulation key read from a DID document.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pq_space::{decode_encapsulation_key, encode_encapsulation_key, WrappedContentKey};

fuzz_target!(|text: &str| {
    let Ok(key) = decode_encapsulation_key(text) else {
        return;
    };
    // A key has one text form.
    assert_eq!(encode_encapsulation_key(&key), text);
    // ML-KEM may still refuse the key. It must not panic.
    let _ = WrappedContentKey::wrap(&key, &[0; 32], b"");
});
