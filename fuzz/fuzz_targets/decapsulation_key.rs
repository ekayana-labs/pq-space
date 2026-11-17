//! A stored decapsulation key, restored and used.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pq_space::{SpaceKeyPair, WrappedContentKey};

fuzz_target!(|bytes: &[u8]| {
    let Ok(pair) = SpaceKeyPair::from_decapsulation_key_bytes(bytes) else {
        return;
    };
    assert_eq!(*pair.decapsulation_key_bytes().unwrap(), bytes);
    // The private half may be corrupt, so the unwrap may fail. It must not panic.
    if let Ok(wrapped) = WrappedContentKey::wrap(pair.encapsulation_key_bytes(), &[1; 32], b"") {
        let _ = wrapped.unwrap_key(&pair, b"");
    }
});
