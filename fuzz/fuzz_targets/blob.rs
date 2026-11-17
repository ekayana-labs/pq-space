//! Sealed blobs, as bytes from storage and as round trips.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pq_space::{open_blob, seal_blob};

const KEY: [u8; 32] = [7; 32];

fuzz_target!(|bytes: &[u8]| {
    let _ = open_blob(&KEY, bytes, b"aad");

    let mut sealed = seal_blob(&KEY, bytes, b"aad").unwrap();
    assert_eq!(open_blob(&KEY, &sealed, b"aad").unwrap(), bytes);

    // Any one flipped bit fails. The input picks which.
    let seed = bytes.iter().fold(0usize, |acc, byte| {
        acc.wrapping_mul(31).wrapping_add(*byte as usize)
    });
    let index = seed % sealed.len();
    sealed[index] ^= 1 << (seed % 8);
    assert!(open_blob(&KEY, &sealed, b"aad").is_err());
});
