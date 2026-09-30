# pq-space

[![CI](https://github.com/ekayana-labs/pq-space/actions/workflows/main.yml/badge.svg)](https://github.com/ekayana-labs/pq-space/actions/workflows/main.yml)
[![crates.io](https://img.shields.io/crates/v/pq-space.svg)](https://crates.io/crates/pq-space)
[![docs.rs](https://img.shields.io/docsrs/pq-space)](https://docs.rs/pq-space)
[![MSRV](https://img.shields.io/crates/msrv/pq-space)](Cargo.toml)
[![license](https://img.shields.io/crates/l/pq-space)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ekayana-labs/pq-space/badge)](https://scorecard.dev/viewer/?uri=github.com/ekayana-labs/pq-space)

Post-quantum private space primitives for storage built on UCAN. The crate
adds `did:bio` principals to pq-ucan, so they share one chain with Ed25519
and ML-DSA-87 `did:key` principals. It also wraps content keys with
ML-KEM-1024 and delegates the wrap inside the UCAN itself.

Built on [pq-ucan] for UCAN 1.0 delegation, invocation and proof chain
validation, and on [did-bio-core] for `did:bio` identities. The post-quantum
cryptography is FIPS 203 and 204 through [aws-lc-rs].

## The idea

Private space storage encrypts each blob under a fresh content key. Today
that key is usually escrowed with a custody service, Lit Protocol or a KMS,
whose access control rests on classical cryptography. This crate replaces
custody with delegation that is post-quantum end to end. It works in three
steps.

1. The space owner wraps the 32 byte content key to the recipient's
   ML-KEM-1024 encapsulation key with `WrappedContentKey::wrap`. The AAD,
   `subject|command`, binds the wrap to one grant.
2. The wrap rides in the UCAN delegation's `meta` map under `"space/key"`
   and is signed by the issuer. The issuer may be a `did:bio` researcher
   identity, a classical Ed25519 `did:key` or an ML-DSA-87 `did:key`.
3. The recipient verifies the delegation and decapsulates the content key.
   `did:bio` and `did:key` both resolve from the identifier itself, so
   checking a chain costs no network round trip. The same token carries
   the capability and the key that decrypts the blob.

## Pieces

| Type | What it is |
|---|---|
| `BioSigner` | Signs pq-ucan tokens as a `did:bio` identity with its Ed25519 subject key |
| `BioResolver` | A pq-ucan `Resolver` for `did:bio`, deferring `did:key` to pq-ucan, for `Delegation::verify` and `Validator` |
| `SpaceKeyPair` | A recipient's ML-KEM-1024 key pair, with helpers to generate it, persist it and publish its encapsulation key |
| `WrappedContentKey` | `ML-KEM-1024 -> HKDF-SHA256 -> AES-256-GCM` wrap of a content key, with IPLD encoding and `meta` helpers |

The crate level example and
[`tests/delegation_flow.rs`](tests/delegation_flow.rs) show the whole flow.
A researcher delegates to a device that holds post-quantum keys, and the
device exercises the grant through a validated chain.

## Publishing the encapsulation key

A wrapper needs the recipient's encapsulation key before it can wrap
anything. `encode_encapsulation_key` renders it as a multibase string for a
DID document service entry typed `SpaceEncapsulationKey`.
`decode_encapsulation_key` reads it back and rejects a wrong multicodec or a
truncated key rather than deferring the failure to encapsulation time.

## Encodings

- The ML-DSA-87 `did:key` uses the registered multicodec `mldsa-87-pub`
  (`0x1212`). It is `did:key:z...` over `0x92 0x24 || pk`.
- The ML-KEM-1024 encapsulation key uses the registered multicodec
  `mlkem-1024-pub` (`0x120d`). It is multibase `z...` over
  `0x8d 0x24 || pk`.
- The varsig header for ML-DSA-87 is the tag `0x1212` with no config
  segments. It stays provisional until the varsig registry includes it. The
  header belongs to pq-ucan, and this crate adds no wire format of its own
  beyond the `meta` entry.

## Status

`BioResolver` resolves generatively, from the subject key inside the
identifier. A registered `did:bio` may have rotated its keys since then.
Where that matters, resolve the DID document through `did-bio-core` and
build a resolver on it.

The crate has not received an external audit, and the provisional varsig
header means a token signed today may not verify once the registry assigns
one.

## License

MIT

[pq-ucan]: https://github.com/ekayana-labs/pq-ucan
[did-bio-core]: https://github.com/ekayana-labs/did-bio-core
[aws-lc-rs]: https://github.com/aws/aws-lc-rs
