# pq-space

[![CI](https://github.com/ekayana-labs/pq-space/actions/workflows/main.yml/badge.svg)](https://github.com/ekayana-labs/pq-space/actions/workflows/main.yml)
[![MSRV](https://img.shields.io/badge/msrv-1.90.0-blue)](rust-toolchain.toml)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ekayana-labs/pq-space/badge)](https://scorecard.dev/viewer/?uri=github.com/ekayana-labs/pq-space)

Post-quantum private space primitives for storage built on UCAN: **`did:bio`
principals for pq-ucan**, in one chain with Ed25519 and ML-DSA-87 `did:key`,
and **ML-KEM-1024 content key wrapping** delegated inside the UCAN itself.

Built on [pq-ucan] for UCAN 1.0 delegation, invocation and proof chain
validation, and on [did-bio-core] for `did:bio` identities. The post-quantum
cryptography is FIPS 203 and 204 through [aws-lc-rs].

## The idea

Private space storage encrypts each blob under a fresh content key. Today
that key is usually escrowed with a custody service, Lit Protocol or a KMS,
whose access control rests on classical cryptography. This crate replaces
custody with delegation that is post-quantum end to end:

1. The space owner wraps the 32 byte content key to the recipient's
   **ML-KEM-1024** encapsulation key (`WrappedContentKey::wrap`), with AAD
   binding the wrap to one grant, `subject|command`.
2. The wrap rides in the UCAN delegation's `meta` map under `"space/key"`,
   signed by the issuer: a `did:bio` researcher identity, a classical
   Ed25519 `did:key`, or an **ML-DSA-87** `did:key`.
3. The recipient verifies the delegation and decapsulates the content key.
   `did:bio` and `did:key` both resolve from the identifier itself, so
   checking a chain costs no network round trip. Capability and decryption
   authority travel together.

## Pieces

| Type | What it is |
|---|---|
| `BioSigner` | Signs pq-ucan tokens as a `did:bio` identity with its Ed25519 subject key |
| `BioResolver` | A pq-ucan `Resolver` for `did:bio`, deferring `did:key` to pq-ucan, for `Delegation::verify` and `Validator` |
| `SpaceKeyPair` | A recipient's ML-KEM-1024 key pair: generate, persist, publish the encapsulation key |
| `WrappedContentKey` | `ML-KEM-1024 -> HKDF-SHA256 -> AES-256-GCM` wrap of a content key, with IPLD encoding and `meta` helpers |

See the crate level example and
[`tests/delegation_flow.rs`](tests/delegation_flow.rs) for the whole story:
a researcher delegating to a device holding post-quantum keys, and the
device exercising the grant through a validated chain.

## Publishing the encapsulation key

A wrapper needs the recipient's encapsulation key before it can wrap
anything. `encode_encapsulation_key` renders it as a multibase string that
goes in a DID document service entry typed `SpaceEncapsulationKey`, and
`decode_encapsulation_key` reads it back, rejecting a wrong multicodec or a
truncated key rather than deferring the failure to encapsulation time.

## Encodings

- ML-DSA-87 `did:key`: multicodec `mldsa-87-pub` (`0x1212`, registered),
  `did:key:z…` over `0x92 0x24 ‖ pk`.
- ML-KEM-1024 encapsulation key: multicodec `mlkem-1024-pub` (`0x120d`,
  registered), multibase `z…` over `0x8d 0x24 ‖ pk`.
- Varsig header for ML-DSA-87: tag `0x1212` with no config segments,
  provisional pending inclusion in the varsig registry. It is pq-ucan's;
  this crate adds no wire format of its own beyond the `meta` entry.

## Status

`BioResolver` resolves generatively, from the subject key inside the
identifier. A registered `did:bio` may have rotated its keys since; where
that matters, resolve the DID document through `did-bio-core` and build a
resolver on it.

The crate has not received an external audit, and the provisional varsig
header means a token signed today may not verify once the registry assigns
one.

## License

MIT

[pq-ucan]: https://github.com/ekayana-labs/pq-ucan
[did-bio-core]: https://github.com/ekayana-labs/did-bio-core
[aws-lc-rs]: https://github.com/aws/aws-lc-rs
