# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-09-10

First release.

### Added

- `BioSigner` and `BioResolver`: a `did:bio` identity as a pq-ucan signer
  and resolver, so one chain may hold `did:bio`, Ed25519 `did:key` and
  ML-DSA-87 `did:key` principals; `did_of` and `bio_of` convert between the
  two identifier types.
- `SpaceKeyPair` and `WrappedContentKey`: ML-KEM-1024 key pairs and the
  `ML-KEM-1024 -> HKDF-SHA256 -> AES-256-GCM` content key wrap, with IPLD
  encoding and helpers for the delegation `meta` map.
- `encode_encapsulation_key` and `decode_encapsulation_key`: the multibase
  form of an ML-KEM-1024 encapsulation key, so a space owner can publish
  one in a DID document service entry under `SPACE_KEY_SERVICE_TYPE`.

[Unreleased]: https://github.com/ekayana-labs/pq-space/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ekayana-labs/pq-space/releases/tag/v0.1.0
