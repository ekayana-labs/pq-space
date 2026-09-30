# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.2] - 2026-10-01

### Added

- `space_aad_for` builds the conventional AAD from a `Did` and a
  `Command`. A DID cannot contain `|`, so the pair decodes one way, which
  the string form cannot promise.
- `DECAPSULATION_KEY_LEN`, `KEM_CIPHERTEXT_LEN` and `SEALED_KEY_LEN`.
- Vectors under `tests/fixtures` pin the wrap format, the AAD convention
  and the decapsulation key layout.
- `Error` implements `PartialEq` and `Eq`.

### Changed

- Moved to `pq-ucan` 0.1.2.
- `BioResolver` says when a `did:bio` subject is owned instead of calling
  it a bad key. Such a subject has no generative key and needs a resolver
  backed by the registry.
- The wrap key and the buffer a content key is opened into are zeroized
  when dropped.
- `wrap` rejects an encapsulation key of the wrong length with
  `Error::Encoding` before any cryptography runs, as
  `from_decapsulation_key_bytes` now does for a decapsulation key.

### Fixed

- A `SpaceKeyPair` restored with `from_decapsulation_key_bytes` could not
  return its encapsulation key. The key is now read from the FIPS 203
  layout of the decapsulation key and checked against the hash stored
  beside it.
- `decode_encapsulation_key` accepted overlong varint prefixes, so one key
  had several text forms. It now uses the strict reader from pq-ucan.
- `WrappedContentKey::from_ipld` accepted a ciphertext or sealed key of any
  length and left the failure to `unwrap_key`.

## [0.1.1] - 2026-09-17

### Changed

- Moved to `did-bio-core` 0.1.2. `BioDid` and `Network` now come from the
  release that knows owned subjects, so a `did:bio` principal can name a
  wallet-owned asset DID. Consumers must move to the same `did-bio-core`
  generation.
- Moved to `pq-ucan` 0.1.1, the release with detached signing, so a space
  can be delegated by a key the builder never holds.

## [0.1.0] - 2026-09-10

First release.

### Added

- `BioSigner` and `BioResolver` make a `did:bio` identity a pq-ucan signer
  and resolver, so one chain may hold `did:bio`, Ed25519 `did:key` and
  ML-DSA-87 `did:key` principals. `did_of` and `bio_of` convert between the
  two identifier types.
- `SpaceKeyPair` and `WrappedContentKey` provide ML-KEM-1024 key pairs and
  the `ML-KEM-1024 -> HKDF-SHA256 -> AES-256-GCM` content key wrap, with
  IPLD encoding and helpers for the delegation `meta` map.
- `encode_encapsulation_key` and `decode_encapsulation_key` give the
  multibase form of an ML-KEM-1024 encapsulation key, so a space owner can
  publish one in a DID document service entry under
  `SPACE_KEY_SERVICE_TYPE`.

[Unreleased]: https://github.com/ekayana-labs/pq-space/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/ekayana-labs/pq-space/releases/tag/v0.1.1
[0.1.0]: https://github.com/ekayana-labs/pq-space/releases/tag/v0.1.0
