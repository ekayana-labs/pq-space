# Contributing

## Development

```console
cargo test
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo doc --no-deps
```

`pq-ucan`'s `ml-dsa` feature and this crate's ML-KEM both build `aws-lc-rs`,
which needs a C compiler and CMake.

## Rules

- Every check fails closed. A wrap presented with the wrong AAD or a
  malformed encapsulation key must return an error, and a token that
  pq-ucan refuses is never accepted around it. Add the hostile case to the
  tests in the same change.
- Every wrap is bound to its grant. A wrapped key that opens outside the
  delegation it was issued for is the bug this crate exists to prevent, so
  new wrapping paths take an AAD and document what it covers.
- Untrusted input never panics. Identifiers, delegation bytes, `meta`
  entries and keys all arrive from the network, so return `Error` instead.
- Errors stay opaque about cryptography. `Error::Crypto` says nothing about
  which step failed.
- Changes keep the existing wire format rather than inventing a new one.
  Multicodec prefixes and the `meta` key are interoperability surface, and
  varsig headers belong to pq-ucan. Change any of them only with a
  changelog note and a round trip test.
- The crate forbids `unsafe` and requires docs on every public item, and
  the compiler enforces both.

## Publishing

Every dependency comes from crates.io. Date the changelog, then
`cargo publish`.

## Commit messages

Write a short, capitalized, imperative subject with no trailing period,
such as `Add key wrapping` or `Reject mismatched signature algorithms`. Use
a `ci:`, `docs:`, `deps:` or `chore:` prefix only for mechanical changes.
Explain why in the body when the diff does not make it obvious.
