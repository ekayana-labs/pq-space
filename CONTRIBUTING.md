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

## Rules of the road

- **Fail closed.** A wrap presented with the wrong AAD and a malformed
  encapsulation key must return an error, and a token pq-ucan refuses is
  never accepted around it. Add the hostile case to the tests in the same
  change.
- **Bind every wrap to its grant.** A wrapped key that opens outside the
  delegation it was issued for is the bug this crate exists to prevent.
  New wrapping paths take an AAD and document what it covers.
- **Untrusted input never panics.** Identifiers, delegation bytes, `meta`
  entries, and keys all arrive from the network. Return `Error`.
- **Errors stay opaque about cryptography.** `Error::Crypto` deliberately
  says nothing about which step failed.
- **Match the wire format, do not invent one.** Multicodec prefixes and the
  `meta` key are interoperability surface; varsig headers belong to
  pq-ucan. Change them only with a note in the changelog and a round trip
  test.
- **No `unsafe`, every public item documented.** The crate enforces both.

## Publishing

Every dependency comes from crates.io. Date the changelog, then
`cargo publish`.

## Commit messages

Short, capitalized, imperative subject with no trailing period: `Add key
wrapping`, `Reject mismatched signature algorithms`. Use a `ci:`, `docs:`,
`deps:`, or `chore:` prefix only for mechanical changes. Explain why in the
body when the diff does not make it obvious.
