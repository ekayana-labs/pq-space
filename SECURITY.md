# Security Policy

## Reporting security problems

Do not open a GitHub issue to report a security problem.

Please use the
[Report a Vulnerability](https://github.com/ekayana-labs/pq-space/security/advisories/new)
link with a helpful title and a detailed description of the problem.
Expect a response typically within 72 hours.

If you receive no response in the advisory, email <suraj410401@gmail.com>
with the advisory URL. Keep exploit details in the advisory and out of the
email.

## Scope

The scope is anything that lets a party read a content key it was not
delegated, or lets a delegation verify under a key that did not sign it.
That includes the cases below.

- A wrap opens under the wrong AAD, the wrong recipient, or after
  tampering.
- A `BioResolver` answers with a key other than the one embedded in the
  `did:bio` identifier, or a `BioSigner` names an issuer that does not
  match its signing key.
- Key material or a shared secret reaches a log, an error message, or a
  serialized form that was meant to stay private.
- Untrusted input causes a panic. Identifiers, delegation bytes, `meta`
  entries and encapsulation keys all arrive from the network.

Weaknesses in the underlying primitives belong upstream. Report ML-KEM,
ML-DSA, HKDF and AES-GCM issues to
[aws-lc-rs](https://github.com/aws/aws-lc-rs), and token, signature or
chain validation issues to
[pq-ucan](https://github.com/ekayana-labs/pq-ucan). Reports here are still
welcome if this crate uses them wrongly.

## Status

This crate has not received an external audit. The ML-DSA-87 varsig
header pq-ucan emits is provisional pending registration, so tokens signed
today may not verify against a future registry assignment.
