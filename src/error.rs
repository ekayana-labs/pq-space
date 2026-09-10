//! Crate error type.

use thiserror::Error;

/// Errors from parsing principals and from wrapping content keys.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// A DID string is not a principal this crate supports.
    #[error("invalid principal: {0}")]
    InvalidPrincipal(&'static str),

    /// A cryptographic operation failed. Opaque by design: which step
    /// failed is not something to branch on or to leak.
    #[error("cryptographic operation failed")]
    Crypto,

    /// A wrapped key or an encoded key is malformed.
    #[error("invalid encoding: {0}")]
    Encoding(&'static str),
}
