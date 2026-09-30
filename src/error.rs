//! Crate error type.

use thiserror::Error;

/// Errors from parsing principals and from wrapping content keys.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A DID string is not a principal this crate supports.
    #[error("invalid principal: {0}")]
    InvalidPrincipal(&'static str),

    /// A cryptographic operation failed. The error does not say which step
    /// failed, so callers cannot branch on it and it cannot leak.
    #[error("cryptographic operation failed")]
    Crypto,

    /// A wrapped key or an encoded key is malformed.
    #[error("invalid encoding: {0}")]
    Encoding(&'static str),
}
