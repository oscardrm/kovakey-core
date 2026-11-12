//! Coarse, secret-free error type. Wrong-password and corruption are deliberately
//! indistinguishable (`Decryption`) to avoid oracles.

use thiserror::Error;

/// Errors returned by `vault-core`. Messages never contain secret material.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// Wrong key/password, or the data was tampered with or corrupted.
    #[error("decryption failed")]
    Decryption,
    /// Malformed input (truncated, bad encoding, bad checksum).
    #[error("invalid or corrupted data")]
    Corrupted,
    /// File/format version is not supported by this build.
    #[error("unsupported format version")]
    UnsupportedVersion,
    /// KDF parameters are below the security floor or out of range.
    #[error("invalid key derivation parameters")]
    InvalidParams,
    /// The OS random number generator failed.
    #[error("random number generation failed")]
    Rng,
    /// The referenced record does not exist (or is deleted).
    #[error("record not found")]
    NotFound,
    /// Input violates an invariant (empty name, unknown type, duplicate id, ...).
    #[error("invalid input")]
    InvalidInput,
    /// Database failure (details withheld to avoid leaking data).
    #[error("database error")]
    Database,
}

/// Crate result alias.
pub type Result<T> = core::result::Result<T, Error>;
