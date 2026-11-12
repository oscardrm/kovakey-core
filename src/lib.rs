//! TrueVault core: all business logic (crypto, key hierarchy, recovery, storage).
#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

pub mod codec;
pub mod crypto;
#[cfg(feature = "sqlcipher")]
pub mod db;
pub mod error;
pub mod generator;
pub mod kdf;
pub mod keys;
pub mod merge;
pub mod models;
pub mod notes;
pub mod recovery;
pub mod side_blob;
pub mod tagger;
pub mod totp;
pub mod vault_file;

pub use error::{Error, Result};
