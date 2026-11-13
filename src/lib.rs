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
pub mod import;
pub mod kdf;
pub mod keys;
pub mod mem_store;
pub mod merge;
pub mod models;
pub mod notes;
pub mod ops;
pub mod presets;
pub mod recovery;
pub mod search;
pub mod session;
pub mod side_blob;
pub mod strength;
pub mod tagger;
pub mod totp;
pub mod vault_file;
pub mod wifi;

pub use error::{Error, Result};
