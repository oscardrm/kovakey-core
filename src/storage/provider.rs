//! Provider-agnostic storage trait. Providers only ever see ciphertext.

use thiserror::Error;

/// Storage failures. Messages never contain URLs, headers, tokens or response bodies.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum StorageError {
    /// Transport failure or unexpected server error.
    #[error("network error")]
    Network,
    /// Missing, expired or insufficient credentials.
    #[error("unauthorized")]
    Unauthorized,
    /// The remote file does not exist.
    #[error("remote file not found")]
    NotFound,
    /// The remote file changed (or already exists) relative to the write condition.
    #[error("remote conflict")]
    Conflict,
    /// The provider asked us to slow down.
    #[error("rate limited")]
    RateLimited,
    /// The account is out of storage space.
    #[error("storage quota exceeded")]
    QuotaExceeded,
    /// The provider response could not be parsed.
    #[error("serialization error")]
    Serialization,
    /// A caller-supplied name or id is not acceptable.
    #[error("invalid input")]
    InvalidInput,
}

/// Opaque version identifier of a remote file; changes on every write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision(pub String);

/// Metadata of a file stored at the provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteFile {
    /// Provider-specific file id.
    pub id: String,
    /// File name.
    pub name: String,
    /// Size in bytes.
    pub size: u64,
    /// Last modification, Unix milliseconds (UTC).
    pub updated_at: i64,
    /// Current revision, for [`WriteCondition::IfRevision`].
    pub revision: Revision,
}

/// Precondition for [`CloudStorageProvider::upload_snapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteCondition {
    /// Create or overwrite unconditionally.
    Any,
    /// Fail with [`StorageError::Conflict`] if a file with this name exists.
    MustNotExist,
    /// Fail with [`StorageError::Conflict`] unless the remote is at this revision.
    IfRevision(Revision),
}

/// A place that stores encrypted vault snapshots.
// Used through generics (no `dyn`), so the missing `Send` bound is deliberate: it keeps the trait
// usable on single-threaded wasm and on multi-threaded native executors alike.
#[allow(async_fn_in_trait)]
pub trait CloudStorageProvider {
    /// Create or update (upsert by `filename`) a snapshot, honouring `condition`.
    async fn upload_snapshot(
        &self,
        filename: &str,
        data: &[u8],
        condition: WriteCondition,
    ) -> Result<RemoteFile, StorageError>;

    /// Download a snapshot's bytes.
    async fn download_snapshot(&self, file_id: &str) -> Result<Vec<u8>, StorageError>;

    /// List all snapshots (follows provider pagination).
    async fn list_snapshots(&self) -> Result<Vec<RemoteFile>, StorageError>;

    /// Permanently delete a snapshot.
    async fn delete_snapshot(&self, file_id: &str) -> Result<(), StorageError>;
}
