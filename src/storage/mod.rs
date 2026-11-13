//! Cloud storage abstraction (ADR 0010): providers move already-encrypted `.vault` bytes only.

#[cfg(feature = "gdrive")]
pub mod gdrive;
pub mod provider;
pub mod transport;

pub use provider::{CloudStorageProvider, RemoteFile, Revision, StorageError, WriteCondition};
pub use transport::{HttpRequest, HttpResponse, HttpTransport, Method, TransportError};
