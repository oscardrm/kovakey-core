//! Minimal HTTP abstraction injected by each platform (URLSession, OkHttp, `fetch`, ...).

use core::fmt;
use thiserror::Error;
use zeroize::Zeroize;

/// HTTP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// GET
    Get,
    /// POST
    Post,
    /// PATCH
    Patch,
    /// DELETE
    Delete,
}

/// An outgoing request. `Debug` is redacted; header values are zeroized on drop (they carry tokens).
pub struct HttpRequest {
    /// Method.
    pub method: Method,
    /// Absolute URL (never contains credentials).
    pub url: String,
    /// Header name/value pairs.
    pub headers: Vec<(String, String)>,
    /// Request body.
    pub body: Vec<u8>,
}

impl Drop for HttpRequest {
    fn drop(&mut self) {
        for (_, v) in &mut self.headers {
            v.zeroize();
        }
    }
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &"<redacted>")
            .field("headers", &"<redacted>")
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// A response from the transport.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body.
    pub body: Vec<u8>,
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// The request could not be delivered (DNS, TLS, timeout, ...). Details are deliberately dropped.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("transport error")]
pub struct TransportError;

/// Platform-provided HTTP client.
#[allow(async_fn_in_trait)]
pub trait HttpTransport {
    /// Perform the request and return the response regardless of status code.
    async fn send(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError>;
}
