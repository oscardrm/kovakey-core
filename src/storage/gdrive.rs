//! Google Drive v3 provider over the `appDataFolder` space (scope `drive.appdata`), ADR 0010.
//!
//! Pure request/response logic: HTTP is injected via [`HttpTransport`], tokens via [`TokenProvider`].
//! The revision check on upload is read-then-write and therefore not atomic (see ADR 0010).

use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::provider::{CloudStorageProvider, RemoteFile, Revision, StorageError, WriteCondition};
use super::transport::{HttpRequest, HttpResponse, HttpTransport, Method};

const API: &str = "https://www.googleapis.com/drive/v3";
const UPLOAD: &str = "https://www.googleapis.com/upload/drive/v3";
const FILE_FIELDS: &str = "id,name,size,modifiedTime,headRevisionId";
const SPACE: &str = "appDataFolder";
const PAGE_SIZE: &str = "100";
/// Hard cap on list pages so a misbehaving server cannot make us loop forever.
const MAX_PAGES: usize = 100;

/// Supplies OAuth access tokens. The platform owns the OAuth flow and refresh.
#[allow(async_fn_in_trait)]
pub trait TokenProvider {
    /// Return a valid access token. `force_refresh` is set on the one retry after a 401.
    async fn access_token(&self, force_refresh: bool) -> Result<Zeroizing<String>, StorageError>;
}

/// In-memory token holder for platforms that refresh tokens themselves and push them in.
#[derive(Default)]
pub struct StaticToken(RwLock<Option<Zeroizing<String>>>);

impl StaticToken {
    /// Create an empty holder (requests fail with `Unauthorized` until a token is set).
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the token. The previous one is zeroized.
    pub fn set(&self, token: String) {
        let mut g = self.0.write().unwrap_or_else(|e| e.into_inner());
        *g = Some(Zeroizing::new(token));
    }

    /// Drop and zeroize the token (e.g. on lock or sign-out).
    pub fn clear(&self) {
        let mut g = self.0.write().unwrap_or_else(|e| e.into_inner());
        *g = None;
    }
}

impl core::fmt::Debug for StaticToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StaticToken(<redacted>)")
    }
}

impl TokenProvider for StaticToken {
    async fn access_token(&self, _force_refresh: bool) -> Result<Zeroizing<String>, StorageError> {
        let g = self.0.read().unwrap_or_else(|e| e.into_inner());
        g.as_ref().cloned().ok_or(StorageError::Unauthorized)
    }
}

/// Google Drive snapshot store.
pub struct GoogleDriveProvider<T, P> {
    http: T,
    tokens: P,
}

impl<T: HttpTransport, P: TokenProvider> GoogleDriveProvider<T, P> {
    /// Build a provider from a platform transport and token source.
    pub fn new(http: T, tokens: P) -> Self {
        Self { http, tokens }
    }

    /// Send a request (built fresh per attempt), adding the bearer token; retry once on 401.
    async fn call(&self, build: impl Fn() -> HttpRequest) -> Result<HttpResponse, StorageError> {
        let mut force = false;
        loop {
            let token = self.tokens.access_token(force).await?;
            let mut req = build();
            req.headers
                .push(("Authorization".into(), format!("Bearer {}", token.as_str())));
            let resp = self
                .http
                .send(&req)
                .await
                .map_err(|_| StorageError::Network)?;
            if resp.status == 401 && !force {
                force = true;
                continue;
            }
            return check_status(resp);
        }
    }

    async fn list_query(&self, q: &str) -> Result<Vec<RemoteFile>, StorageError> {
        let mut out = Vec::new();
        let mut page: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut url = format!(
                "{API}/files?spaces={SPACE}&pageSize={PAGE_SIZE}&orderBy=modifiedTime%20desc\
                 &q={}&fields={}",
                pct(q),
                pct(&format!("nextPageToken,files({FILE_FIELDS})")),
            );
            if let Some(t) = &page {
                url.push_str("&pageToken=");
                url.push_str(&pct(t));
            }
            let resp = self
                .call(|| HttpRequest {
                    method: Method::Get,
                    url: url.clone(),
                    headers: Vec::new(),
                    body: Vec::new(),
                })
                .await?;
            let list: FileList =
                serde_json::from_slice(&resp.body).map_err(|_| StorageError::Serialization)?;
            for f in list.files {
                out.push(f.into_remote()?);
            }
            match list.next_page_token {
                Some(t) if !t.is_empty() => page = Some(t),
                _ => return Ok(out),
            }
        }
        // Too many pages: treat as a malformed/hostile listing rather than truncating silently.
        Err(StorageError::Serialization)
    }

    async fn find_by_name(&self, name: &str) -> Result<Option<RemoteFile>, StorageError> {
        let q = format!("name = '{}' and trashed = false", escape_q(name));
        // Ordered newest first; if a race created duplicates, the newest wins.
        Ok(self.list_query(&q).await?.into_iter().next())
    }
}

impl<T: HttpTransport, P: TokenProvider> CloudStorageProvider for GoogleDriveProvider<T, P> {
    async fn upload_snapshot(
        &self,
        filename: &str,
        data: &[u8],
        condition: WriteCondition,
    ) -> Result<RemoteFile, StorageError> {
        validate_name(filename)?;
        let existing = self.find_by_name(filename).await?;
        let resp = match (condition, existing) {
            (WriteCondition::MustNotExist, Some(_)) | (WriteCondition::IfRevision(_), None) => {
                return Err(StorageError::Conflict)
            }
            (WriteCondition::IfRevision(want), Some(f)) if f.revision != want => {
                return Err(StorageError::Conflict)
            }
            (_, Some(f)) => {
                validate_id(&f.id)?;
                let url = format!(
                    "{UPLOAD}/files/{}?uploadType=media&fields={}",
                    f.id,
                    pct(FILE_FIELDS)
                );
                self.call(|| HttpRequest {
                    method: Method::Patch,
                    url: url.clone(),
                    headers: vec![("Content-Type".into(), "application/octet-stream".into())],
                    body: data.to_vec(),
                })
                .await?
            }
            (_, None) => {
                let meta = serde_json::to_vec(&Metadata {
                    name: filename,
                    parents: Some([SPACE]),
                })
                .map_err(|_| StorageError::Serialization)?;
                let (content_type, body) = multipart(&meta, data);
                let url = format!(
                    "{UPLOAD}/files?uploadType=multipart&fields={}",
                    pct(FILE_FIELDS)
                );
                self.call(|| HttpRequest {
                    method: Method::Post,
                    url: url.clone(),
                    headers: vec![("Content-Type".into(), content_type.clone())],
                    body: body.clone(),
                })
                .await?
            }
        };
        serde_json::from_slice::<DriveFile>(&resp.body)
            .map_err(|_| StorageError::Serialization)?
            .into_remote()
    }

    async fn download_snapshot(&self, file_id: &str) -> Result<Vec<u8>, StorageError> {
        validate_id(file_id)?;
        let url = format!("{API}/files/{file_id}?alt=media");
        let resp = self
            .call(|| HttpRequest {
                method: Method::Get,
                url: url.clone(),
                headers: Vec::new(),
                body: Vec::new(),
            })
            .await?;
        Ok(resp.body.clone())
    }

    async fn list_snapshots(&self) -> Result<Vec<RemoteFile>, StorageError> {
        self.list_query("trashed = false").await
    }

    async fn delete_snapshot(&self, file_id: &str) -> Result<(), StorageError> {
        validate_id(file_id)?;
        let url = format!("{API}/files/{file_id}");
        self.call(|| HttpRequest {
            method: Method::Delete,
            url: url.clone(),
            headers: Vec::new(),
            body: Vec::new(),
        })
        .await
        .map(|_| ())
    }
}

#[derive(Serialize)]
struct Metadata<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    parents: Option<[&'a str; 1]>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DriveFile {
    id: String,
    name: String,
    size: Option<String>,
    modified_time: Option<String>,
    head_revision_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileList {
    #[serde(default)]
    files: Vec<DriveFile>,
    next_page_token: Option<String>,
}

impl DriveFile {
    fn into_remote(self) -> Result<RemoteFile, StorageError> {
        let updated_at = self
            .modified_time
            .as_deref()
            .and_then(parse_rfc3339_millis)
            .ok_or(StorageError::Serialization)?;
        let revision = self
            .head_revision_id
            .filter(|r| !r.is_empty())
            .ok_or(StorageError::Serialization)?;
        let size = match self.size {
            Some(s) => s.parse().map_err(|_| StorageError::Serialization)?,
            None => 0,
        };
        Ok(RemoteFile {
            id: self.id,
            name: self.name,
            size,
            updated_at,
            revision: Revision(revision),
        })
    }
}

/// Map HTTP status to a result. Only coarse substrings of a 403 body are inspected; the body is
/// never copied into an error.
fn check_status(resp: HttpResponse) -> Result<HttpResponse, StorageError> {
    match resp.status {
        200..=299 => Ok(resp),
        401 => Err(StorageError::Unauthorized),
        403 => {
            let body = String::from_utf8_lossy(&resp.body);
            if body.contains("storageQuotaExceeded") {
                Err(StorageError::QuotaExceeded)
            } else if body.contains("ateLimitExceeded") {
                Err(StorageError::RateLimited)
            } else {
                Err(StorageError::Unauthorized)
            }
        }
        404 => Err(StorageError::NotFound),
        409 | 412 => Err(StorageError::Conflict),
        429 => Err(StorageError::RateLimited),
        _ => Err(StorageError::Network),
    }
}

fn validate_name(name: &str) -> Result<(), StorageError> {
    if name.is_empty() || name.len() > 255 || name.chars().any(char::is_control) {
        return Err(StorageError::InvalidInput);
    }
    Ok(())
}

/// Drive ids are URL-safe; refusing anything else prevents path/query injection into URLs.
fn validate_id(id: &str) -> Result<(), StorageError> {
    let ok = !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(StorageError::InvalidInput)
    }
}

/// Escape a value for a Drive `q` string literal.
fn escape_q(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Percent-encode everything except RFC 3986 unreserved characters.
fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Build a `multipart/related` body; the boundary is chosen so it cannot occur in the payload.
fn multipart(meta: &[u8], data: &[u8]) -> (String, Vec<u8>) {
    let mut n = 0u32;
    let boundary = loop {
        let b = format!("kovakey-boundary-{n}");
        let needle = b.as_bytes();
        let clash = |hay: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
        if !clash(meta) && !clash(data) {
            break b;
        }
        n += 1;
    };
    let mut body = Vec::with_capacity(meta.len() + data.len() + 256);
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(meta);
    body.extend_from_slice(
        format!("\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(data);
    body.extend_from_slice(format!("\r\n--{boundary}--").as_bytes());
    (format!("multipart/related; boundary={boundary}"), body)
}

/// Parse `YYYY-MM-DDTHH:MM:SS[.fff]Z` into Unix milliseconds.
fn parse_rfc3339_millis(s: &str) -> Option<i64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-');
    let (y, m, day): (i64, i64, i64) = (
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
    );
    let mut t = time.split(':');
    let h: i64 = t.next()?.parse().ok()?;
    let mi: i64 = t.next()?.parse().ok()?;
    let sec_part = t.next()?;
    if t.next().is_some() || d.next().is_some() {
        return None;
    }
    let (sec, frac) = sec_part.split_once('.').unwrap_or((sec_part, ""));
    let sec: i64 = sec.parse().ok()?;
    if !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut ms = 0i64;
    for i in 0..3 {
        let digit = frac.as_bytes().get(i).map_or(0, |b| i64::from(b - b'0'));
        ms = ms * 10 + digit;
    }
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    // Days from civil (Howard Hinnant).
    let yy = if m <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 24 + h) * 60 + mi) * 60_000 + sec * 1000 + ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::transport::TransportError;
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Wake, Waker};

    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }
    fn block_on<F: Future>(f: F) -> F::Output {
        let waker = Waker::from(Arc::new(Noop));
        let mut cx = Context::from_waker(&waker);
        let mut f = pin!(f);
        loop {
            if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    type Seen = (Method, String, Vec<(String, String)>, Vec<u8>);

    #[derive(Clone, Default)]
    struct Mock {
        replies: Arc<Mutex<VecDeque<Result<HttpResponse, TransportError>>>>,
        seen: Arc<Mutex<Vec<Seen>>>,
    }
    impl Mock {
        fn reply(&self, status: u16, body: &str) -> &Self {
            self.replies.lock().unwrap().push_back(Ok(HttpResponse {
                status,
                body: body.as_bytes().to_vec(),
            }));
            self
        }
        fn seen(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }
    }
    impl HttpTransport for Mock {
        async fn send(&self, r: &HttpRequest) -> Result<HttpResponse, TransportError> {
            self.seen.lock().unwrap().push((
                r.method,
                r.url.clone(),
                r.headers.clone(),
                r.body.clone(),
            ));
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Err(TransportError))
        }
    }

    /// Token source that records the `force_refresh` flags it was asked with.
    #[derive(Default)]
    struct Tokens(Mutex<Vec<bool>>);
    impl TokenProvider for Tokens {
        async fn access_token(&self, force: bool) -> Result<Zeroizing<String>, StorageError> {
            let mut g = self.0.lock().unwrap();
            g.push(force);
            Ok(Zeroizing::new(format!("tok{}", g.len())))
        }
    }

    fn file_json(id: &str, name: &str, rev: &str) -> String {
        format!(
            r#"{{"id":"{id}","name":"{name}","size":"42","modifiedTime":"2026-11-13T10:20:30.500Z","headRevisionId":"{rev}"}}"#
        )
    }
    fn list_json(files: &[String], next: Option<&str>) -> String {
        let n = next.map_or(String::new(), |t| format!(r#","nextPageToken":"{t}""#));
        format!(r#"{{"files":[{}]{n}}}"#, files.join(","))
    }
    fn provider(m: &Mock) -> GoogleDriveProvider<Mock, Tokens> {
        GoogleDriveProvider::new(m.clone(), Tokens::default())
    }
    fn auth(h: &[(String, String)]) -> Option<&str> {
        h.iter()
            .find(|(k, _)| k == "Authorization")
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn rfc3339_known_values() {
        assert_eq!(parse_rfc3339_millis("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_millis("2000-01-01T00:00:00Z"),
            Some(946_684_800_000)
        );
        assert_eq!(
            parse_rfc3339_millis("2024-02-29T12:00:00.123Z"),
            Some(1_709_208_000_123)
        );
        assert_eq!(
            parse_rfc3339_millis("2024-02-29T12:00:00.5Z"),
            Some(1_709_208_000_500)
        );
        for bad in [
            "",
            "2024-13-01T00:00:00Z",
            "2024-01-01 00:00:00Z",
            "2024-01-01T00:00:00+01:00",
            "x",
        ] {
            assert_eq!(parse_rfc3339_millis(bad), None, "{bad}");
        }
    }

    #[test]
    fn create_uses_multipart_in_appdata_with_bearer() {
        let m = Mock::default();
        m.reply(200, &list_json(&[], None))
            .reply(200, &file_json("id1", "a.vault", "r1"));
        let data = b"\x00\x01cipher\xff";
        let f =
            block_on(provider(&m).upload_snapshot("a.vault", data, WriteCondition::Any)).unwrap();
        assert_eq!(f.id, "id1");
        assert_eq!(f.size, 42);
        assert_eq!(f.updated_at, 1_794_565_230_500);
        assert_eq!(f.revision, Revision("r1".into()));
        let seen = m.seen();
        let (method, url, headers, body) = &seen[1];
        assert_eq!(*method, Method::Post);
        assert!(url.contains("uploadType=multipart"));
        assert_eq!(auth(headers), Some("Bearer tok2"));
        let ct = &headers.iter().find(|(k, _)| k == "Content-Type").unwrap().1;
        let boundary = ct.strip_prefix("multipart/related; boundary=").unwrap();
        let text = String::from_utf8_lossy(body);
        assert!(text.contains(r#"{"name":"a.vault","parents":["appDataFolder"]}"#));
        assert!(text.ends_with(&format!("--{boundary}--")));
        assert!(body.windows(data.len()).any(|w| w == data));
        assert!(seen[0].1.contains("spaces=appDataFolder"));
    }

    #[test]
    fn update_when_revision_matches() {
        let m = Mock::default();
        m.reply(200, &list_json(&[file_json("id1", "a.vault", "r1")], None))
            .reply(200, &file_json("id1", "a.vault", "r2"));
        let f = block_on(provider(&m).upload_snapshot(
            "a.vault",
            b"new",
            WriteCondition::IfRevision(Revision("r1".into())),
        ))
        .unwrap();
        assert_eq!(f.revision, Revision("r2".into()));
        let seen = m.seen();
        assert_eq!(seen[1].0, Method::Patch);
        assert!(seen[1].1.contains("/files/id1?uploadType=media"));
        assert_eq!(seen[1].3, b"new");
    }

    #[test]
    fn conflicts_do_not_write() {
        let existing = list_json(&[file_json("id1", "a.vault", "r1")], None);
        let cases = [
            (
                WriteCondition::IfRevision(Revision("old".into())),
                existing.clone(),
            ),
            (WriteCondition::MustNotExist, existing),
            (
                WriteCondition::IfRevision(Revision("r1".into())),
                list_json(&[], None),
            ),
        ];
        for (cond, listing) in cases {
            let m = Mock::default();
            m.reply(200, &listing);
            let r = block_on(provider(&m).upload_snapshot("a.vault", b"x", cond));
            assert_eq!(r, Err(StorageError::Conflict));
            assert_eq!(m.seen().len(), 1, "only the lookup may be sent");
        }
    }

    #[test]
    fn list_follows_pagination() {
        let m = Mock::default();
        m.reply(200, &list_json(&[file_json("a", "1", "r")], Some("T 1")))
            .reply(200, &list_json(&[file_json("b", "2", "r")], None));
        let files = block_on(provider(&m).list_snapshots()).unwrap();
        assert_eq!(
            files.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
        let seen = m.seen();
        assert!(!seen[0].1.contains("pageToken"));
        assert!(seen[1].1.contains("pageToken=T%201"));
    }

    #[test]
    fn list_stops_at_page_cap() {
        let m = Mock::default();
        for _ in 0..=MAX_PAGES {
            m.reply(200, &list_json(&[], Some("more")));
        }
        assert_eq!(
            block_on(provider(&m).list_snapshots()),
            Err(StorageError::Serialization)
        );
        assert_eq!(m.seen().len(), MAX_PAGES);
    }

    #[test]
    fn download_and_delete() {
        let m = Mock::default();
        m.reply(200, "bytes").reply(204, "");
        let p = provider(&m);
        assert_eq!(block_on(p.download_snapshot("id_1-x")).unwrap(), b"bytes");
        block_on(p.delete_snapshot("id_1-x")).unwrap();
        let seen = m.seen();
        assert!(seen[0].1.ends_with("/files/id_1-x?alt=media"));
        assert_eq!(seen[1].0, Method::Delete);
    }

    #[test]
    fn retries_once_with_forced_refresh_on_401() {
        let m = Mock::default();
        m.reply(401, "{}").reply(200, "ok");
        let p = provider(&m);
        assert_eq!(block_on(p.download_snapshot("a")).unwrap(), b"ok");
        assert_eq!(*p.tokens.0.lock().unwrap(), [false, true]);
        assert_eq!(auth(&m.seen()[1].2), Some("Bearer tok2"));

        let m = Mock::default();
        m.reply(401, "{}").reply(401, "{}");
        assert_eq!(
            block_on(provider(&m).download_snapshot("a")),
            Err(StorageError::Unauthorized)
        );
        assert_eq!(m.seen().len(), 2);
    }

    #[test]
    fn status_mapping() {
        let cases = [
            (404, "", StorageError::NotFound),
            (412, "", StorageError::Conflict),
            (429, "", StorageError::RateLimited),
            (
                403,
                r#"{"reason":"userRateLimitExceeded"}"#,
                StorageError::RateLimited,
            ),
            (
                403,
                r#"{"reason":"storageQuotaExceeded"}"#,
                StorageError::QuotaExceeded,
            ),
            (403, r#"{"reason":"forbidden"}"#, StorageError::Unauthorized),
            (500, "", StorageError::Network),
        ];
        for (status, body, want) in cases {
            let m = Mock::default();
            m.reply(status, body);
            assert_eq!(
                block_on(provider(&m).download_snapshot("a")),
                Err(want),
                "{status}"
            );
        }
        // Transport failure and malformed JSON.
        assert_eq!(
            block_on(provider(&Mock::default()).download_snapshot("a")),
            Err(StorageError::Network)
        );
        let m = Mock::default();
        m.reply(200, "not json");
        assert_eq!(
            block_on(provider(&m).list_snapshots()),
            Err(StorageError::Serialization)
        );
    }

    #[test]
    fn rejects_unsafe_ids_and_escapes_names() {
        let m = Mock::default();
        let p = provider(&m);
        for bad in ["", "a/b", "a?x=1", "a b", "../x"] {
            assert_eq!(
                block_on(p.download_snapshot(bad)),
                Err(StorageError::InvalidInput)
            );
            assert_eq!(
                block_on(p.delete_snapshot(bad)),
                Err(StorageError::InvalidInput)
            );
        }
        assert_eq!(
            block_on(p.upload_snapshot("", b"x", WriteCondition::Any)),
            Err(StorageError::InvalidInput)
        );
        assert!(m.seen().is_empty());

        m.reply(200, &list_json(&[], None))
            .reply(200, &file_json("i", "n", "r"));
        block_on(p.upload_snapshot("it's\\x", b"x", WriteCondition::Any)).unwrap();
        // q = name = 'it\'s\\x' and trashed = false  (percent-encoded)
        assert!(m.seen()[0]
            .1
            .contains(&pct(r"name = 'it\'s\\x' and trashed = false")));
    }

    #[test]
    fn multipart_boundary_avoids_payload() {
        let data = b"xx kovakey-boundary-0 yy kovakey-boundary-1 zz";
        let (ct, body) = multipart(b"{}", data);
        let b = ct.strip_prefix("multipart/related; boundary=").unwrap();
        assert_eq!(b, "kovakey-boundary-2");
        let hits = body.windows(b.len()).filter(|w| *w == b.as_bytes()).count();
        assert_eq!(hits, 3);
    }

    #[test]
    fn secrets_do_not_leak_via_debug_or_errors() {
        let req = HttpRequest {
            method: Method::Get,
            url: "https://x/secret-id".into(),
            headers: vec![("Authorization".into(), "Bearer SECRETTOKEN".into())],
            body: b"ciphertext".to_vec(),
        };
        let dbg = format!("{req:?}");
        assert!(!dbg.contains("SECRETTOKEN") && !dbg.contains("secret-id"));
        let t = StaticToken::new();
        t.set("SECRETTOKEN".into());
        assert!(!format!("{t:?}").contains("SECRETTOKEN"));
        let resp = HttpResponse {
            status: 200,
            body: b"SECRETBODY".to_vec(),
        };
        assert!(!format!("{resp:?}").contains("SECRETBODY"));
    }

    #[test]
    fn static_token_set_clear() {
        let t = StaticToken::new();
        assert_eq!(
            block_on(t.access_token(false)).unwrap_err(),
            StorageError::Unauthorized
        );
        t.set("a".into());
        assert_eq!(block_on(t.access_token(false)).unwrap().as_str(), "a");
        t.clear();
        assert_eq!(
            block_on(t.access_token(true)).unwrap_err(),
            StorageError::Unauthorized
        );
    }
}
