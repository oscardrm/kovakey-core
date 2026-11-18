//! Shared-vault operations on Google Drive (ADR 0021, scope `drive.file`).
//!
//! Unlike personal sync (`appDataFolder`, not shareable), a shared vault lives in the owner's regular
//! Drive inside a `Kovakey Shared` folder, tagged with private `appProperties`, and is addressed by
//! file id. Everything here moves ciphertext only; the shared vault has its own password, validated
//! by the caller opening the downloaded bytes.

use serde::{Deserialize, Serialize};

use super::gdrive::{
    escape_q, multipart_typed, pct, validate_id, validate_name, DriveFile, GoogleDriveProvider,
    TokenProvider, API, FILE_FIELDS, UPLOAD,
};
use super::provider::{RemoteFile, StorageError, WriteCondition};
use super::transport::{HttpRequest, HttpTransport, Method};

/// Name of the folder that holds shared vaults in the owner's Drive.
pub const SHARED_FOLDER_NAME: &str = "Kovakey Shared";
const FOLDER_MIME: &str = "application/vnd.google-apps.folder";
/// MIME type of every shared vault file in Drive. A type of its own lets the Google Picker (desktop/mobile
/// mode, which can only filter by `mimetypes` or `file_ids`) show a member just the vault files, not their
/// whole Drive. It is a plain identifier, not a secret. Files created before this type existed get it on
/// their next upload.
pub const SHARED_VAULT_MIME: &str = "application/vnd.kovakey.shared-vault";
const MAX_DISPLAY_NAME: usize = 80;
const MAX_EMAIL: usize = 254;
const MAX_MESSAGE: usize = 500;

/// Pointer to a shared vault in Drive. Holds no keys or passwords; safe to store in preferences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedVaultRef {
    /// Drive file id of the `.vault`.
    pub file_id: String,
    /// Id of the `Kovakey Shared` folder (known only to the owner).
    pub folder_id: Option<String>,
    /// Sanitized, truncated display name (untrusted: display only).
    pub display_name: String,
}

/// Strip control characters and truncate a remote-controlled name for display.
pub fn sanitize_display_name(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control())
        .take(MAX_DISPLAY_NAME)
        .collect()
}

impl<T: HttpTransport, P: TokenProvider> GoogleDriveProvider<T, P> {
    /// Create `name` as a new shared vault: find-or-create the `Kovakey Shared` folder, upload the
    /// ciphertext into it and tag the file. Never overwrites an existing file.
    pub async fn create_shared_vault(
        &self,
        name: &str,
        data: &[u8],
    ) -> Result<(SharedVaultRef, RemoteFile), StorageError> {
        validate_name(name)?;
        let folder_id = self.find_or_create_shared_folder().await?;
        let meta = serde_json::to_vec(&CreateMeta {
            name,
            mime_type: SHARED_VAULT_MIME,
            parents: [&folder_id],
            app_properties: AppProps {
                kovakey: "shared-vault",
                v: "1",
            },
        })
        .map_err(|_| StorageError::Serialization)?;
        let (content_type, body) = multipart_typed(&meta, data, SHARED_VAULT_MIME);
        let url = format!(
            "{UPLOAD}/files?uploadType=multipart&fields={}",
            pct(FILE_FIELDS)
        );
        let resp = self
            .call(|| HttpRequest {
                method: Method::Post,
                url: url.clone(),
                headers: vec![("Content-Type".into(), content_type.clone())],
                body: body.clone(),
            })
            .await?;
        let file = parse_file(&resp.body)?;
        let reference = SharedVaultRef {
            file_id: file.id.clone(),
            folder_id: Some(folder_id),
            display_name: sanitize_display_name(&file.name),
        };
        Ok((reference, file))
    }

    /// Grant `email` edit access to a shared vault and let Google send the notification. The
    /// message must not contain the vault password (the UI never offers it).
    pub async fn share_shared_vault(
        &self,
        file_id: &str,
        email: &str,
        message: &str,
    ) -> Result<(), StorageError> {
        validate_id(file_id)?;
        validate_email(email)?;
        if message.len() > MAX_MESSAGE || message.chars().any(|c| c.is_control() && c != '\n') {
            return Err(StorageError::InvalidInput);
        }
        let body = serde_json::to_vec(&Permission {
            kind: "user",
            role: "writer",
            email_address: email,
        })
        .map_err(|_| StorageError::Serialization)?;
        let url = format!(
            "{API}/files/{file_id}/permissions?sendNotificationEmail=true&emailMessage={}&fields=id",
            pct(message)
        );
        self.call(|| HttpRequest {
            method: Method::Post,
            url: url.clone(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: body.clone(),
        })
        .await
        .map(|_| ())
    }

    /// Current metadata (revision, size, modified time) of a shared vault by file id.
    pub async fn shared_vault_metadata(&self, file_id: &str) -> Result<RemoteFile, StorageError> {
        validate_id(file_id)?;
        // `trashed` is true for a file in the Trash and for one inside a trashed folder. Such a vault was
        // removed by its owner, so it counts as gone exactly like a permanently deleted one.
        let url = format!(
            "{API}/files/{file_id}?fields={}",
            pct(&format!("{FILE_FIELDS},trashed"))
        );
        let resp = self
            .call(|| HttpRequest {
                method: Method::Get,
                url: url.clone(),
                headers: Vec::new(),
                body: Vec::new(),
            })
            .await?;
        parse_live_file(&resp.body)
    }

    /// Whether the signed-in user owns the shared vault file (Drive's `ownedByMe`), so apps can offer owner-only
    /// actions on every device of the owner. A trashed or missing file is `NotFound`, as in `shared_vault_metadata`.
    pub async fn shared_vault_owned_by_me(&self, file_id: &str) -> Result<bool, StorageError> {
        validate_id(file_id)?;
        let url = format!("{API}/files/{file_id}?fields={}", pct("ownedByMe,trashed"));
        let resp = self
            .call(|| HttpRequest {
                method: Method::Get,
                url: url.clone(),
                headers: Vec::new(),
                body: Vec::new(),
            })
            .await?;
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Ownership {
            #[serde(default)]
            owned_by_me: bool,
            #[serde(default)]
            trashed: bool,
        }
        let o: Ownership =
            serde_json::from_slice(&resp.body).map_err(|_| StorageError::Serialization)?;
        if o.trashed {
            return Err(StorageError::NotFound);
        }
        Ok(o.owned_by_me)
    }

    /// Overwrite a shared vault by file id, honouring `condition` (read-then-write, like personal
    /// sync). `MustNotExist` is meaningless for an existing id and is rejected.
    pub async fn upload_shared_vault(
        &self,
        file_id: &str,
        data: &[u8],
        condition: WriteCondition,
    ) -> Result<RemoteFile, StorageError> {
        validate_id(file_id)?;
        match condition {
            WriteCondition::MustNotExist => return Err(StorageError::InvalidInput),
            WriteCondition::IfRevision(want) => {
                if self.shared_vault_metadata(file_id).await?.revision != want {
                    return Err(StorageError::Conflict);
                }
            }
            WriteCondition::Any => {}
        }
        // Multipart (metadata + content) so every upload also stamps the shared-vault MIME type: files created
        // before it existed are migrated the next time their owner or a member syncs them.
        let meta = serde_json::to_vec(&UpdateMeta {
            mime_type: SHARED_VAULT_MIME,
        })
        .map_err(|_| StorageError::Serialization)?;
        let (content_type, body) = multipart_typed(&meta, data, SHARED_VAULT_MIME);
        let url = format!(
            "{UPLOAD}/files/{file_id}?uploadType=multipart&fields={}",
            pct(FILE_FIELDS)
        );
        let resp = self
            .call(|| HttpRequest {
                method: Method::Patch,
                url: url.clone(),
                headers: vec![("Content-Type".into(), content_type.clone())],
                body: body.clone(),
            })
            .await?;
        parse_file(&resp.body)
    }

    async fn find_or_create_shared_folder(&self) -> Result<String, StorageError> {
        let q = format!(
            "name = '{}' and mimeType = '{FOLDER_MIME}' and trashed = false \
             and appProperties has {{ key='kovakey' and value='shared-folder' }}",
            escape_q(SHARED_FOLDER_NAME)
        );
        let url = format!(
            "{API}/files?spaces=drive&pageSize=1&orderBy=createdTime&q={}&fields={}",
            pct(&q),
            pct("files(id)")
        );
        let resp = self
            .call(|| HttpRequest {
                method: Method::Get,
                url: url.clone(),
                headers: Vec::new(),
                body: Vec::new(),
            })
            .await?;
        let list: IdList =
            serde_json::from_slice(&resp.body).map_err(|_| StorageError::Serialization)?;
        if let Some(f) = list.files.into_iter().next() {
            validate_id(&f.id)?;
            return Ok(f.id);
        }
        let body = serde_json::to_vec(&FolderMeta {
            name: SHARED_FOLDER_NAME,
            mime_type: FOLDER_MIME,
            app_properties: AppProps {
                kovakey: "shared-folder",
                v: "1",
            },
        })
        .map_err(|_| StorageError::Serialization)?;
        let url = format!("{API}/files?fields=id");
        let resp = self
            .call(|| HttpRequest {
                method: Method::Post,
                url: url.clone(),
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: body.clone(),
            })
            .await?;
        let created: IdOnly =
            serde_json::from_slice(&resp.body).map_err(|_| StorageError::Serialization)?;
        validate_id(&created.id)?;
        Ok(created.id)
    }
}

/// Like `parse_file`, but a trashed file is `NotFound`.
fn parse_live_file(body: &[u8]) -> Result<RemoteFile, StorageError> {
    let file =
        serde_json::from_slice::<DriveFile>(body).map_err(|_| StorageError::Serialization)?;
    if file.trashed {
        return Err(StorageError::NotFound);
    }
    file.into_remote()
}

fn parse_file(body: &[u8]) -> Result<RemoteFile, StorageError> {
    serde_json::from_slice::<DriveFile>(body)
        .map_err(|_| StorageError::Serialization)?
        .into_remote()
}

/// Conservative email check: one `@`, no whitespace/control/quote characters, bounded length.
fn validate_email(email: &str) -> Result<(), StorageError> {
    let ok = email.len() <= MAX_EMAIL
        && email.matches('@').count() == 1
        && !email.starts_with('@')
        && !email.ends_with('@')
        && email.chars().all(|c| {
            !c.is_control()
                && !c.is_whitespace()
                && !matches!(c, '"' | '\'' | '\\' | ',' | ';' | '<' | '>')
        });
    if ok {
        Ok(())
    } else {
        Err(StorageError::InvalidInput)
    }
}

#[derive(Serialize)]
struct AppProps {
    kovakey: &'static str,
    v: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateMeta<'a> {
    name: &'a str,
    mime_type: &'a str,
    parents: [&'a str; 1],
    app_properties: AppProps,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateMeta<'a> {
    mime_type: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FolderMeta<'a> {
    name: &'a str,
    mime_type: &'a str,
    app_properties: AppProps,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Permission<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    role: &'a str,
    email_address: &'a str,
}

#[derive(Deserialize)]
struct IdList {
    #[serde(default)]
    files: Vec<IdOnly>,
}

#[derive(Deserialize)]
struct IdOnly {
    id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::gdrive::TokenProvider;
    use crate::storage::provider::Revision;
    use crate::storage::transport::{HttpResponse, TransportError};
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Wake, Waker};
    use zeroize::Zeroizing;

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

    type Seen = (Method, String, Vec<u8>);

    #[derive(Clone, Default)]
    struct Mock {
        replies: Arc<Mutex<VecDeque<HttpResponse>>>,
        seen: Arc<Mutex<Vec<Seen>>>,
    }
    impl Mock {
        fn reply(&self, status: u16, body: &str) -> &Self {
            self.replies.lock().unwrap().push_back(HttpResponse {
                status,
                body: body.as_bytes().to_vec(),
            });
            self
        }
        fn seen(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }
    }
    impl HttpTransport for Mock {
        async fn send(&self, r: &HttpRequest) -> Result<HttpResponse, TransportError> {
            self.seen
                .lock()
                .unwrap()
                .push((r.method, r.url.clone(), r.body.clone()));
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .ok_or(TransportError)
        }
    }
    struct Tok;
    impl TokenProvider for Tok {
        async fn access_token(&self, _f: bool) -> Result<Zeroizing<String>, StorageError> {
            Ok(Zeroizing::new("tok".into()))
        }
    }
    fn provider(m: &Mock) -> GoogleDriveProvider<Mock, Tok> {
        GoogleDriveProvider::new(m.clone(), Tok)
    }
    fn file_json(id: &str, name: &str, rev: &str) -> String {
        format!(
            r#"{{"id":"{id}","name":"{name}","size":"42","modifiedTime":"2026-11-13T10:20:30.500Z","headRevisionId":"{rev}"}}"#
        )
    }

    #[test]
    fn create_makes_folder_then_tags_file() {
        let m = Mock::default();
        m.reply(200, r#"{"files":[]}"#)
            .reply(200, r#"{"id":"fold1"}"#)
            .reply(200, &file_json("file1", "Team.vault", "r1"));
        let (r, f) = block_on(provider(&m).create_shared_vault("Team.vault", b"cipher")).unwrap();
        assert_eq!(r.file_id, "file1");
        assert_eq!(r.folder_id.as_deref(), Some("fold1"));
        assert_eq!(f.revision, Revision("r1".into()));
        let seen = m.seen();
        assert!(seen[0].1.contains("spaces=drive"));
        assert!(!seen[0].1.contains("appDataFolder"));
        let folder = String::from_utf8_lossy(&seen[1].2).into_owned();
        assert!(folder.contains(FOLDER_MIME) && folder.contains("shared-folder"));
        let file = String::from_utf8_lossy(&seen[2].2).into_owned();
        assert!(file.contains(r#""parents":["fold1"]"#));
        assert!(file.contains(r#""appProperties":{"kovakey":"shared-vault","v":"1"}"#));
        assert!(!file.contains("appDataFolder"));
        // The dedicated MIME type is what lets the Picker filter to vault files (kovakey-core#4).
        assert!(file.contains(&format!(r#""mimeType":"{SHARED_VAULT_MIME}""#)));
        assert!(file.contains(&format!("Content-Type: {SHARED_VAULT_MIME}")));
        assert!(!file.contains("application/octet-stream"));
    }

    #[test]
    fn shared_vault_mime_is_a_stable_vendor_type() {
        // The apps hard-code nothing: they read this constant. Changing it would hide every existing vault from
        // the filtered Picker, so a change must be deliberate.
        assert_eq!(SHARED_VAULT_MIME, "application/vnd.kovakey.shared-vault");
        assert!(SHARED_VAULT_MIME.starts_with("application/vnd."));
    }

    #[test]
    fn create_reuses_existing_folder() {
        let m = Mock::default();
        m.reply(200, r#"{"files":[{"id":"fold9"}]}"#)
            .reply(200, &file_json("file1", "T.vault", "r1"));
        let (r, _) = block_on(provider(&m).create_shared_vault("T.vault", b"x")).unwrap();
        assert_eq!(r.folder_id.as_deref(), Some("fold9"));
        assert_eq!(m.seen().len(), 2);
    }

    #[test]
    fn share_sends_writer_permission_and_email() {
        let m = Mock::default();
        m.reply(200, r#"{"id":"p1"}"#);
        block_on(provider(&m).share_shared_vault("file1", "bob@example.com", "Open Kovakey"))
            .unwrap();
        let seen = m.seen();
        assert_eq!(seen[0].0, Method::Post);
        assert!(seen[0].1.contains("/files/file1/permissions"));
        assert!(seen[0].1.contains("sendNotificationEmail=true"));
        assert!(seen[0].1.contains("emailMessage=Open%20Kovakey"));
        let body = String::from_utf8_lossy(&seen[0].2).into_owned();
        assert!(body.contains(r#""type":"user""#) && body.contains(r#""role":"writer""#));
        assert!(body.contains(r#""emailAddress":"bob@example.com""#));
    }

    #[test]
    fn share_rejects_bad_input_without_network() {
        let m = Mock::default();
        let p = provider(&m);
        for email in [
            "",
            "a",
            "a@@b.c",
            "a b@c.d",
            "a@b.c,d@e.f",
            "\"a\"@b.c",
            "@b.c",
        ] {
            assert_eq!(
                block_on(p.share_shared_vault("file1", email, "")),
                Err(StorageError::InvalidInput),
                "{email}"
            );
        }
        assert_eq!(
            block_on(p.share_shared_vault("a/b", "a@b.c", "")),
            Err(StorageError::InvalidInput)
        );
        assert_eq!(
            block_on(p.share_shared_vault("file1", "a@b.c", "x\r\ny\u{0}")),
            Err(StorageError::InvalidInput)
        );
        assert!(m.seen().is_empty());
    }

    #[test]
    fn a_trashed_vault_is_reported_as_not_found_for_metadata_and_uploads() {
        let trashed = r#"{"id":"file1","name":"T.vault","size":"1","modifiedTime":"2026-01-01T00:00:00Z","headRevisionId":"r1","trashed":true}"#;
        let m = Mock::default();
        m.reply(200, trashed);
        assert_eq!(
            block_on(provider(&m).shared_vault_metadata("file1")),
            Err(StorageError::NotFound)
        );
        assert!(m.seen()[0].1.contains("trashed"), "the field is requested");

        // A conditional upload reads the metadata first, so it never writes into a trashed file.
        let m = Mock::default();
        m.reply(200, trashed);
        assert_eq!(
            block_on(provider(&m).upload_shared_vault(
                "file1",
                b"x",
                WriteCondition::IfRevision(Revision("r1".into()))
            )),
            Err(StorageError::NotFound)
        );
        assert_eq!(m.seen().len(), 1, "no write after a trashed file");

        // A live file (trashed false or absent) is returned as before.
        let m = Mock::default();
        m.reply(200, &file_json("file1", "T.vault", "r1"));
        assert!(block_on(provider(&m).shared_vault_metadata("file1")).is_ok());
    }

    #[test]
    fn ownership_reads_owned_by_me_and_treats_trash_as_not_found() {
        let m = Mock::default();
        m.reply(200, r#"{"ownedByMe":true}"#)
            .reply(200, r#"{"ownedByMe":false}"#)
            .reply(200, "{}")
            .reply(200, r#"{"ownedByMe":true,"trashed":true}"#)
            .reply(404, "{}");
        let p = provider(&m);
        assert_eq!(block_on(p.shared_vault_owned_by_me("file1")), Ok(true));
        assert_eq!(block_on(p.shared_vault_owned_by_me("file1")), Ok(false));
        assert_eq!(
            block_on(p.shared_vault_owned_by_me("file1")),
            Ok(false),
            "absent means not owned"
        );
        assert_eq!(
            block_on(p.shared_vault_owned_by_me("file1")),
            Err(StorageError::NotFound)
        );
        assert_eq!(
            block_on(p.shared_vault_owned_by_me("file1")),
            Err(StorageError::NotFound)
        );
        assert!(m.seen()[0].1.contains("ownedByMe"));
        assert_eq!(
            block_on(provider(&Mock::default()).shared_vault_owned_by_me("../x")),
            Err(StorageError::InvalidInput)
        );
    }

    #[test]
    fn upload_by_id_checks_revision() {
        let m = Mock::default();
        m.reply(200, &file_json("file1", "T.vault", "r2"));
        let r = block_on(provider(&m).upload_shared_vault(
            "file1",
            b"x",
            WriteCondition::IfRevision(Revision("r1".into())),
        ));
        assert_eq!(r, Err(StorageError::Conflict));
        assert_eq!(m.seen().len(), 1, "no write after a revision mismatch");

        let m = Mock::default();
        m.reply(200, &file_json("file1", "T.vault", "r1"))
            .reply(200, &file_json("file1", "T.vault", "r2"));
        let f = block_on(provider(&m).upload_shared_vault(
            "file1",
            b"x",
            WriteCondition::IfRevision(Revision("r1".into())),
        ))
        .unwrap();
        assert_eq!(f.revision, Revision("r2".into()));
        assert_eq!(m.seen()[1].0, Method::Patch);
        // Every upload also stamps the MIME type, which migrates files created before it existed.
        assert!(m.seen()[1].1.contains("uploadType=multipart"));
        let body = String::from_utf8_lossy(&m.seen()[1].2).into_owned();
        assert!(body.contains(&format!(r#"{{"mimeType":"{SHARED_VAULT_MIME}"}}"#)));
        assert!(
            body.contains("\r\n\r\nx\r\n--"),
            "the vault bytes are the second part"
        );
        assert!(!body.contains("application/octet-stream"));
        assert_eq!(
            block_on(provider(&Mock::default()).upload_shared_vault(
                "file1",
                b"x",
                WriteCondition::MustNotExist
            )),
            Err(StorageError::InvalidInput)
        );
    }

    #[test]
    fn display_name_is_sanitized() {
        assert_eq!(sanitize_display_name("a\u{0}b\nc"), "abc");
        assert_eq!(
            sanitize_display_name(&"x".repeat(500)).len(),
            MAX_DISPLAY_NAME
        );
    }
}
