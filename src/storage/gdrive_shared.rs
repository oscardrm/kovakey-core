//! Shared-vault operations on Google Drive (ADR 0021, scope `drive.file`).
//!
//! Unlike personal sync (`appDataFolder`, not shareable), a shared vault lives in the owner's regular
//! Drive inside a `Kovakey Shared` folder, tagged with private `appProperties`, and is addressed by
//! file id. Everything here moves ciphertext only; the shared vault has its own password, validated
//! by the caller opening the downloaded bytes. The owner can also list and revoke the file's Drive
//! permissions; the names and emails Drive returns are untrusted and sanitized for display.

use core::fmt;

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
/// Drive's largest `permissions.list` page.
const PERMISSION_PAGE_SIZE: &str = "100";
/// Hard cap on permission pages (Drive allows a few hundred people per file), so a misbehaving server cannot make
/// us loop forever.
const MAX_PERMISSION_PAGES: usize = 20;
const PERMISSION_FIELDS: &str = "nextPageToken,permissions(id,role,displayName,emailAddress)";

/// Access level of a person on a shared vault file, from Drive's permission `role`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedRole {
    /// Drive `owner`: the account that holds the file. Its permission cannot be removed.
    Owner,
    /// Drive `writer` (what [`GoogleDriveProvider::share_shared_vault`] grants).
    Writer,
    /// Drive `reader`.
    Reader,
    /// Any other Drive role (`commenter`, `organizer`, `fileOrganizer`, or one Drive adds later).
    Other,
}

impl SharedRole {
    /// Map Drive's role string. Unknown values are `Other`, never an error and never interpreted further.
    fn from_drive(role: &str) -> Self {
        match role {
            "owner" => Self::Owner,
            "writer" => Self::Writer,
            "reader" => Self::Reader,
            _ => Self::Other,
        }
    }
}

/// One Drive permission on a shared vault file: who has access and how.
///
/// `display_name` and `email` are set by other people's Google accounts, so they are untrusted: they are sanitized
/// here and are for display only, never to be interpreted. `Debug` redacts them. Revoking a permission stops Drive
/// access only; the person keeps the vault password and any copy already downloaded (ADR 0021).
#[derive(Clone, PartialEq, Eq)]
pub struct SharedPermission {
    /// Drive permission id (checked URL-safe), the handle for
    /// [`GoogleDriveProvider::delete_shared_vault_permission`].
    pub id: String,
    /// Sanitized display name: no control, bidi or invisible characters, trimmed, at most 80 characters. Empty when
    /// Drive sends none (for example a link or domain permission).
    pub display_name: String,
    /// Sanitized email address. `None` when Drive sends none, or sends something that is not one plain address
    /// (dropped rather than shown altered).
    pub email: Option<String>,
    /// Access level.
    pub role: SharedRole,
    /// The permission belongs to the signed-in account.
    pub is_me: bool,
}

impl fmt::Debug for SharedPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedPermission")
            .field("id", &self.id)
            .field("display_name", &"<redacted>")
            .field("email", &self.email.as_ref().map(|_| "<redacted>"))
            .field("role", &self.role)
            .field("is_me", &self.is_me)
            .finish()
    }
}

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

    /// Everyone with access to a shared vault file (Drive `permissions.list`, every page), with the signed-in
    /// account marked `is_me` (Drive `about.user.permissionId`). Meant for the owner: for another account Drive may
    /// return fewer entries or refuse (`Unauthorized`), and what it returns is passed on as is. A missing file is
    /// `NotFound`. Names and emails are sanitized and display only (see [`SharedPermission`]).
    pub async fn list_shared_vault_permissions(
        &self,
        file_id: &str,
    ) -> Result<Vec<SharedPermission>, StorageError> {
        validate_id(file_id)?;
        let raw = self.permission_pages(file_id).await?;
        let me = self.my_permission_id().await?;
        raw.into_iter().map(|p| p.into_shared(&me)).collect()
    }

    /// Remove one person's access to a shared vault file (Drive `permissions.delete`), by an id from
    /// [`Self::list_shared_vault_permissions`]. Meant for the owner.
    ///
    /// The permission is read first: an owner permission (the owner's own) is refused with `InvalidInput` and
    /// nothing is deleted; an unknown permission or file is `NotFound`. The read-then-delete is not atomic, but only
    /// the owner can change who owns the file. Revoking stops Drive access only: the person keeps the vault password
    /// and any copy already downloaded, so full revocation also needs a new shared password (ADR 0021).
    pub async fn delete_shared_vault_permission(
        &self,
        file_id: &str,
        permission_id: &str,
    ) -> Result<(), StorageError> {
        validate_id(file_id)?;
        validate_id(permission_id)?;
        let url = format!("{API}/files/{file_id}/permissions/{permission_id}");
        let get_url = format!("{url}?fields={}", pct("id,role"));
        let resp = self
            .call(|| HttpRequest {
                method: Method::Get,
                url: get_url.clone(),
                headers: Vec::new(),
                body: Vec::new(),
            })
            .await?;
        // `role` is required: a permission whose role cannot be read is never deleted.
        #[derive(Deserialize)]
        struct RoleOnly {
            role: String,
        }
        let current: RoleOnly =
            serde_json::from_slice(&resp.body).map_err(|_| StorageError::Serialization)?;
        if SharedRole::from_drive(&current.role) == SharedRole::Owner {
            return Err(StorageError::InvalidInput);
        }
        self.call(|| HttpRequest {
            method: Method::Delete,
            url: url.clone(),
            headers: Vec::new(),
            body: Vec::new(),
        })
        .await
        .map(|_| ())
    }

    /// All raw permission entries of a file, following `nextPageToken` up to [`MAX_PERMISSION_PAGES`].
    async fn permission_pages(&self, file_id: &str) -> Result<Vec<DrivePermission>, StorageError> {
        let mut out = Vec::new();
        let mut page: Option<String> = None;
        for _ in 0..MAX_PERMISSION_PAGES {
            let mut url = format!(
                "{API}/files/{file_id}/permissions?pageSize={PERMISSION_PAGE_SIZE}&fields={}",
                pct(PERMISSION_FIELDS)
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
            let list: PermissionList =
                serde_json::from_slice(&resp.body).map_err(|_| StorageError::Serialization)?;
            out.extend(list.permissions);
            match list.next_page_token {
                Some(t) if !t.is_empty() => page = Some(t),
                _ => return Ok(out),
            }
        }
        // Too many pages: a malformed or hostile listing, not something to truncate silently.
        Err(StorageError::Serialization)
    }

    /// The signed-in account's permission id, which is how Drive names that account in every file's permissions.
    async fn my_permission_id(&self) -> Result<String, StorageError> {
        let url = format!("{API}/about?fields={}", pct("user(permissionId)"));
        let resp = self
            .call(|| HttpRequest {
                method: Method::Get,
                url: url.clone(),
                headers: Vec::new(),
                body: Vec::new(),
            })
            .await?;
        #[derive(Deserialize)]
        struct About {
            user: AboutUser,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct AboutUser {
            permission_id: String,
        }
        let about: About =
            serde_json::from_slice(&resp.body).map_err(|_| StorageError::Serialization)?;
        validate_id(&about.user.permission_id).map_err(|_| StorageError::Serialization)?;
        Ok(about.user.permission_id)
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

/// Bidi controls and invisible characters that could make a remote name or address read as something else.
/// (Zero-width joiner and non-joiner stay: some scripts and emoji need them.)
fn is_spoofing_char(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{200B}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

/// Sanitize a person's name from Drive for display: drop control, bidi and invisible characters, trim, truncate.
fn sanitize_person_name(name: &str) -> String {
    let kept: String = name
        .chars()
        .filter(|c| !c.is_control() && !is_spoofing_char(*c))
        .skip_while(|c| c.is_whitespace())
        .take(MAX_DISPLAY_NAME)
        .collect();
    kept.trim_end().to_owned()
}

/// Keep an email from Drive only if it is one plain address (the rule used for sharing) with nothing that could
/// change how it reads. Anything else is dropped rather than shown altered.
fn sanitize_email(email: Option<&str>) -> Option<String> {
    let e = email?.trim();
    (validate_email(e).is_ok() && !e.chars().any(is_spoofing_char)).then(|| e.to_owned())
}

/// A permission as Drive returns it. Every field is untrusted.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DrivePermission {
    id: String,
    role: Option<String>,
    display_name: Option<String>,
    email_address: Option<String>,
}

impl DrivePermission {
    /// Check and sanitize. An id that is not URL-safe makes the whole listing malformed (`Serialization`): it could
    /// not be revoked safely, and hiding the entry would hide a person who has access.
    fn into_shared(self, my_id: &str) -> Result<SharedPermission, StorageError> {
        validate_id(&self.id).map_err(|_| StorageError::Serialization)?;
        Ok(SharedPermission {
            is_me: self.id == my_id,
            display_name: sanitize_person_name(self.display_name.as_deref().unwrap_or_default()),
            email: sanitize_email(self.email_address.as_deref()),
            role: SharedRole::from_drive(self.role.as_deref().unwrap_or_default()),
            id: self.id,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PermissionList {
    #[serde(default)]
    permissions: Vec<DrivePermission>,
    next_page_token: Option<String>,
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

    fn perm(
        id: &str,
        name: &str,
        email: Option<&str>,
        role: SharedRole,
        me: bool,
    ) -> SharedPermission {
        SharedPermission {
            id: id.into(),
            display_name: name.into(),
            email: email.map(Into::into),
            role,
            is_me: me,
        }
    }

    #[test]
    fn permissions_list_follows_pages_sanitizes_and_marks_me() {
        // Two pages, then `about`. Names and emails are attacker-controlled (other people's Google accounts).
        let page1 = r#"{"nextPageToken":"tok/2","permissions":[
            {"id":"111","role":"owner","displayName":"Alice Owner","emailAddress":"alice@example.test"},
            {"id":"222","role":"writer","displayName":"  Bob\u202e\u0000 Builder\n","emailAddress":" bob@example.test "},
            {"id":"333","role":"reader","displayName":"Mallory","emailAddress":"mallory@example.test, eve@example.test"}
        ]}"#;
        let long = "x".repeat(500);
        let page2 = format!(
            r#"{{"permissions":[
            {{"id":"444","role":"commenter","displayName":"{long}","emailAddress":"eve\u202e@example.test"}},
            {{"id":"anyoneWithLink","role":"reader","type":"anyone"}},
            {{"id":"555","role":"fileOrganizer","displayName":"\u200fCarol\u2066","emailAddress":null}}
        ]}}"#
        );
        let m = Mock::default();
        m.reply(200, page1)
            .reply(200, &page2)
            .reply(200, r#"{"user":{"permissionId":"111"}}"#);
        let got = block_on(provider(&m).list_shared_vault_permissions("file1")).unwrap();
        assert_eq!(
            got,
            vec![
                perm(
                    "111",
                    "Alice Owner",
                    Some("alice@example.test"),
                    SharedRole::Owner,
                    true
                ),
                perm(
                    "222",
                    "Bob Builder",
                    Some("bob@example.test"),
                    SharedRole::Writer,
                    false
                ),
                perm("333", "Mallory", None, SharedRole::Reader, false),
                perm(
                    "444",
                    &"x".repeat(MAX_DISPLAY_NAME),
                    None,
                    SharedRole::Other,
                    false
                ),
                perm("anyoneWithLink", "", None, SharedRole::Reader, false),
                perm("555", "Carol", None, SharedRole::Other, false),
            ]
        );
        let seen = m.seen();
        assert_eq!(seen.len(), 3);
        assert!(seen.iter().all(|s| s.0 == Method::Get));
        assert_eq!(
            seen[0].1,
            format!(
                "{API}/files/file1/permissions?pageSize=100&fields=\
                 nextPageToken%2Cpermissions%28id%2Crole%2CdisplayName%2CemailAddress%29"
            )
        );
        assert!(seen[1].1.ends_with("&pageToken=tok%2F2"));
        assert_eq!(
            seen[2].1,
            format!("{API}/about?fields=user%28permissionId%29")
        );
    }

    #[test]
    fn permissions_list_passes_on_what_drive_returns_for_a_non_owner() {
        // A member sees a partial list (or none); nobody is marked as the owner's permission by us.
        let m = Mock::default();
        m.reply(200, r#"{"permissions":[{"id":"222","role":"writer"}]}"#)
            .reply(200, r#"{"user":{"permissionId":"222"}}"#);
        assert_eq!(
            block_on(provider(&m).list_shared_vault_permissions("file1")),
            Ok(vec![perm("222", "", None, SharedRole::Writer, true)])
        );
        let m = Mock::default();
        m.reply(200, "{}")
            .reply(200, r#"{"user":{"permissionId":"222"}}"#);
        assert_eq!(
            block_on(provider(&m).list_shared_vault_permissions("file1")),
            Ok(vec![])
        );
        let m = Mock::default();
        m.reply(403, r#"{"error":{"reason":"insufficientFilePermissions"}}"#);
        assert_eq!(
            block_on(provider(&m).list_shared_vault_permissions("file1")),
            Err(StorageError::Unauthorized)
        );
    }

    #[test]
    fn permissions_list_rejects_bad_input_and_malformed_listings() {
        let p = provider(&Mock::default());
        for id in ["", "a/b", "../x", "f?x=1"] {
            assert_eq!(
                block_on(p.list_shared_vault_permissions(id)),
                Err(StorageError::InvalidInput),
                "{id}"
            );
        }

        let m = Mock::default();
        m.reply(404, "{}");
        assert_eq!(
            block_on(provider(&m).list_shared_vault_permissions("file1")),
            Err(StorageError::NotFound)
        );
        assert_eq!(m.seen().len(), 1, "no about call after a missing file");

        // An id that could not be addressed safely makes the listing malformed instead of hiding a person.
        for page in [
            r#"{"permissions":[{"id":"a/b","role":"writer"}]}"#,
            r#"{"permissions":[{"id":"","role":"writer"}]}"#,
            r#"{"permissions":[{"role":"writer"}]}"#,
            "not json",
        ] {
            let m = Mock::default();
            m.reply(200, page)
                .reply(200, r#"{"user":{"permissionId":"111"}}"#);
            assert_eq!(
                block_on(provider(&m).list_shared_vault_permissions("file1")),
                Err(StorageError::Serialization),
                "{page}"
            );
        }
        for about in ["{}", r#"{"user":{}}"#, r#"{"user":{"permissionId":"x y"}}"#] {
            let m = Mock::default();
            m.reply(200, r#"{"permissions":[]}"#).reply(200, about);
            assert_eq!(
                block_on(provider(&m).list_shared_vault_permissions("file1")),
                Err(StorageError::Serialization),
                "{about}"
            );
        }

        // A server that never stops paging is cut off at the cap.
        let m = Mock::default();
        for _ in 0..MAX_PERMISSION_PAGES {
            m.reply(200, r#"{"nextPageToken":"again","permissions":[]}"#);
        }
        assert_eq!(
            block_on(provider(&m).list_shared_vault_permissions("file1")),
            Err(StorageError::Serialization)
        );
        assert_eq!(m.seen().len(), MAX_PERMISSION_PAGES);
    }

    #[test]
    fn permission_delete_reads_the_role_then_deletes() {
        let m = Mock::default();
        m.reply(200, r#"{"id":"222","role":"writer"}"#)
            .reply(204, "");
        assert_eq!(
            block_on(provider(&m).delete_shared_vault_permission("file1", "222")),
            Ok(())
        );
        let seen = m.seen();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].0, Method::Get);
        assert_eq!(
            seen[0].1,
            format!("{API}/files/file1/permissions/222?fields=id%2Crole")
        );
        assert_eq!(seen[1].0, Method::Delete);
        assert_eq!(seen[1].1, format!("{API}/files/file1/permissions/222"));
        assert!(seen[1].2.is_empty());
    }

    #[test]
    fn permission_delete_of_an_unknown_permission_is_not_found() {
        let m = Mock::default();
        m.reply(404, r#"{"error":{"code":404}}"#);
        assert_eq!(
            block_on(provider(&m).delete_shared_vault_permission("file1", "999")),
            Err(StorageError::NotFound)
        );
        assert_eq!(m.seen().len(), 1, "nothing deleted");

        // Removed by someone else between the read and the delete.
        let m = Mock::default();
        m.reply(200, r#"{"id":"222","role":"reader"}"#)
            .reply(404, "{}");
        assert_eq!(
            block_on(provider(&m).delete_shared_vault_permission("file1", "222")),
            Err(StorageError::NotFound)
        );
    }

    #[test]
    fn permission_delete_refuses_the_owner_without_deleting() {
        let m = Mock::default();
        m.reply(200, r#"{"id":"111","role":"owner"}"#);
        assert_eq!(
            block_on(provider(&m).delete_shared_vault_permission("file1", "111")),
            Err(StorageError::InvalidInput)
        );
        assert_eq!(m.seen().len(), 1, "no DELETE for the owner");
        assert_eq!(m.seen()[0].0, Method::Get);

        // A role that cannot be read is never deleted either.
        for body in [r#"{"id":"111"}"#, "not json"] {
            let m = Mock::default();
            m.reply(200, body);
            assert_eq!(
                block_on(provider(&m).delete_shared_vault_permission("file1", "111")),
                Err(StorageError::Serialization),
                "{body}"
            );
            assert_eq!(m.seen().len(), 1);
        }
    }

    #[test]
    fn permission_delete_rejects_bad_ids_without_network() {
        let m = Mock::default();
        let p = provider(&m);
        for (file, permission) in [
            ("file1", ""),
            ("file1", "a/b"),
            ("file1", "../x"),
            ("file1", "1?x=2"),
            ("", "222"),
            ("a/b", "222"),
        ] {
            assert_eq!(
                block_on(p.delete_shared_vault_permission(file, permission)),
                Err(StorageError::InvalidInput),
                "{file} {permission}"
            );
        }
        assert!(m.seen().is_empty());
    }

    #[test]
    fn person_names_and_emails_are_sanitized_for_display() {
        for (raw, want) in [
            ("Ana", "Ana"),
            ("  Ana  López \t", "Ana  López"),
            ("a\u{0}b\u{7}c\u{1b}[31m", "abc[31m"),
            ("\u{202e}evil\u{202c}", "evil"),
            ("x\u{200b}y\u{feff}z\u{2060}", "xyz"),
            ("\u{2067}\u{061c}\u{200e}", ""),
            // Joiners stay: emoji sequences and some scripts need them.
            (
                "\u{1f469}\u{200d}\u{1f4bb} dev",
                "\u{1f469}\u{200d}\u{1f4bb} dev",
            ),
            ("می\u{200c}خواهم", "می\u{200c}خواهم"),
        ] {
            assert_eq!(sanitize_person_name(raw), want, "{raw:?}");
        }
        assert_eq!(
            sanitize_person_name(&"ñ".repeat(200)).chars().count(),
            MAX_DISPLAY_NAME
        );

        assert_eq!(sanitize_email(Some(" a@b.test ")), Some("a@b.test".into()));
        for bad in [
            "",
            "nobody",
            "a@b@c",
            "a@b.test, c@d.test",
            "a b@c.test",
            "\"a\"@b.test",
            "a\u{202e}@b.test",
            "a\u{200b}@b.test",
        ] {
            assert_eq!(sanitize_email(Some(bad)), None, "{bad:?}");
        }
        assert_eq!(sanitize_email(None), None);
        assert_eq!(
            sanitize_email(Some(&format!("{}@b.test", "a".repeat(260)))),
            None
        );
    }

    #[test]
    fn shared_permission_debug_redacts_name_and_email() {
        let p = perm(
            "222",
            "Bob Builder",
            Some("bob@example.test"),
            SharedRole::Writer,
            false,
        );
        let d = format!("{p:?}");
        assert!(!d.contains("Bob") && !d.contains("bob@"), "{d}");
        assert!(d.contains("222") && d.contains("Writer"));
    }
}
