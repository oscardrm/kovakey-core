//! Exports (ADR 0016). Everything is built in memory by core; UIs only hand the bytes to the OS
//! save dialog.
//!
//! * **Encrypted KovaKey export** ([`export_encrypted`]): the recommended format. A standalone
//!   file sealed with AES-256-GCM under a key derived (Argon2id, production floor) from an
//!   *export password* chosen for this file. Re-importable via [`crate::import::kovakey`].
//! * **Plaintext** ([`export_plain_json`], [`export_plain_csv`]): readable by anyone who gets the
//!   file. UIs must warn and get explicit confirmation before calling them.
//!
//! Items in the Trash and permanently deleted items are never exported. Values are never logged:
//! the wire structs wipe themselves on drop and the returned buffers are [`Zeroizing`].
//!
//! Encrypted file layout:
//!
//! ```text
//! "KVKX" | format_version u8 | kdf params (PARAMS_LEN) | nonce[12] | ciphertext | tag[16]
//! ```
//!
//! The AAD is everything before the nonce, so downgrading the KDF parameters or the version is
//! detected as tampering. The plaintext is the same JSON document as [`export_plain_json`].

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto;
use crate::error::{Error, Result};
use crate::kdf::{KdfParams, PARAMS_LEN};
use crate::models::BlockKind;
use crate::ops::VaultStore;

/// File magic of an encrypted export.
pub const MAGIC: &[u8; 4] = b"KVKX";
/// Current encrypted export format version.
pub const FORMAT_VERSION: u8 = 1;
/// Value of the `format` field of the JSON document.
pub const DOC_FORMAT: &str = "kovakey-export";
/// Current JSON document version.
pub const DOC_VERSION: u32 = 1;

/// The exported document (JSON schema of both the plaintext and the decrypted encrypted export).
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct Doc {
    #[zeroize(skip)]
    pub format: String,
    #[zeroize(skip)]
    pub version: u32,
    #[serde(default)]
    pub items: Vec<DocItem>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct DocItem {
    /// Storage identifier of the item type (`credential`, `card`, ...).
    pub item_type: String,
    /// Built-in category key the item is filed under.
    pub category: String,
    pub title: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub fields: Vec<DocField>,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Previous passwords, oldest first.
    #[serde(default)]
    pub password_history: Vec<String>,
    #[zeroize(skip)]
    #[serde(default)]
    pub updated_at: i64,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct DocField {
    pub name: String,
    pub kind: String,
    pub value: String,
    #[zeroize(skip)]
    #[serde(default)]
    pub is_secret: bool,
}

/// Read every live, non-trashed item of `store` (secrets included) into a document.
fn collect<S: VaultStore>(store: &S) -> Result<Doc> {
    let categories = store.list_categories()?;
    let mut items = Vec::new();
    for s in store.list_items()? {
        let detail = store.get_item(&s.id)?;
        let category = s
            .category_id
            .as_ref()
            .and_then(|id| categories.iter().find(|c| &c.id == id))
            .and_then(|c| c.preset.clone())
            .unwrap_or_else(|| s.item_type.as_str().to_string());

        let mut fields = Vec::with_capacity(detail.fields.len());
        for f in &detail.fields {
            let value = match &f.value {
                Some(v) => v.clone(),
                None => store.reveal_field(&s.id, &f.id)?.to_string(),
            };
            fields.push(DocField {
                name: f.name.clone(),
                kind: f.kind.clone(),
                value,
                is_secret: f.is_secret,
            });
        }

        let note = detail
            .blocks
            .iter()
            .filter(|b| matches!(b.kind, BlockKind::RichText | BlockKind::Code))
            .map(|b| b.content.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        let mut password_history: Vec<String> = store
            .reveal_password_history(&s.id)?
            .iter()
            .map(|h| h.password.clone())
            .collect();
        password_history.reverse(); // store: newest first; document: oldest first

        items.push(DocItem {
            item_type: s.item_type.as_str().to_string(),
            category,
            title: s.title.clone(),
            url: s.url.clone(),
            favorite: s.favorite,
            fields,
            note,
            tags: s.tags.clone(),
            password_history,
            updated_at: s.updated_at,
        });
    }
    Ok(Doc {
        format: DOC_FORMAT.to_string(),
        version: DOC_VERSION,
        items,
    })
}

fn to_json(doc: &Doc) -> Result<Zeroizing<Vec<u8>>> {
    serde_json::to_vec(doc)
        .map(Zeroizing::new)
        .map_err(|_| Error::InvalidInput)
}

/// Plaintext JSON export. **Unprotected**: callers must warn the user first.
pub fn export_plain_json<S: VaultStore>(store: &S) -> Result<Zeroizing<Vec<u8>>> {
    to_json(&collect(store)?)
}

/// Header row of the CSV export.
pub const CSV_HEADER: &str = "type,title,url,username,password,totp,tags,favorite,notes";

/// Plaintext CSV export (RFC 4180 quoting). **Unprotected**: callers must warn the user first.
///
/// Columns are [`CSV_HEADER`]. `username` is the first plain text/e-mail field, `password` the
/// first password field, `totp` the first TOTP field; every other field is appended to `notes` as
/// `Name: value` lines. Password history is not representable in CSV (use the JSON or encrypted
/// export for a lossless copy).
pub fn export_plain_csv<S: VaultStore>(store: &S) -> Result<Zeroizing<Vec<u8>>> {
    let doc = collect(store)?;
    let mut out = Zeroizing::new(String::new());
    out.push_str(CSV_HEADER);
    out.push_str("\r\n");
    for it in &doc.items {
        let first = |pred: &dyn Fn(&DocField) -> bool| it.fields.iter().position(pred);
        let user = first(&|f| !f.is_secret && (f.kind == "text" || f.kind == "email"));
        let pass = first(&|f| f.kind == "password");
        let totp = first(&|f| f.kind == "totp");
        let get = |i: Option<usize>| {
            i.and_then(|i| it.fields.get(i))
                .map(|f| f.value.as_str())
                .unwrap_or("")
        };
        let mut notes = Zeroizing::new(it.note.clone());
        for (i, f) in it.fields.iter().enumerate() {
            if [user, pass, totp].contains(&Some(i)) || f.value.is_empty() {
                continue;
            }
            if !notes.is_empty() {
                notes.push('\n');
            }
            notes.push_str(&f.name);
            notes.push_str(": ");
            notes.push_str(&f.value);
        }
        let tags = it.tags.join(";");
        let row = [
            it.item_type.as_str(),
            &it.title,
            it.url.as_deref().unwrap_or(""),
            get(user),
            get(pass),
            get(totp),
            &tags,
            if it.favorite { "1" } else { "0" },
            &notes,
        ];
        for (n, cell) in row.iter().enumerate() {
            if n > 0 {
                out.push(',');
            }
            push_csv_cell(&mut out, cell);
        }
        out.push_str("\r\n");
    }
    Ok(Zeroizing::new(out.as_bytes().to_vec()))
}

fn push_csv_cell(out: &mut String, cell: &str) {
    if cell.contains([',', '"', '\n', '\r']) {
        out.push('"');
        out.push_str(&cell.replace('"', "\"\""));
        out.push('"');
    } else {
        out.push_str(cell);
    }
}

/// Encrypted KovaKey export under `password` (production Argon2id parameters).
///
/// `password` is chosen by the user for this file and is unrelated to the Master Password; it
/// must not be empty (UIs should also enforce a minimum strength).
pub fn export_encrypted<S: VaultStore>(store: &S, password: &str) -> Result<Vec<u8>> {
    export_encrypted_with(store, password, &KdfParams::generate()?)
}

pub(crate) fn export_encrypted_with<S: VaultStore>(
    store: &S,
    password: &str,
    params: &KdfParams,
) -> Result<Vec<u8>> {
    if password.is_empty() {
        return Err(Error::InvalidInput);
    }
    let json = to_json(&collect(store)?)?;
    let header = [&MAGIC[..], &[FORMAT_VERSION], &params.to_bytes()[..]].concat();
    let key = params.derive_kek(password.as_bytes())?;
    let sealed = crypto::seal(&key, &json, &header)?;
    Ok([header, sealed].concat())
}

/// Decrypt an encrypted export into its document.
pub(crate) fn open_encrypted(file: &[u8], password: &str) -> Result<Doc> {
    let header_len = MAGIC.len() + 1 + PARAMS_LEN;
    let (header, sealed) = file.split_at_checked(header_len).ok_or(Error::Corrupted)?;
    let (magic, rest) = header.split_at(MAGIC.len());
    if magic != MAGIC {
        return Err(Error::Corrupted);
    }
    let (version, params) = rest.split_first().ok_or(Error::Corrupted)?;
    if *version != FORMAT_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    let params = KdfParams::from_bytes(params)?;
    let key = params.derive_kek(password.as_bytes())?;
    let json = crypto::open(&key, sealed, header)?;
    parse_doc(&json)
}

/// Parse the JSON document, checking `format` and `version`.
pub(crate) fn parse_doc(json: &[u8]) -> Result<Doc> {
    let doc: Doc = serde_json::from_slice(json).map_err(|_| Error::Corrupted)?;
    if doc.format != DOC_FORMAT {
        return Err(Error::Corrupted);
    }
    if doc.version > DOC_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem_store::MemStore;
    use crate::models::ItemType;
    use crate::ops::{FieldInput, NewItem, WriteCtx};

    const PW: &str = "fake-export-pass";

    fn ctx(now_ms: i64) -> WriteCtx<'static> {
        WriteCtx {
            now_ms,
            device_id: "dev-a",
        }
    }

    fn store() -> MemStore {
        let mut s = MemStore::new();
        s.seed_default_categories(&ctx(1)).unwrap();
        let mut n = NewItem::new(ItemType::Credential, "Mail, \"work\"");
        n.url = Some("https://mail.example.test".into());
        n.favorite = true;
        n.fields = vec![
            FieldInput::new("Username", "text", "alice", false),
            FieldInput::new("Password", "password", "fake-pw-1", true),
            FieldInput::new("Recovery", "text", "line\nbreak", false),
        ];
        let id = s.create_item(&ctx(10), &n).unwrap();
        let d = s.get_item(&id).unwrap();
        let fields = d
            .fields
            .iter()
            .map(|f| {
                let v = if f.kind == "password" {
                    "fake-pw-2".to_string()
                } else {
                    f.value.clone().unwrap_or_default()
                };
                FieldInput::new(&f.name, &f.kind, &v, f.is_secret).with_id(&f.id)
            })
            .collect();
        s.update_item(
            &ctx(20),
            &id,
            &crate::ops::ItemUpdate {
                fields: Some(fields),
                ..Default::default()
            },
        )
        .unwrap();
        let trashed = s
            .create_item(&ctx(30), &NewItem::new(ItemType::Note, "Trashed"))
            .unwrap();
        s.trash_item(&ctx(31), &trashed).unwrap();
        s
    }

    fn cheap() -> KdfParams {
        KdfParams::for_tests()
    }

    #[test]
    fn encrypted_export_round_trips_through_the_importer() {
        let s = store();
        let file = export_encrypted_with(&s, PW, &cheap()).unwrap();
        assert!(file.starts_with(MAGIC));
        let p = crate::import::kovakey::parse_encrypted(&file, PW).unwrap();
        assert_eq!(p.items.len(), 1, "trashed items are not exported");
        let it = &p.items[0];
        assert_eq!(it.title, "Mail, \"work\"");
        assert_eq!(it.preset_key, "credential");
        assert!(it.favorite);
        assert_eq!(it.password_history, vec!["fake-pw-1".to_string()]);
        let pw = it.fields.iter().find(|f| f.kind == "password").unwrap();
        assert_eq!(pw.value, "fake-pw-2");
    }

    #[test]
    fn encrypted_export_hides_content_and_rejects_wrong_password() {
        let file = export_encrypted_with(&store(), PW, &cheap()).unwrap();
        assert!(!file.windows(9).any(|w| w == b"fake-pw-2"));
        assert!(!file.windows(5).any(|w| w == b"alice"));
        assert_eq!(
            open_encrypted(&file, "wrong-password").err(),
            Some(Error::Decryption)
        );
    }

    #[test]
    fn encrypted_export_detects_tampering_in_every_region() {
        let file = export_encrypted_with(&store(), PW, &cheap()).unwrap();
        let header = MAGIC.len() + 1 + PARAMS_LEN;
        // version, KDF params (salt), nonce, ciphertext, last tag byte
        for i in [4, 6, header - 1, header, header + 20, file.len() - 1] {
            let mut bad = file.clone();
            bad[i] ^= 1;
            assert!(open_encrypted(&bad, PW).is_err(), "byte {i} not protected");
        }
        let mut bad = file.clone();
        bad[0] ^= 1;
        assert_eq!(open_encrypted(&bad, PW).err(), Some(Error::Corrupted));
        assert_eq!(
            open_encrypted(&file[..header + 5], PW).err(),
            Some(Error::Corrupted)
        );
        assert_eq!(open_encrypted(&[], PW).err(), Some(Error::Corrupted));
    }

    #[test]
    fn encrypted_export_rejects_empty_password_and_fresh_nonce_each_time() {
        let s = store();
        assert_eq!(
            export_encrypted_with(&s, "", &cheap()).err(),
            Some(Error::InvalidInput)
        );
        let a = export_encrypted_with(&s, PW, &cheap()).unwrap();
        let b = export_encrypted_with(&s, PW, &cheap()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn plain_json_round_trips_and_csv_quotes_cells() {
        let s = store();
        let json = export_plain_json(&s).unwrap();
        let p = crate::import::kovakey::parse_json(&json).unwrap();
        assert_eq!(p.items.len(), 1);

        let csv = export_plain_csv(&s).unwrap();
        let csv = String::from_utf8(csv.to_vec()).unwrap();
        let mut lines = csv.split("\r\n");
        assert_eq!(lines.next(), Some(CSV_HEADER));
        assert!(csv.contains("\"Mail, \"\"work\"\"\""));
        assert!(csv.contains("alice,fake-pw-2,"));
        assert!(csv.contains("\"Recovery: line\nbreak\""));
    }

    #[test]
    fn importer_rejects_foreign_json_and_future_versions() {
        use crate::import::kovakey::parse_json;
        assert!(parse_json(b"{\"format\":\"other\",\"version\":1}").is_err());
        assert_eq!(
            parse_json(b"{\"format\":\"kovakey-export\",\"version\":99}").err(),
            Some(Error::UnsupportedVersion)
        );
        assert!(parse_json(b"not json").is_err());
    }
}
