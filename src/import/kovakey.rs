//! KovaKey export reader: the encrypted `.kvkx` file ([`parse_encrypted`]) and the plaintext JSON
//! export ([`parse_json`]) produced by [`crate::export`]. Same mapping rules as the other
//! importers: nothing is written until [`super::import_items`] is called.

use super::{ImportItem, ImportPreview, MAX_IMPORT_BYTES};
use crate::error::{Error, Result};
use crate::export::{self, Doc};
use crate::models::ItemType;
use crate::ops::FieldInput;

/// Decrypt an encrypted export with its export password and map it to an import preview.
/// A wrong password or a tampered file is [`Error::Decryption`].
pub fn parse_encrypted(file: &[u8], password: &str) -> Result<ImportPreview> {
    if file.len() > MAX_IMPORT_BYTES {
        return Err(Error::InvalidInput);
    }
    to_preview(export::open_encrypted(file, password)?)
}

/// Map a plaintext KovaKey JSON export to an import preview.
pub fn parse_json(json: &[u8]) -> Result<ImportPreview> {
    if json.len() > MAX_IMPORT_BYTES {
        return Err(Error::InvalidInput);
    }
    to_preview(export::parse_doc(json)?)
}

fn to_preview(doc: Doc) -> Result<ImportPreview> {
    let mut preview = ImportPreview::default();
    for it in &doc.items {
        let item_type = match ItemType::parse(&it.item_type) {
            Ok(t) if !it.title.trim().is_empty() => t,
            _ => {
                preview.skipped_invalid += 1;
                continue;
            }
        };
        preview.items.push(ImportItem {
            item_type,
            preset_key: it.category.clone(),
            title: it.title.clone(),
            url: it.url.clone(),
            favorite: it.favorite,
            fields: it
                .fields
                .iter()
                .map(|f| FieldInput::new(&f.name, &f.kind, &f.value, f.is_secret))
                .collect(),
            note: it.note.clone(),
            tags: it.tags.clone(),
            password_history: it.password_history.clone(),
        });
    }
    Ok(preview)
}
