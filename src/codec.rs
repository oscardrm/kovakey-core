//! Versioned snapshot codec (postcard). See ADR 0001.

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::models::{NoteImage, Snapshot};
use crate::side_blob::{is_external, sha256_hex};

/// Current snapshot payload format version.
pub const SNAPSHOT_FORMAT_VERSION: u8 = 3;

/// Result of [`encode_snapshot`].
pub struct EncodedSnapshot<'a> {
    /// Serialized payload (plaintext secrets, wiped on drop).
    pub payload: Zeroizing<Vec<u8>>,
    /// Images that were replaced by references and must be stored as side blobs.
    pub external: Vec<&'a NoteImage>,
}

/// Resolver for externalized image bytes: `(sha256_hex, size) -> bytes`.
pub type ImageResolver<'a> = dyn FnMut(&str, u64) -> Result<Zeroizing<Vec<u8>>> + 'a;

/// Serialize `snapshot` at [`SNAPSHOT_FORMAT_VERSION`] (v2 = the frozen v1 payload followed by
/// the category extension: preset keys and category field templates; v3 appends the Trash
/// extension: the trash time of each trashed item).
///
/// Image `sha256`/`size` are verified against the bytes (ADR 0001: never trusted on save);
/// a mismatch is [`Error::InvalidInput`]. Images above the side-blob threshold are replaced by a
/// reference and returned in [`EncodedSnapshot::external`].
pub fn encode_snapshot(snapshot: &Snapshot) -> Result<EncodedSnapshot<'_>> {
    encode_at(snapshot, SNAPSHOT_FORMAT_VERSION)
}

fn encode_at(snapshot: &Snapshot, version: u8) -> Result<EncodedSnapshot<'_>> {
    let (wire, external) = v1::Payload::from_snapshot(snapshot)?;
    let mut bytes = postcard::to_allocvec(&wire).map_err(|_| Error::Corrupted)?;
    if version >= 2 {
        let ext = v2::Ext::from_snapshot(snapshot);
        let tail = postcard::to_allocvec(&ext).map_err(|_| Error::Corrupted)?;
        bytes.extend_from_slice(&tail);
    }
    if version >= 3 {
        let ext = v3::Ext::from_snapshot(snapshot);
        let tail = postcard::to_allocvec(&ext).map_err(|_| Error::Corrupted)?;
        bytes.extend_from_slice(&tail);
    }
    Ok(EncodedSnapshot {
        payload: Zeroizing::new(bytes),
        external,
    })
}

/// Decode a payload written at `version`, upgrading it to the current in-memory model.
///
/// Unknown versions fail with [`Error::UnsupportedVersion`] before any parsing. Truncated,
/// malformed or over-long input is [`Error::Corrupted`]. `resolve` supplies externalized image
/// bytes, which are re-verified against the reference.
pub fn decode_snapshot(
    version: u8,
    bytes: &[u8],
    resolve: &mut ImageResolver<'_>,
) -> Result<Snapshot> {
    match version {
        1 => v1::decode(bytes, resolve),
        2 | 3 => {
            let (mut snap, rest) = v1::decode_prefix(bytes, resolve)?;
            let (ext, rest) =
                postcard::take_from_bytes::<v2::Ext>(rest).map_err(|_| Error::Corrupted)?;
            ext.apply(&mut snap)?;
            let rest = if version >= 3 {
                let (trash, rest) =
                    postcard::take_from_bytes::<v3::Ext>(rest).map_err(|_| Error::Corrupted)?;
                trash.apply(&mut snap)?;
                rest
            } else {
                rest
            };
            if !rest.is_empty() {
                return Err(Error::Corrupted);
            }
            Ok(snap)
        }
        _ => Err(Error::UnsupportedVersion),
    }
}

/// `(sha256_hex, size)` of every image stored outside the payload (a side blob), so a client can
/// fetch exactly those blobs before decoding. Unknown versions fail before any parsing.
pub fn external_image_refs(version: u8, bytes: &[u8]) -> Result<Vec<(String, u64)>> {
    match version {
        1 => v1::external_refs(bytes),
        2 | 3 => v1::external_refs_prefix(bytes),
        _ => Err(Error::UnsupportedVersion),
    }
}

/// Whether this build can decode `version`.
pub fn is_supported_version(version: u8) -> bool {
    matches!(version, 1..=3)
}

/// Wire format v1. **Frozen**: postcard is not self-describing, so any change to these types
/// (field added, removed, reordered or retyped) is a new format version with its own module,
/// while this one keeps decoding old files. `golden_v1_*` tests pin the bytes.
///
/// Wire structs wipe their (secret) contents on drop.
mod v1 {
    use std::collections::BTreeSet;
    use std::mem::take;

    use data_encoding::HEXLOWER;
    use serde::{Deserialize, Serialize};
    use zeroize::{Zeroize, Zeroizing};

    use super::{is_external, sha256_hex, ImageResolver};
    use crate::error::{Error, Result};
    use crate::models::{
        BlockKind, Category, HistoryEntry, Item, ItemField, ItemTag, ItemType, NoteBlock,
        NoteImage, Snapshot, Tag, VaultMeta,
    };

    #[derive(Serialize, Deserialize, Zeroize)]
    #[zeroize(drop)]
    pub struct Payload {
        vault_meta: Vec<VaultMetaW>,
        categories: Vec<CategoryW>,
        tags: Vec<TagW>,
        items: Vec<ItemW>,
        item_fields: Vec<FieldW>,
        item_tags: Vec<ItemTagW>,
        note_blocks: Vec<BlockW>,
        images: Vec<ImageW>,
    }

    #[derive(Serialize, Deserialize, Zeroize)]
    #[zeroize(drop)]
    struct VaultMetaW {
        id: String,
        name: String,
        color: String,
        badge: Option<String>,
        created_at: i64,
        updated_at: i64,
        updated_by: String,
    }

    #[derive(Serialize, Deserialize, Zeroize)]
    #[zeroize(drop)]
    struct CategoryW {
        id: String,
        name: String,
        color: String,
        icon: String,
        icon_color: String,
        sort_order: i64,
        created_at: i64,
        updated_at: i64,
        updated_by: String,
        deleted_at: Option<i64>,
    }

    #[derive(Serialize, Deserialize, Zeroize)]
    #[zeroize(drop)]
    struct TagW {
        id: String,
        name: String,
        color: String,
        created_at: i64,
        updated_at: i64,
        updated_by: String,
        deleted_at: Option<i64>,
    }

    #[derive(Serialize, Deserialize, Zeroize)]
    #[zeroize(drop)]
    struct HistoryW {
        id: String,
        field_id: Option<String>,
        password: String,
        changed_at: i64,
    }

    #[derive(Serialize, Deserialize, Zeroize)]
    #[zeroize(drop)]
    struct ItemW {
        id: String,
        category_id: Option<String>,
        item_type: String,
        title: String,
        url: Option<String>,
        color: Option<String>,
        favorite: bool,
        created_at: i64,
        updated_at: i64,
        updated_by: String,
        deleted_at: Option<i64>,
        use_count: i64,
        last_used_at: Option<i64>,
        history: Vec<HistoryW>,
    }

    #[derive(Serialize, Deserialize, Zeroize)]
    #[zeroize(drop)]
    struct FieldW {
        id: String,
        item_id: String,
        name: String,
        kind: String,
        value: String,
        is_secret: bool,
        sort_order: i64,
        updated_at: i64,
        updated_by: String,
        deleted_at: Option<i64>,
    }

    #[derive(Serialize, Deserialize, Zeroize)]
    #[zeroize(drop)]
    struct ItemTagW {
        item_id: String,
        tag_id: String,
        auto: bool,
        updated_at: i64,
        updated_by: String,
        deleted_at: Option<i64>,
    }

    #[derive(Serialize, Deserialize, Zeroize)]
    #[zeroize(drop)]
    struct BlockW {
        id: String,
        item_id: String,
        position: i64,
        kind: String,
        language: Option<String>,
        content: String,
        image_id: Option<String>,
        updated_at: i64,
        updated_by: String,
        deleted_at: Option<i64>,
    }

    /// `data == None` means the bytes live in a side blob addressed by `sha256`.
    #[derive(Serialize, Deserialize, Zeroize)]
    #[zeroize(drop)]
    struct ImageW {
        id: String,
        mime_type: String,
        sha256: [u8; 32],
        size: u64,
        created_at: i64,
        data: Option<Vec<u8>>,
    }

    fn hash_bytes(hex: &str) -> Result<[u8; 32]> {
        HEXLOWER
            .decode(hex.as_bytes())
            .map_err(|_| Error::InvalidInput)?
            .try_into()
            .map_err(|_| Error::InvalidInput)
    }

    impl Payload {
        pub fn from_snapshot(s: &Snapshot) -> Result<(Self, Vec<&NoteImage>)> {
            let mut external = Vec::new();
            let mut images = Vec::with_capacity(s.note_images.len());
            for i in &s.note_images {
                if i.size != i.data.len() as u64 || i.sha256 != sha256_hex(&i.data) {
                    return Err(Error::InvalidInput);
                }
                let data = if is_external(i.data.len()) {
                    external.push(i);
                    None
                } else {
                    Some(i.data.clone())
                };
                images.push(ImageW {
                    id: i.id.clone(),
                    mime_type: i.mime_type.clone(),
                    sha256: hash_bytes(&i.sha256)?,
                    size: i.size,
                    created_at: i.created_at,
                    data,
                });
            }
            let wire = Self {
                vault_meta: s
                    .vault_meta
                    .iter()
                    .map(|v| VaultMetaW {
                        id: v.id.clone(),
                        name: v.name.clone(),
                        color: v.color.clone(),
                        badge: v.badge.clone(),
                        created_at: v.created_at,
                        updated_at: v.updated_at,
                        updated_by: v.updated_by.clone(),
                    })
                    .collect(),
                categories: s
                    .categories
                    .iter()
                    .map(|c| CategoryW {
                        id: c.id.clone(),
                        name: c.name.clone(),
                        color: c.color.clone(),
                        icon: c.icon.clone(),
                        icon_color: c.icon_color.clone(),
                        sort_order: c.sort_order,
                        created_at: c.created_at,
                        updated_at: c.updated_at,
                        updated_by: c.updated_by.clone(),
                        deleted_at: c.deleted_at,
                    })
                    .collect(),
                tags: s
                    .tags
                    .iter()
                    .map(|t| TagW {
                        id: t.id.clone(),
                        name: t.name.clone(),
                        color: t.color.clone(),
                        created_at: t.created_at,
                        updated_at: t.updated_at,
                        updated_by: t.updated_by.clone(),
                        deleted_at: t.deleted_at,
                    })
                    .collect(),
                items: s
                    .items
                    .iter()
                    .map(|i| ItemW {
                        id: i.id.clone(),
                        category_id: i.category_id.clone(),
                        item_type: i.item_type.as_str().to_owned(),
                        title: i.title.clone(),
                        url: i.url.clone(),
                        color: i.color.clone(),
                        favorite: i.favorite,
                        created_at: i.created_at,
                        updated_at: i.updated_at,
                        updated_by: i.updated_by.clone(),
                        deleted_at: i.deleted_at,
                        use_count: i.use_count,
                        last_used_at: i.last_used_at,
                        history: i
                            .history
                            .iter()
                            .map(|h| HistoryW {
                                id: h.id.clone(),
                                field_id: h.field_id.clone(),
                                password: h.password.clone(),
                                changed_at: h.changed_at,
                            })
                            .collect(),
                    })
                    .collect(),
                item_fields: s
                    .item_fields
                    .iter()
                    .map(|f| FieldW {
                        id: f.id.clone(),
                        item_id: f.item_id.clone(),
                        name: f.name.clone(),
                        kind: f.kind.clone(),
                        value: f.value.clone(),
                        is_secret: f.is_secret,
                        sort_order: f.sort_order,
                        updated_at: f.updated_at,
                        updated_by: f.updated_by.clone(),
                        deleted_at: f.deleted_at,
                    })
                    .collect(),
                item_tags: s
                    .item_tags
                    .iter()
                    .map(|t| ItemTagW {
                        item_id: t.item_id.clone(),
                        tag_id: t.tag_id.clone(),
                        auto: t.auto,
                        updated_at: t.updated_at,
                        updated_by: t.updated_by.clone(),
                        deleted_at: t.deleted_at,
                    })
                    .collect(),
                note_blocks: s
                    .note_blocks
                    .iter()
                    .map(|b| BlockW {
                        id: b.id.clone(),
                        item_id: b.item_id.clone(),
                        position: b.position,
                        kind: b.kind.as_str().to_owned(),
                        language: b.language.clone(),
                        content: b.content.clone(),
                        image_id: b.image_id.clone(),
                        updated_at: b.updated_at,
                        updated_by: b.updated_by.clone(),
                        deleted_at: b.deleted_at,
                    })
                    .collect(),
                images,
            };
            Ok((wire, external))
        }

        fn into_snapshot(mut self, resolve: &mut ImageResolver<'_>) -> Result<Snapshot> {
            let mut snap = Snapshot::default();
            for v in &mut self.vault_meta {
                snap.vault_meta.push(VaultMeta {
                    id: take(&mut v.id),
                    name: take(&mut v.name),
                    color: take(&mut v.color),
                    badge: v.badge.take(),
                    created_at: v.created_at,
                    updated_at: v.updated_at,
                    updated_by: take(&mut v.updated_by),
                });
            }
            for c in &mut self.categories {
                snap.categories.push(Category {
                    id: take(&mut c.id),
                    name: take(&mut c.name),
                    color: take(&mut c.color),
                    icon: take(&mut c.icon),
                    icon_color: take(&mut c.icon_color),
                    sort_order: c.sort_order,
                    created_at: c.created_at,
                    updated_at: c.updated_at,
                    updated_by: take(&mut c.updated_by),
                    deleted_at: c.deleted_at,
                    preset: None,
                });
            }
            for t in &mut self.tags {
                snap.tags.push(Tag {
                    id: take(&mut t.id),
                    name: take(&mut t.name),
                    color: take(&mut t.color),
                    created_at: t.created_at,
                    updated_at: t.updated_at,
                    updated_by: take(&mut t.updated_by),
                    deleted_at: t.deleted_at,
                });
            }
            for i in &mut self.items {
                let history: BTreeSet<HistoryEntry> = i
                    .history
                    .iter_mut()
                    .map(|h| HistoryEntry {
                        id: take(&mut h.id),
                        field_id: h.field_id.take(),
                        password: take(&mut h.password),
                        changed_at: h.changed_at,
                    })
                    .collect();
                snap.items.push(Item {
                    id: take(&mut i.id),
                    category_id: i.category_id.take(),
                    item_type: ItemType::parse(&i.item_type)?,
                    title: take(&mut i.title),
                    url: i.url.take(),
                    color: i.color.take(),
                    favorite: i.favorite,
                    created_at: i.created_at,
                    updated_at: i.updated_at,
                    updated_by: take(&mut i.updated_by),
                    deleted_at: i.deleted_at,
                    trashed_at: None,
                    use_count: i.use_count,
                    last_used_at: i.last_used_at,
                    history,
                });
            }
            for f in &mut self.item_fields {
                snap.item_fields.push(ItemField {
                    id: take(&mut f.id),
                    item_id: take(&mut f.item_id),
                    name: take(&mut f.name),
                    kind: take(&mut f.kind),
                    value: take(&mut f.value),
                    is_secret: f.is_secret,
                    sort_order: f.sort_order,
                    updated_at: f.updated_at,
                    updated_by: take(&mut f.updated_by),
                    deleted_at: f.deleted_at,
                });
            }
            for t in &mut self.item_tags {
                snap.item_tags.push(ItemTag {
                    item_id: take(&mut t.item_id),
                    tag_id: take(&mut t.tag_id),
                    auto: t.auto,
                    updated_at: t.updated_at,
                    updated_by: take(&mut t.updated_by),
                    deleted_at: t.deleted_at,
                });
            }
            for b in &mut self.note_blocks {
                snap.note_blocks.push(NoteBlock {
                    id: take(&mut b.id),
                    item_id: take(&mut b.item_id),
                    position: b.position,
                    kind: BlockKind::parse(&b.kind)?,
                    language: b.language.take(),
                    content: take(&mut b.content),
                    image_id: b.image_id.take(),
                    updated_at: b.updated_at,
                    updated_by: take(&mut b.updated_by),
                    deleted_at: b.deleted_at,
                });
            }
            for i in &mut self.images {
                let hex = HEXLOWER.encode(&i.sha256);
                let data = match i.data.take() {
                    Some(d) => Zeroizing::new(d),
                    None => resolve(&hex, i.size)?,
                };
                // Re-verify inline and side-blob bytes against the reference.
                if data.len() as u64 != i.size || sha256_hex(&data) != hex {
                    return Err(Error::Corrupted);
                }
                let mut data = data;
                snap.note_images.push(NoteImage {
                    id: take(&mut i.id),
                    mime_type: take(&mut i.mime_type),
                    sha256: hex,
                    size: i.size,
                    data: take(&mut *data),
                    created_at: i.created_at,
                });
            }
            Ok(snap)
        }
    }

    pub fn external_refs(bytes: &[u8]) -> Result<Vec<(String, u64)>> {
        let (refs, rest) = external_refs_split(bytes)?;
        if !rest.is_empty() {
            return Err(Error::Corrupted);
        }
        Ok(refs)
    }

    /// Like [`external_refs`] but tolerates trailing bytes (the v2 extension).
    pub fn external_refs_prefix(bytes: &[u8]) -> Result<Vec<(String, u64)>> {
        external_refs_split(bytes).map(|(refs, _)| refs)
    }

    type ExternalRefs = Vec<(String, u64)>;

    fn external_refs_split(bytes: &[u8]) -> Result<(ExternalRefs, &[u8])> {
        let (wire, rest) =
            postcard::take_from_bytes::<Payload>(bytes).map_err(|_| Error::Corrupted)?;
        let refs = wire
            .images
            .iter()
            .filter(|i| i.data.is_none())
            .map(|i| (HEXLOWER.encode(&i.sha256), i.size))
            .collect();
        Ok((refs, rest))
    }

    pub fn decode(bytes: &[u8], resolve: &mut ImageResolver<'_>) -> Result<Snapshot> {
        let (snap, rest) = decode_prefix(bytes, resolve)?;
        if !rest.is_empty() {
            return Err(Error::Corrupted);
        }
        Ok(snap)
    }

    /// Decode the v1 payload at the start of `bytes`; returns the unread remainder.
    pub fn decode_prefix<'a>(
        bytes: &'a [u8],
        resolve: &mut ImageResolver<'_>,
    ) -> Result<(Snapshot, &'a [u8])> {
        let (wire, rest) =
            postcard::take_from_bytes::<Payload>(bytes).map_err(|_| Error::Corrupted)?;
        Ok((wire.into_snapshot(resolve)?, rest))
    }
}

/// Wire format v2 = v1 payload + this extension. **Frozen** like v1. Adds what v1 could not
/// carry: the preset key of a category and the category field templates.
mod v2 {
    use serde::{Deserialize, Serialize};

    use crate::error::Result;
    use crate::models::{CategoryField, Snapshot};

    #[derive(Serialize, Deserialize)]
    struct PresetW {
        category_id: String,
        preset: String,
    }

    #[derive(Serialize, Deserialize)]
    struct CategoryFieldW {
        id: String,
        category_id: String,
        name: String,
        kind: String,
        is_secret: bool,
        is_core: bool,
        sort_order: i64,
        updated_at: i64,
        updated_by: String,
        deleted_at: Option<i64>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Ext {
        presets: Vec<PresetW>,
        category_fields: Vec<CategoryFieldW>,
    }

    impl Ext {
        pub fn from_snapshot(s: &Snapshot) -> Self {
            Self {
                presets: s
                    .categories
                    .iter()
                    .filter_map(|c| {
                        c.preset.as_ref().map(|p| PresetW {
                            category_id: c.id.clone(),
                            preset: p.clone(),
                        })
                    })
                    .collect(),
                category_fields: s
                    .category_fields
                    .iter()
                    .map(|f| CategoryFieldW {
                        id: f.id.clone(),
                        category_id: f.category_id.clone(),
                        name: f.name.clone(),
                        kind: f.kind.clone(),
                        is_secret: f.is_secret,
                        is_core: f.is_core,
                        sort_order: f.sort_order,
                        updated_at: f.updated_at,
                        updated_by: f.updated_by.clone(),
                        deleted_at: f.deleted_at,
                    })
                    .collect(),
            }
        }

        pub fn apply(self, snap: &mut Snapshot) -> Result<()> {
            for p in self.presets {
                if let Some(c) = snap.categories.iter_mut().find(|c| c.id == p.category_id) {
                    c.preset = Some(p.preset);
                }
            }
            for f in self.category_fields {
                crate::models::InputKind::parse(&f.kind)
                    .map_err(|_| crate::error::Error::Corrupted)?;
                snap.category_fields.push(CategoryField {
                    id: f.id,
                    category_id: f.category_id,
                    name: f.name,
                    kind: f.kind,
                    is_secret: f.is_secret,
                    is_core: f.is_core,
                    sort_order: f.sort_order,
                    updated_at: f.updated_at,
                    updated_by: f.updated_by,
                    deleted_at: f.deleted_at,
                });
            }
            Ok(())
        }
    }
}

/// Wire format v3 extension (after the v2 one): the Trash state. Frozen like the others.
mod v3 {
    use serde::{Deserialize, Serialize};

    use crate::error::{Error, Result};
    use crate::models::Snapshot;

    #[derive(Serialize, Deserialize)]
    pub(super) struct TrashedW {
        pub(super) item_id: String,
        pub(super) trashed_at: i64,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Ext {
        pub(super) trashed: Vec<TrashedW>,
    }

    impl Ext {
        pub fn from_snapshot(s: &Snapshot) -> Self {
            Self {
                trashed: s
                    .items
                    .iter()
                    .filter_map(|i| {
                        i.trashed_at.map(|t| TrashedW {
                            item_id: i.id.clone(),
                            trashed_at: t,
                        })
                    })
                    .collect(),
            }
        }

        pub fn apply(self, snap: &mut Snapshot) -> Result<()> {
            for t in self.trashed {
                // A reference to an unknown item means the payload is damaged.
                let item = snap
                    .items
                    .iter_mut()
                    .find(|i| i.id == t.item_id)
                    .ok_or(Error::Corrupted)?;
                item.trashed_at = Some(t.trashed_at);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use std::collections::BTreeSet;

    use crate::models::*;
    use crate::side_blob::sha256_hex;

    pub fn image(id: &str, data: Vec<u8>) -> NoteImage {
        NoteImage {
            id: id.into(),
            mime_type: "image/png".into(),
            sha256: sha256_hex(&data),
            size: data.len() as u64,
            data,
            created_at: 1_700_000_000_500,
        }
    }

    /// What survives a v1 round trip: v1 cannot carry presets or category fields.
    pub(crate) fn v1_view(mut s: Snapshot) -> Snapshot {
        s.category_fields.clear();
        for c in &mut s.categories {
            c.preset = None;
        }
        s
    }

    /// Deterministic pseudo-random bytes (not secrets).
    pub fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| ((i * 31 + 7) % 251) as u8).collect()
    }

    fn hist(id: &str, pw: &str, t: i64) -> HistoryEntry {
        HistoryEntry {
            id: id.into(),
            field_id: Some("fld-1".into()),
            password: pw.into(),
            changed_at: t,
        }
    }

    /// Covers every record type, `None`/`Some` options, tombstones and multi-entry history.
    /// `big` adds an image above the side-blob threshold.
    pub fn sample(big: bool) -> Snapshot {
        let mut images = vec![image("img-small", vec![1, 2, 3, 4, 5])];
        if big {
            images.push(image("img-big", pattern(65_537)));
        }
        Snapshot {
            category_fields: vec![
                CategoryField {
                    id: "cf-1".into(),
                    category_id: "cat-1".into(),
                    name: "Card number".into(),
                    kind: "card_number".into(),
                    is_secret: true,
                    is_core: true,
                    sort_order: 0,
                    updated_at: 1_700_000_002_500,
                    updated_by: "dev-a".into(),
                    deleted_at: None,
                },
                CategoryField {
                    id: "cf-2".into(),
                    category_id: "cat-1".into(),
                    name: "Extra".into(),
                    kind: "text".into(),
                    is_secret: false,
                    is_core: false,
                    sort_order: 1,
                    updated_at: 1_700_000_002_600,
                    updated_by: "dev-b".into(),
                    deleted_at: Some(1_700_000_002_700),
                },
            ],
            vault_meta: vec![VaultMeta {
                id: "vault-1".into(),
                name: "Personal".into(),
                color: "#112233".into(),
                badge: Some("work".into()),
                created_at: 1_700_000_000_000,
                updated_at: 1_700_000_001_000,
                updated_by: "dev-a".into(),
            }],
            categories: vec![Category {
                id: "cat-1".into(),
                name: "Logins".into(),
                color: "#ff0000".into(),
                icon: "key".into(),
                icon_color: "#00ff00".into(),
                preset: Some("credential".into()),
                sort_order: 2,
                created_at: 1_700_000_000_000,
                updated_at: 1_700_000_002_000,
                updated_by: "dev-a".into(),
                deleted_at: None,
            }],
            tags: vec![Tag {
                id: "tag-1".into(),
                name: "#work".into(),
                color: "#abcdef".into(),
                created_at: 1_700_000_000_000,
                updated_at: 1_700_000_003_000,
                updated_by: "dev-b".into(),
                deleted_at: Some(1_700_000_004_000),
            }],
            items: vec![
                Item {
                    id: "item-1".into(),
                    category_id: Some("cat-1".into()),
                    item_type: ItemType::Credential,
                    title: "Example".into(),
                    url: Some("https://example.test".into()),
                    color: None,
                    favorite: true,
                    created_at: 1_700_000_000_000,
                    updated_at: 1_700_000_005_000,
                    updated_by: "dev-a".into(),
                    deleted_at: None,
                    trashed_at: None,
                    use_count: 3,
                    last_used_at: Some(1_700_000_006_000),
                    history: BTreeSet::from([
                        hist("h-1", "old-fake-pass-1", 1_700_000_001_000),
                        hist("h-2", "old-fake-pass-2", 1_700_000_002_000),
                    ]),
                },
                Item {
                    id: "item-2".into(),
                    category_id: None,
                    item_type: ItemType::Note,
                    title: "Note".into(),
                    url: None,
                    color: Some("#010101".into()),
                    favorite: false,
                    created_at: 1_700_000_000_000,
                    updated_at: 1_700_000_005_500,
                    updated_by: "dev-b".into(),
                    deleted_at: Some(1_700_000_007_000),
                    trashed_at: None,
                    use_count: 0,
                    last_used_at: None,
                    history: BTreeSet::new(),
                },
            ],
            item_fields: vec![ItemField {
                id: "fld-1".into(),
                item_id: "item-1".into(),
                name: "password".into(),
                kind: "password".into(),
                value: "fake-secret-value".into(),
                is_secret: true,
                sort_order: 1,
                updated_at: 1_700_000_005_000,
                updated_by: "dev-a".into(),
                deleted_at: None,
            }],
            item_tags: vec![ItemTag {
                item_id: "item-1".into(),
                tag_id: "tag-1".into(),
                auto: true,
                updated_at: 1_700_000_005_000,
                updated_by: "dev-a".into(),
                deleted_at: Some(1_700_000_008_000),
            }],
            note_blocks: vec![NoteBlock {
                id: "blk-1".into(),
                item_id: "item-2".into(),
                position: 0,
                kind: BlockKind::Image,
                language: Some("rust".into()),
                content: "fake note body".into(),
                image_id: Some("img-small".into()),
                updated_at: 1_700_000_005_000,
                updated_by: "dev-b".into(),
                deleted_at: None,
            }],
            note_images: images,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::side_blob::sha256_hex;
    use std::collections::HashMap;

    fn no_resolver() -> impl FnMut(&str, u64) -> Result<Zeroizing<Vec<u8>>> {
        |_, _| Err(Error::NotFound)
    }

    fn round_trip(s: &Snapshot) -> Snapshot {
        let enc = encode_snapshot(s).unwrap();
        let store: HashMap<String, Vec<u8>> = enc
            .external
            .iter()
            .map(|i| (i.sha256.clone(), i.data.clone()))
            .collect();
        decode_snapshot(SNAPSHOT_FORMAT_VERSION, &enc.payload, &mut |h, _| {
            store
                .get(h)
                .cloned()
                .map(Zeroizing::new)
                .ok_or(Error::NotFound)
        })
        .unwrap()
    }

    #[test]
    fn round_trips_every_record_type() {
        let s = sample(false);
        assert_eq!(round_trip(&s), s);
    }

    #[test]
    fn round_trip_preserves_null_last_used_and_history_ids() {
        let out = round_trip(&sample(false));
        let it2 = out.items.iter().find(|i| i.id == "item-2").unwrap();
        assert_eq!(it2.last_used_at, None);
        let it1 = out.items.iter().find(|i| i.id == "item-1").unwrap();
        let ids: Vec<_> = it1.history.iter().map(|h| h.id.as_str()).collect();
        assert_eq!(ids, ["h-1", "h-2"]);
    }

    #[test]
    fn empty_snapshot_round_trips() {
        let s = Snapshot::default();
        assert_eq!(round_trip(&s), s);
    }

    #[test]
    fn encoding_is_deterministic() {
        let s = sample(false);
        assert_eq!(
            *encode_snapshot(&s).unwrap().payload,
            *encode_snapshot(&s).unwrap().payload
        );
    }

    #[test]
    fn small_images_stay_inline_and_large_ones_are_externalized() {
        let s = sample(true);
        let enc = encode_snapshot(&s).unwrap();
        let ids: Vec<_> = enc.external.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, ["img-big"]);
        // The big image bytes must not be inside the payload; the snapshot stays light.
        let big = pattern(65_537);
        assert!(
            enc.payload.len() < 4_000,
            "payload is {}",
            enc.payload.len()
        );
        assert!(!enc.payload.windows(64).any(|w| w == &big[..64]));
        assert_eq!(round_trip(&s), s);
    }

    #[test]
    fn image_exactly_at_threshold_is_inline() {
        let mut s = Snapshot::default();
        s.note_images.push(image("edge", pattern(65_536)));
        assert!(encode_snapshot(&s).unwrap().external.is_empty());
        s.note_images.push(image("over", pattern(65_537)));
        assert_eq!(encode_snapshot(&s).unwrap().external.len(), 1);
    }

    #[test]
    fn encode_rejects_image_whose_declared_hash_or_size_is_wrong() {
        let mut s = sample(false);
        s.note_images[0].sha256 = sha256_hex(b"other");
        assert_eq!(encode_snapshot(&s).err(), Some(Error::InvalidInput));
        let mut s = sample(false);
        s.note_images[0].size += 1;
        assert_eq!(encode_snapshot(&s).err(), Some(Error::InvalidInput));
    }

    #[test]
    fn decode_rejects_resolver_bytes_that_do_not_match_the_reference() {
        let snap = sample(true);
        let enc = encode_snapshot(&snap).unwrap();
        let wrong = decode_snapshot(1, &enc.payload, &mut |_, size| {
            Ok(Zeroizing::new(vec![0u8; size as usize]))
        });
        assert_eq!(wrong.err(), Some(Error::Corrupted));
        let short = decode_snapshot(1, &enc.payload, &mut |_, _| Ok(Zeroizing::new(vec![1])));
        assert_eq!(short.err(), Some(Error::Corrupted));
    }

    #[test]
    fn decode_propagates_missing_side_blob() {
        let snap = sample(true);
        let enc = encode_snapshot(&snap).unwrap();
        let r = decode_snapshot(1, &enc.payload, &mut no_resolver());
        assert_eq!(r.err(), Some(Error::NotFound));
    }

    #[test]
    fn unknown_versions_are_rejected_before_parsing() {
        let snap = sample(false);
        let enc = encode_snapshot(&snap).unwrap();
        for v in [0u8, 4, 255] {
            let r = decode_snapshot(v, &enc.payload, &mut no_resolver());
            assert_eq!(r.err(), Some(Error::UnsupportedVersion), "v{v}");
        }
    }

    #[test]
    fn truncated_and_trailing_bytes_are_corrupted() {
        let snap = sample(false);
        let enc = encode_snapshot(&snap).unwrap();
        for cut in [0, 1, enc.payload.len() / 2, enc.payload.len() - 1] {
            let r = decode_snapshot(1, &enc.payload[..cut], &mut no_resolver());
            assert_eq!(r.err(), Some(Error::Corrupted), "cut {cut}");
        }
        let mut extra = enc.payload.to_vec();
        extra.push(0);
        let r = decode_snapshot(1, &extra, &mut no_resolver());
        assert_eq!(r.err(), Some(Error::Corrupted));
    }

    #[test]
    fn garbage_never_panics() {
        for seed in 0..200u32 {
            let junk: Vec<u8> = (0..64u32)
                .map(|i| (i.wrapping_mul(seed + 3) >> 2) as u8)
                .collect();
            let _ = decode_snapshot(1, &junk, &mut no_resolver());
        }
    }

    const GOLDEN: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/snapshot_v1.postcard"
    );
    const GOLDEN_V2: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/snapshot_v2.postcard"
    );

    const GOLDEN_V3: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/snapshot_v3.postcard"
    );

    /// The sample with `item-1` in the Trash (what the v3 golden file pins).
    fn trashed_sample(big: bool) -> Snapshot {
        let mut s = sample(big);
        if let Some(i) = s.items.iter_mut().find(|i| i.id == "item-1") {
            i.trashed_at = Some(1_700_000_008_000);
        }
        s
    }

    /// Regenerate with `TV_REGEN_GOLDEN=1 cargo test -p vault-core regenerate_snapshot_golden -- --ignored`.
    /// Only do that when intentionally adding a new format version. (v1 and v2 are frozen: never
    /// regenerate them; only the current version's file may be written.)
    #[test]
    #[ignore]
    fn regenerate_snapshot_golden() {
        if std::env::var("TV_REGEN_GOLDEN").is_err() {
            return;
        }
        let snap = trashed_sample(true);
        let enc = encode_snapshot(&snap).unwrap();
        std::fs::write(GOLDEN_V3, &*enc.payload).unwrap();
    }

    fn big_resolver(h: &str, size: u64) -> Result<Zeroizing<Vec<u8>>> {
        let big = pattern(65_537);
        assert_eq!(h, sha256_hex(&big));
        assert_eq!(size, 65_537);
        Ok(Zeroizing::new(big))
    }

    #[test]
    fn golden_v1_blob_still_decodes_to_the_expected_snapshot() {
        let bytes = std::fs::read(GOLDEN).unwrap();
        let out = decode_snapshot(1, &bytes, &mut big_resolver).unwrap();
        assert_eq!(out, v1_view(sample(true)));
    }

    #[test]
    fn v1_encoder_still_produces_the_golden_v1_bytes() {
        let bytes = std::fs::read(GOLDEN).unwrap();
        let snap = sample(true);
        assert_eq!(*encode_at(&snap, 1).unwrap().payload, bytes);
    }

    #[test]
    fn golden_v2_blob_decodes_to_the_expected_snapshot() {
        let bytes = std::fs::read(GOLDEN_V2).unwrap();
        let out = decode_snapshot(2, &bytes, &mut big_resolver).unwrap();
        assert_eq!(out, sample(true));
    }

    #[test]
    fn v2_encoder_still_produces_the_golden_v2_bytes() {
        let bytes = std::fs::read(GOLDEN_V2).unwrap();
        let snap = sample(true);
        assert_eq!(*encode_at(&snap, 2).unwrap().payload, bytes);
    }

    #[test]
    fn golden_v3_blob_decodes_to_the_expected_snapshot() {
        let bytes = std::fs::read(GOLDEN_V3).unwrap();
        let out = decode_snapshot(3, &bytes, &mut big_resolver).unwrap();
        assert_eq!(out, trashed_sample(true));
    }

    #[test]
    fn current_encoder_still_produces_the_golden_v3_bytes() {
        let bytes = std::fs::read(GOLDEN_V3).unwrap();
        let snap = trashed_sample(true);
        assert_eq!(*encode_snapshot(&snap).unwrap().payload, bytes);
    }

    #[test]
    fn v3_round_trips_trash_state_and_v2_drops_it() {
        let snap = trashed_sample(false);
        let out = round_trip(&snap);
        assert_eq!(
            out.items
                .iter()
                .find(|i| i.id == "item-1")
                .unwrap()
                .trashed_at,
            Some(1_700_000_008_000)
        );
        // An older (v2) encoding cannot carry the trash state.
        let v2 = encode_at(&snap, 2).unwrap();
        let out = decode_snapshot(2, &v2.payload, &mut no_resolver()).unwrap();
        assert!(out.items.iter().all(|i| i.trashed_at.is_none()));
    }

    #[test]
    fn v3_rejects_a_trash_entry_for_an_unknown_item() {
        let snap = trashed_sample(false);
        let mut bytes = encode_at(&snap, 2).unwrap().payload.to_vec();
        let bogus = postcard::to_allocvec(&v3::Ext {
            trashed: vec![v3::TrashedW {
                item_id: "nope".into(),
                trashed_at: 1,
            }],
        })
        .unwrap();
        bytes.extend_from_slice(&bogus);
        assert_eq!(
            decode_snapshot(3, &bytes, &mut no_resolver()).err(),
            Some(Error::Corrupted)
        );
    }

    #[test]
    fn v2_rejects_unknown_input_kind_and_trailing_bytes() {
        let mut snap = sample(false);
        let mut enc = encode_at(&snap, 2).unwrap().payload.to_vec();
        enc.push(0);
        assert_eq!(
            decode_snapshot(2, &enc, &mut no_resolver()).err(),
            Some(Error::Corrupted)
        );
        if let Some(f) = snap.category_fields.first_mut() {
            f.kind = "bogus".into();
        }
        let bad = encode_at(&snap, 2).unwrap();
        assert_eq!(
            decode_snapshot(2, &bad.payload, &mut no_resolver()).err(),
            Some(Error::Corrupted)
        );
    }
}
