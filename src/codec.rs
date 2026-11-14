//! Versioned snapshot codec (postcard). See ADR 0001.

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::models::Snapshot;
use crate::side_blob::{is_external, sha256_hex};

/// Newest snapshot payload format version this build can read and write.
pub const SNAPSHOT_FORMAT_VERSION: u8 = 6;

/// Version written when the snapshot has attachments but no passkeys (ADR 0019).
const ATTACHMENTS_FORMAT_VERSION: u8 = 5;

/// Version written when the snapshot has no attachments. Staying on v4 keeps such vaults readable
/// by builds that predate attachments (ADR 0019).
const BASE_FORMAT_VERSION: u8 = 4;

/// Result of [`encode_snapshot`].
pub struct EncodedSnapshot<'a> {
    /// Format version the payload was written at.
    pub version: u8,
    /// Serialized payload (plaintext secrets, wiped on drop).
    pub payload: Zeroizing<Vec<u8>>,
    /// Blobs (large images, every attachment) that were replaced by references and must be
    /// stored as side blobs.
    pub external: Vec<ExternalBlob<'a>>,
}

/// Bytes that live in a side blob, addressed by their plaintext SHA-256.
pub struct ExternalBlob<'a> {
    /// Lowercase hex SHA-256 of `data`.
    pub sha256: &'a str,
    /// The bytes to seal.
    pub data: &'a [u8],
}

/// Resolver for externalized image bytes: `(sha256_hex, size) -> bytes`.
pub type ImageResolver<'a> = dyn FnMut(&str, u64) -> Result<Zeroizing<Vec<u8>>> + 'a;

/// Serialize `snapshot` at v6 if it has passkeys, v5 if it has attachments, else v4 (v2 = the frozen v1 payload followed by
/// the category extension: preset keys and category field templates; v3 appends the Trash
/// extension: the trash time of each trashed item; v4 appends the Vaults extension: each item's
/// vault and the tombstone time of deleted vaults; v5 appends attachments; v6 appends passkeys).
/// Writing the lowest version that holds the data keeps vaults readable by older builds.
///
/// Image `sha256`/`size` are verified against the bytes (ADR 0001: never trusted on save);
/// a mismatch is [`Error::InvalidInput`]. Images above the side-blob threshold are replaced by a
/// reference and returned in [`EncodedSnapshot::external`].
pub fn encode_snapshot(snapshot: &Snapshot) -> Result<EncodedSnapshot<'_>> {
    let version = if !snapshot.passkeys.is_empty() {
        SNAPSHOT_FORMAT_VERSION
    } else if !snapshot.attachments.is_empty() {
        ATTACHMENTS_FORMAT_VERSION
    } else {
        BASE_FORMAT_VERSION
    };
    encode_at(snapshot, version)
}

fn encode_at(snapshot: &Snapshot, version: u8) -> Result<EncodedSnapshot<'_>> {
    let (wire, mut external) = v1::Payload::from_snapshot(snapshot)?;
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
    if version >= 4 {
        let ext = v4::Ext::from_snapshot(snapshot);
        let tail = postcard::to_allocvec(&ext).map_err(|_| Error::Corrupted)?;
        bytes.extend_from_slice(&tail);
    }
    if version >= 5 {
        let (ext, blobs) = v5::Ext::from_snapshot(snapshot)?;
        let tail = postcard::to_allocvec(&ext).map_err(|_| Error::Corrupted)?;
        bytes.extend_from_slice(&tail);
        external.extend(blobs);
    }
    if version >= 6 {
        let ext = v6::Ext::from_snapshot(snapshot)?;
        let tail = postcard::to_allocvec(&ext).map_err(|_| Error::Corrupted)?;
        bytes.extend_from_slice(&tail);
    }
    Ok(EncodedSnapshot {
        version,
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
        2..=6 => {
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
            let rest = if version >= 4 {
                let (vaults, rest) =
                    postcard::take_from_bytes::<v4::Ext>(rest).map_err(|_| Error::Corrupted)?;
                vaults.apply(&mut snap)?;
                rest
            } else {
                rest
            };
            let rest = if version >= 5 {
                let (att, rest) =
                    postcard::take_from_bytes::<v5::Ext>(rest).map_err(|_| Error::Corrupted)?;
                att.apply(&mut snap, resolve)?;
                rest
            } else {
                rest
            };
            let rest = if version >= 6 {
                let (keys, rest) =
                    postcard::take_from_bytes::<v6::Ext>(rest).map_err(|_| Error::Corrupted)?;
                keys.apply(&mut snap)?;
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
        2..=4 => v1::external_refs_prefix(bytes),
        5 | 6 => {
            let (mut refs, rest) = v1::external_refs_split(bytes)?;
            let (_, rest) =
                postcard::take_from_bytes::<v2::Ext>(rest).map_err(|_| Error::Corrupted)?;
            let (_, rest) =
                postcard::take_from_bytes::<v3::Ext>(rest).map_err(|_| Error::Corrupted)?;
            let (_, rest) =
                postcard::take_from_bytes::<v4::Ext>(rest).map_err(|_| Error::Corrupted)?;
            let (att, rest) =
                postcard::take_from_bytes::<v5::Ext>(rest).map_err(|_| Error::Corrupted)?;
            // Passkeys (v6) are small and always inline: no side blobs to fetch.
            let rest = if version == 6 {
                postcard::take_from_bytes::<v6::Ext>(rest)
                    .map_err(|_| Error::Corrupted)?
                    .1
            } else {
                rest
            };
            if !rest.is_empty() {
                return Err(Error::Corrupted);
            }
            refs.extend(att.external_refs());
            Ok(refs)
        }
        _ => Err(Error::UnsupportedVersion),
    }
}

/// Whether this build can decode `version`.
pub fn is_supported_version(version: u8) -> bool {
    matches!(version, 1..=6)
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
        NoteImage, Snapshot, Tag, VaultMeta, DEFAULT_VAULT_ID,
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

    pub(super) fn hash_bytes(hex: &str) -> Result<[u8; 32]> {
        HEXLOWER
            .decode(hex.as_bytes())
            .map_err(|_| Error::InvalidInput)?
            .try_into()
            .map_err(|_| Error::InvalidInput)
    }

    impl Payload {
        pub fn from_snapshot(s: &Snapshot) -> Result<(Self, Vec<super::ExternalBlob<'_>>)> {
            let mut external = Vec::new();
            let mut images = Vec::with_capacity(s.note_images.len());
            for i in &s.note_images {
                if i.size != i.data.len() as u64 || i.sha256 != sha256_hex(&i.data) {
                    return Err(Error::InvalidInput);
                }
                let data = if is_external(i.data.len()) {
                    external.push(super::ExternalBlob {
                        sha256: i.sha256.as_str(),
                        data: i.data.as_slice(),
                    });
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
                    deleted_at: None,
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
                    vault_id: DEFAULT_VAULT_ID.to_string(),
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

    pub(super) type ExternalRefs = Vec<(String, u64)>;

    pub(super) fn external_refs_split(bytes: &[u8]) -> Result<(ExternalRefs, &[u8])> {
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

/// Wire format v5 extension (appended after v4): file attachments (ADR 0019). Bytes are never
/// inline; every live attachment is a side blob addressed by `sha256`. Tombstoned attachments carry
/// no blob (`size == 0`). Written only when the vault has attachment rows, so vaults without them
/// stay at v4.
mod v5 {
    use data_encoding::HEXLOWER;
    use serde::{Deserialize, Serialize};
    use zeroize::Zeroize;

    use super::v1::hash_bytes;
    use super::{ExternalBlob, ImageResolver};
    use crate::error::{Error, Result};
    use crate::models::{Attachment, Snapshot};
    use crate::side_blob::sha256_hex;

    #[derive(Serialize, Deserialize, Zeroize)]
    #[zeroize(drop)]
    pub(super) struct AttachmentW {
        id: String,
        item_id: String,
        file_name: String,
        mime_type: String,
        sha256: [u8; 32],
        size: u64,
        created_at: i64,
        updated_at: i64,
        updated_by: String,
        deleted_at: Option<i64>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Ext {
        attachments: Vec<AttachmentW>,
    }

    impl Ext {
        pub fn from_snapshot(s: &Snapshot) -> Result<(Self, Vec<ExternalBlob<'_>>)> {
            let mut blobs = Vec::new();
            let mut attachments = Vec::with_capacity(s.attachments.len());
            for a in &s.attachments {
                // Never trust declared hash/size: derive from the bytes (ADR 0001).
                if a.size != a.data.len() as u64 || a.sha256 != sha256_hex(&a.data) {
                    return Err(Error::InvalidInput);
                }
                if a.deleted_at.is_none() {
                    if a.data.is_empty() {
                        return Err(Error::InvalidInput);
                    }
                    blobs.push(ExternalBlob {
                        sha256: a.sha256.as_str(),
                        data: a.data.as_slice(),
                    });
                } else if !a.data.is_empty() {
                    // A tombstone must have been scrubbed.
                    return Err(Error::InvalidInput);
                }
                attachments.push(AttachmentW {
                    id: a.id.clone(),
                    item_id: a.item_id.clone(),
                    file_name: a.file_name.clone(),
                    mime_type: a.mime_type.clone(),
                    sha256: hash_bytes(&a.sha256)?,
                    size: a.size,
                    created_at: a.created_at,
                    updated_at: a.updated_at,
                    updated_by: a.updated_by.clone(),
                    deleted_at: a.deleted_at,
                });
            }
            Ok((Self { attachments }, blobs))
        }

        /// `(sha256_hex, size)` of every blob this extension refers to.
        pub fn external_refs(&self) -> Vec<(String, u64)> {
            self.attachments
                .iter()
                .filter(|a| a.deleted_at.is_none())
                .map(|a| (HEXLOWER.encode(&a.sha256), a.size))
                .collect()
        }

        pub fn apply(mut self, snap: &mut Snapshot, resolve: &mut ImageResolver<'_>) -> Result<()> {
            for w in &mut self.attachments {
                // A reference to an unknown item means the payload is damaged.
                if !snap.items.iter().any(|i| i.id == w.item_id) {
                    return Err(Error::Corrupted);
                }
                let hex = HEXLOWER.encode(&w.sha256);
                let data = if w.deleted_at.is_none() {
                    let bytes = resolve(&hex, w.size)?;
                    if bytes.is_empty() || bytes.len() as u64 != w.size || sha256_hex(&bytes) != hex
                    {
                        return Err(Error::Corrupted);
                    }
                    let mut bytes = bytes;
                    std::mem::take(&mut *bytes)
                } else {
                    if w.size != 0 {
                        return Err(Error::Corrupted);
                    }
                    Vec::new()
                };
                snap.attachments.push(Attachment {
                    id: std::mem::take(&mut w.id),
                    item_id: std::mem::take(&mut w.item_id),
                    file_name: std::mem::take(&mut w.file_name),
                    mime_type: std::mem::take(&mut w.mime_type),
                    sha256: sha256_hex(&data),
                    size: data.len() as u64,
                    data,
                    created_at: w.created_at,
                    updated_at: w.updated_at,
                    updated_by: std::mem::take(&mut w.updated_by),
                    deleted_at: w.deleted_at,
                });
            }
            Ok(())
        }
    }
}

/// Wire format v6 extension (appended after v5): passkeys (ADR 0020). Keys are 32 bytes and travel
/// inline inside the encrypted payload. Live passkeys must carry a valid P-256 scalar; tombstones
/// must carry none. Written only when the vault has passkey rows.
mod v6 {
    use serde::{Deserialize, Serialize};
    use zeroize::Zeroize;

    use crate::error::{Error, Result};
    use crate::models::{Passkey, Snapshot};
    use crate::passkey::{
        check_user_handle, cose_public_key, normalize_rp_id, CREDENTIAL_ID_LEN, PRIVATE_KEY_LEN,
    };

    #[derive(Serialize, Deserialize, Zeroize)]
    #[zeroize(drop)]
    pub(super) struct PasskeyW {
        id: String,
        item_id: String,
        credential_id: Vec<u8>,
        rp_id: String,
        user_name: String,
        user_handle: Vec<u8>,
        private_key: Vec<u8>,
        created_at: i64,
        updated_at: i64,
        updated_by: String,
        deleted_at: Option<i64>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Ext {
        passkeys: Vec<PasskeyW>,
    }

    /// Shape checks shared by encode (`InvalidInput`) and decode (`Corrupted`).
    fn well_formed(
        credential_id: &[u8],
        rp_id: &str,
        user_handle: &[u8],
        key: &[u8],
        deleted: bool,
    ) -> bool {
        let shape = !credential_id.is_empty()
            && credential_id.len() <= 4 * CREDENTIAL_ID_LEN
            && normalize_rp_id(rp_id).is_ok_and(|n| n == rp_id)
            && check_user_handle(user_handle).is_ok();
        let key_ok = if deleted {
            key.is_empty()
        } else {
            key.len() == PRIVATE_KEY_LEN && cose_public_key(key).is_ok()
        };
        shape && key_ok
    }

    impl Ext {
        pub fn from_snapshot(s: &Snapshot) -> Result<Self> {
            let mut passkeys = Vec::with_capacity(s.passkeys.len());
            for p in &s.passkeys {
                if !well_formed(
                    &p.credential_id,
                    &p.rp_id,
                    &p.user_handle,
                    &p.private_key,
                    p.deleted_at.is_some(),
                ) {
                    return Err(Error::InvalidInput);
                }
                passkeys.push(PasskeyW {
                    id: p.id.clone(),
                    item_id: p.item_id.clone(),
                    credential_id: p.credential_id.clone(),
                    rp_id: p.rp_id.clone(),
                    user_name: p.user_name.clone(),
                    user_handle: p.user_handle.clone(),
                    private_key: p.private_key.clone(),
                    created_at: p.created_at,
                    updated_at: p.updated_at,
                    updated_by: p.updated_by.clone(),
                    deleted_at: p.deleted_at,
                });
            }
            Ok(Self { passkeys })
        }

        pub fn apply(mut self, snap: &mut Snapshot) -> Result<()> {
            for w in &mut self.passkeys {
                if !snap.items.iter().any(|i| i.id == w.item_id)
                    || !well_formed(
                        &w.credential_id,
                        &w.rp_id,
                        &w.user_handle,
                        &w.private_key,
                        w.deleted_at.is_some(),
                    )
                {
                    return Err(Error::Corrupted);
                }
                snap.passkeys.push(Passkey {
                    id: std::mem::take(&mut w.id),
                    item_id: std::mem::take(&mut w.item_id),
                    credential_id: std::mem::take(&mut w.credential_id),
                    rp_id: std::mem::take(&mut w.rp_id),
                    user_name: std::mem::take(&mut w.user_name),
                    user_handle: std::mem::take(&mut w.user_handle),
                    private_key: std::mem::take(&mut w.private_key),
                    created_at: w.created_at,
                    updated_at: w.updated_at,
                    updated_by: std::mem::take(&mut w.updated_by),
                    deleted_at: w.deleted_at,
                });
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
                deleted_at: None,
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
                    vault_id: "default".into(),
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
                    vault_id: "default".into(),
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
            attachments: Vec::new(),
            passkeys: Vec::new(),
        }
    }
}

/// Wire format v4 extension (appended after v3): the vault of every item that is not in the
/// default vault, and the tombstone time of deleted vaults. Payloads written before v4 decode
/// with every item in the default vault.
mod v4 {
    use serde::{Deserialize, Serialize};

    use crate::error::{Error, Result};
    use crate::models::{Snapshot, DEFAULT_VAULT_ID};

    #[derive(Serialize, Deserialize)]
    pub(super) struct ItemVaultW {
        pub(super) item_id: String,
        pub(super) vault_id: String,
    }

    #[derive(Serialize, Deserialize)]
    pub(super) struct VaultDeletedW {
        pub(super) vault_id: String,
        pub(super) deleted_at: i64,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Ext {
        pub(super) item_vaults: Vec<ItemVaultW>,
        pub(super) deleted_vaults: Vec<VaultDeletedW>,
    }

    impl Ext {
        pub fn from_snapshot(s: &Snapshot) -> Self {
            Self {
                item_vaults: s
                    .items
                    .iter()
                    .filter(|i| i.vault_id != DEFAULT_VAULT_ID)
                    .map(|i| ItemVaultW {
                        item_id: i.id.clone(),
                        vault_id: i.vault_id.clone(),
                    })
                    .collect(),
                deleted_vaults: s
                    .vault_meta
                    .iter()
                    .filter_map(|v| {
                        v.deleted_at.map(|t| VaultDeletedW {
                            vault_id: v.id.clone(),
                            deleted_at: t,
                        })
                    })
                    .collect(),
            }
        }

        pub fn apply(self, snap: &mut Snapshot) -> Result<()> {
            for w in self.item_vaults {
                // A reference to an unknown item means the payload is damaged.
                let item = snap
                    .items
                    .iter_mut()
                    .find(|i| i.id == w.item_id)
                    .ok_or(Error::Corrupted)?;
                item.vault_id = w.vault_id;
            }
            for w in self.deleted_vaults {
                let v = snap
                    .vault_meta
                    .iter_mut()
                    .find(|v| v.id == w.vault_id)
                    .ok_or(Error::Corrupted)?;
                v.deleted_at = Some(w.deleted_at);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::models::Attachment;
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
            .map(|i| (i.sha256.to_string(), i.data.to_vec()))
            .collect();
        decode_snapshot(enc.version, &enc.payload, &mut |h, _| {
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
        let hashes: Vec<_> = enc.external.iter().map(|i| i.sha256).collect();
        assert_eq!(hashes, [sha256_hex(&pattern(65_537))]);
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
        for v in [0u8, 7, 255] {
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

    const GOLDEN_V4: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/snapshot_v4.postcard"
    );

    /// The v3 sample with `item-2` moved to a non-default vault and one deleted vault (what the v4
    /// golden file pins).
    fn vaulted_sample(big: bool) -> Snapshot {
        let mut s = trashed_sample(big);
        if let Some(i) = s.items.iter_mut().find(|i| i.id == "item-2") {
            i.vault_id = "vault-1".into();
        }
        s.vault_meta.push(crate::models::VaultMeta {
            id: "vault-old".into(),
            name: "Old".into(),
            color: "#445566".into(),
            badge: None,
            created_at: 1_700_000_000_500,
            updated_at: 1_700_000_009_000,
            updated_by: "dev-b".into(),
            deleted_at: Some(1_700_000_009_000),
        });
        s
    }

    const GOLDEN_V5: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/snapshot_v5.postcard"
    );

    fn attachment(id: &str, item: &str, data: Vec<u8>, deleted_at: Option<i64>) -> Attachment {
        Attachment {
            id: id.into(),
            item_id: item.into(),
            file_name: "scan.pdf".into(),
            mime_type: "application/pdf".into(),
            sha256: sha256_hex(&data),
            size: data.len() as u64,
            data,
            created_at: 1_700_000_010_000,
            updated_at: 1_700_000_011_000,
            updated_by: "dev-a".into(),
            deleted_at,
        }
    }

    /// The v4 sample plus one live attachment and one tombstoned one (what the v5 golden file pins).
    fn attached_sample(big: bool) -> Snapshot {
        let mut s = vaulted_sample(big);
        s.attachments
            .push(attachment("att-1", "item-1", pattern(1_000), None));
        s.attachments.push(attachment(
            "att-2",
            "item-1",
            Vec::new(),
            Some(1_700_000_012_000),
        ));
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
        // v1–v5 are frozen; only the newest version's file may be (re)written.
        let snap = passkey_sample(true);
        let enc = encode_snapshot(&snap).unwrap();
        assert_eq!(enc.version, 6);
        std::fs::write(GOLDEN_V6, &*enc.payload).unwrap();
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
    fn v3_encoder_still_produces_the_golden_v3_bytes() {
        let bytes = std::fs::read(GOLDEN_V3).unwrap();
        let snap = trashed_sample(true);
        assert_eq!(*encode_at(&snap, 3).unwrap().payload, bytes);
    }

    #[test]
    fn golden_v4_blob_decodes_to_the_expected_snapshot() {
        let bytes = std::fs::read(GOLDEN_V4).unwrap();
        let out = decode_snapshot(4, &bytes, &mut big_resolver).unwrap();
        assert_eq!(out, vaulted_sample(true));
    }

    #[test]
    fn current_encoder_still_produces_the_golden_v4_bytes() {
        let bytes = std::fs::read(GOLDEN_V4).unwrap();
        let snap = vaulted_sample(true);
        assert_eq!(*encode_snapshot(&snap).unwrap().payload, bytes);
    }

    fn attach_resolver(h: &str, size: u64) -> Result<Zeroizing<Vec<u8>>> {
        if h == sha256_hex(&pattern(1_000)) {
            assert_eq!(size, 1_000);
            Ok(Zeroizing::new(pattern(1_000)))
        } else {
            big_resolver(h, size)
        }
    }

    #[test]
    fn golden_v5_blob_decodes_to_the_expected_snapshot() {
        let bytes = std::fs::read(GOLDEN_V5).unwrap();
        let out = decode_snapshot(5, &bytes, &mut attach_resolver).unwrap();
        assert_eq!(out, attached_sample(true));
    }

    #[test]
    fn current_encoder_still_produces_the_golden_v5_bytes() {
        let bytes = std::fs::read(GOLDEN_V5).unwrap();
        let snap = attached_sample(true);
        let enc = encode_snapshot(&snap).unwrap();
        assert_eq!(enc.version, 5);
        assert_eq!(*enc.payload, bytes);
    }

    #[test]
    fn vaults_without_attachments_stay_at_v4_and_attachments_bump_to_v5() {
        assert_eq!(encode_snapshot(&vaulted_sample(false)).unwrap().version, 4);
        assert_eq!(encode_snapshot(&attached_sample(false)).unwrap().version, 5);
    }

    #[test]
    fn attachments_are_always_side_blobs_and_round_trip() {
        let s = attached_sample(false);
        let enc = encode_snapshot(&s).unwrap();
        let hashes: Vec<_> = enc.external.iter().map(|b| b.sha256).collect();
        assert_eq!(hashes, [sha256_hex(&pattern(1_000))]);
        let probe = pattern(1_000);
        assert!(!enc.payload.windows(64).any(|w| w == &probe[..64]));
        assert_eq!(round_trip(&s), s);
        let refs = external_image_refs(5, &enc.payload).unwrap();
        assert_eq!(refs, [(sha256_hex(&pattern(1_000)), 1_000)]);
    }

    #[test]
    fn encode_rejects_inconsistent_attachments() {
        let mut s = attached_sample(false);
        s.attachments[0].sha256 = sha256_hex(b"other");
        assert_eq!(encode_snapshot(&s).err(), Some(Error::InvalidInput));
        let mut s = attached_sample(false);
        s.attachments[0].size += 1;
        assert_eq!(encode_snapshot(&s).err(), Some(Error::InvalidInput));
        // A live attachment without bytes and a tombstone that still holds bytes are both invalid.
        let mut s = attached_sample(false);
        s.attachments[0] = attachment("att-1", "item-1", Vec::new(), None);
        assert_eq!(encode_snapshot(&s).err(), Some(Error::InvalidInput));
        let mut s = attached_sample(false);
        s.attachments[1] = attachment("att-2", "item-1", pattern(10), Some(1));
        assert_eq!(encode_snapshot(&s).err(), Some(Error::InvalidInput));
    }

    #[test]
    fn decode_rejects_attachment_bytes_that_do_not_match_or_are_missing() {
        let snap = attached_sample(false);
        let enc = encode_snapshot(&snap).unwrap();
        let wrong = decode_snapshot(5, &enc.payload, &mut |_, _| {
            Ok(Zeroizing::new(vec![1, 2, 3]))
        });
        assert_eq!(wrong.err(), Some(Error::Corrupted));
        let missing = decode_snapshot(5, &enc.payload, &mut no_resolver());
        assert_eq!(missing.err(), Some(Error::NotFound));
    }

    #[test]
    fn decode_rejects_an_attachment_of_an_unknown_item() {
        let mut s = attached_sample(false);
        s.attachments[0].item_id = "ghost".into();
        let enc = encode_snapshot(&s).unwrap();
        let r = decode_snapshot(5, &enc.payload, &mut attach_resolver);
        assert_eq!(r.err(), Some(Error::Corrupted));
    }

    #[test]
    fn truncated_v5_payloads_are_corrupted_never_a_panic() {
        let snap = attached_sample(false);
        let enc = encode_snapshot(&snap).unwrap();
        for cut in [1usize, 5, 40] {
            let short = &enc.payload[..enc.payload.len() - cut];
            let r = decode_snapshot(5, short, &mut attach_resolver);
            assert!(r.is_err(), "cut {cut}");
        }
    }

    #[test]
    fn v4_round_trips_vaults_and_v3_puts_everything_in_the_default_vault() {
        let snap = vaulted_sample(false);
        assert_eq!(round_trip(&snap), snap);
        let v3 =
            decode_snapshot(3, &encode_at(&snap, 3).unwrap().payload, &mut no_resolver()).unwrap();
        assert!(v3.items.iter().all(|i| i.vault_id == "default"));
        assert!(v3.vault_meta.iter().all(|v| v.deleted_at.is_none()));
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

    // ---- v6: passkeys (ADR 0020) ----

    const GOLDEN_V6: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/snapshot_v6.postcard"
    );

    /// RFC 6979 §A.2.5 test key (a published, fake key).
    const FAKE_KEY: [u8; 32] = [
        0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6,
        0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f,
        0x67, 0x21,
    ];

    fn passkey(id: &str, item: &str, deleted_at: Option<i64>) -> crate::models::Passkey {
        crate::models::Passkey {
            id: id.into(),
            item_id: item.into(),
            credential_id: vec![7; 16],
            rp_id: "example.com".into(),
            user_name: "ana@example.test".into(),
            user_handle: vec![1, 2, 3, 4],
            private_key: if deleted_at.is_some() {
                Vec::new()
            } else {
                FAKE_KEY.to_vec()
            },
            created_at: 1_700_000_013_000,
            updated_at: 1_700_000_014_000,
            updated_by: "dev-a".into(),
            deleted_at,
        }
    }

    /// The v5 sample plus one live passkey and one tombstoned one (what the v6 golden file pins).
    fn passkey_sample(big: bool) -> Snapshot {
        let mut s = attached_sample(big);
        s.passkeys.push(passkey("pk-1", "item-1", None));
        s.passkeys
            .push(passkey("pk-2", "item-1", Some(1_700_000_015_000)));
        s
    }

    #[test]
    fn passkeys_bump_to_v6_and_the_lower_versions_are_kept_otherwise() {
        assert_eq!(encode_snapshot(&vaulted_sample(false)).unwrap().version, 4);
        assert_eq!(encode_snapshot(&attached_sample(false)).unwrap().version, 5);
        assert_eq!(encode_snapshot(&passkey_sample(false)).unwrap().version, 6);
        // Passkeys without attachments still need v6 (v5's attachment list is just empty).
        let mut s = vaulted_sample(false);
        s.passkeys.push(passkey("pk-1", "item-1", None));
        assert_eq!(encode_snapshot(&s).unwrap().version, 6);
        assert_eq!(round_trip(&s), s);
    }

    #[test]
    fn passkeys_round_trip_inline_without_side_blobs() {
        let s = passkey_sample(false);
        let enc = encode_snapshot(&s).unwrap();
        // Only the attachment is a side blob.
        assert_eq!(enc.external.len(), 1);
        assert_eq!(round_trip(&s), s);
        let refs = external_image_refs(6, &enc.payload).unwrap();
        assert_eq!(refs, [(sha256_hex(&pattern(1_000)), 1_000)]);
    }

    #[test]
    fn golden_v6_blob_decodes_to_the_expected_snapshot() {
        let bytes = std::fs::read(GOLDEN_V6).unwrap();
        let out = decode_snapshot(6, &bytes, &mut attach_resolver).unwrap();
        assert_eq!(out, passkey_sample(true));
    }

    #[test]
    fn current_encoder_still_produces_the_golden_v6_bytes() {
        let bytes = std::fs::read(GOLDEN_V6).unwrap();
        let snap = passkey_sample(true);
        let enc = encode_snapshot(&snap).unwrap();
        assert_eq!(enc.version, 6);
        assert_eq!(*enc.payload, bytes);
    }

    #[test]
    fn encode_rejects_malformed_passkeys() {
        let cases: Vec<fn(&mut crate::models::Passkey)> = vec![
            |p| p.private_key = vec![0; 32],
            |p| p.private_key = vec![1; 31],
            |p| p.private_key.clear(),
            |p| p.rp_id = "Example.com".into(),
            |p| p.rp_id = "bad domain".into(),
            |p| p.user_handle.clear(),
            |p| p.user_handle = vec![0; 65],
            |p| p.credential_id.clear(),
        ];
        for (i, mutate) in cases.into_iter().enumerate() {
            let mut s = passkey_sample(false);
            mutate(&mut s.passkeys[0]);
            assert_eq!(
                encode_snapshot(&s).err(),
                Some(Error::InvalidInput),
                "case {i}"
            );
        }
        // A tombstone must have been scrubbed.
        let mut s = passkey_sample(false);
        s.passkeys[1].private_key = FAKE_KEY.to_vec();
        assert_eq!(encode_snapshot(&s).err(), Some(Error::InvalidInput));
    }

    #[test]
    fn decode_rejects_a_passkey_of_an_unknown_item_or_a_damaged_key() {
        let mut s = passkey_sample(false);
        s.passkeys[0].item_id = "ghost".into();
        let enc = encode_snapshot(&s).unwrap();
        let r = decode_snapshot(6, &enc.payload, &mut attach_resolver);
        assert_eq!(r.err(), Some(Error::Corrupted));

        // Flip the encoded key into an invalid scalar (all 0xff) inside an otherwise valid payload.
        let s = passkey_sample(false);
        let enc = encode_snapshot(&s).unwrap();
        let mut bytes = enc.payload.to_vec();
        let at = bytes.windows(32).position(|w| w == FAKE_KEY).unwrap();
        bytes[at..at + 32].fill(0xff);
        let r = decode_snapshot(6, &bytes, &mut attach_resolver);
        assert_eq!(r.err(), Some(Error::Corrupted));
    }

    #[test]
    fn truncated_v6_payloads_are_corrupted_never_a_panic() {
        let snap = passkey_sample(false);
        let enc = encode_snapshot(&snap).unwrap();
        for cut in [1usize, 5, 40] {
            let short = &enc.payload[..enc.payload.len() - cut];
            assert!(
                decode_snapshot(6, short, &mut attach_resolver).is_err(),
                "cut {cut}"
            );
        }
        // A v5 reader would see trailing bytes: older builds never mis-read a v6 payload.
        assert_eq!(
            decode_snapshot(5, &enc.payload, &mut attach_resolver).err(),
            Some(Error::Corrupted)
        );
    }
}
