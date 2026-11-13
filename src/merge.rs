//! Item-level last-writer-wins merge.
//!
//! `merge(a, b)` is a pure function that is **commutative, associative and idempotent**:
//! * the winner of two versions of a record is the maximum under a *total order*
//!   `(updated_at, updated_by, full-record Ord)`, so ties are broken deterministically;
//! * password history is the set union of both sides, so entries are never dropped;
//! * deletes are tombstones carried in the record, so they propagate like any other edit;
//! * output is sorted by id.
//!
//! * `use_count` / `last_used_at` are monotone counters merged as max, so usage recorded on a
//!   device that loses the LWW race is not lost.
//! * Child records (fields, tags links, note blocks) are independent versioned records merged by
//!   id. Merge never rewrites a record to "fix" it against its parent, because that would break
//!   associativity; readers hide children of tombstoned parents instead.
//!
//! Merge never touches disk; callers decrypt both vaults in memory and re-encrypt the result.
//! Clock skew: a device with a clock far in the future always wins; callers can detect this with
//! [`max_future_skew`] and warn (a hybrid logical clock is a candidate ADR).

use std::collections::BTreeMap;

use crate::models::{
    Category, CategoryField, Item, ItemField, ItemTag, NoteBlock, NoteImage, Snapshot, Tag,
    VaultMeta,
};

/// A record that participates in LWW merge.
pub trait Versioned: Clone + Ord {
    /// Stable record key (the id, or a composite key for link records).
    fn key(&self) -> String;
    /// Primary ordering key (modification time).
    fn updated_at(&self) -> i64;
    /// Secondary ordering key (writer device id).
    fn updated_by(&self) -> &str;
    /// Hook for merging side data after the winner is chosen (e.g. history union).
    /// Must be commutative, associative and idempotent.
    fn absorb(&mut self, _loser: &Self) {}
}

fn rank<T: Versioned>(r: &T) -> (i64, &str) {
    (r.updated_at(), r.updated_by())
}

fn pick_winner<T: Versioned>(a: &T, b: &T) -> T {
    // Strict total order: (updated_at, updated_by), then the whole record as a final tie-break.
    let a_wins = (rank(a), a) >= (rank(b), b);
    let (win, lose) = if a_wins { (a, b) } else { (b, a) };
    let mut out = win.clone();
    out.absorb(lose);
    out
}

/// Merge two record collections by key.
pub fn merge_records<T: Versioned>(a: &[T], b: &[T]) -> Vec<T> {
    let mut map: BTreeMap<String, T> = BTreeMap::new();
    for r in a.iter().chain(b.iter()) {
        let merged = match map.get(&r.key()) {
            Some(existing) => pick_winner(existing, r),
            None => r.clone(),
        };
        map.insert(r.key(), merged);
    }
    map.into_values().collect()
}

/// Images are immutable: union by id. A (corrupt) id collision resolves to the larger record so
/// the result stays deterministic.
fn merge_images(a: &[NoteImage], b: &[NoteImage]) -> Vec<NoteImage> {
    let mut map: BTreeMap<&str, &NoteImage> = BTreeMap::new();
    for r in a.iter().chain(b.iter()) {
        match map.get(r.id.as_str()) {
            Some(existing) if *existing >= r => {}
            _ => {
                map.insert(r.id.as_str(), r);
            }
        }
    }
    map.into_values().cloned().collect()
}

/// Merge two vault snapshots.
pub fn merge(local: &Snapshot, remote: &Snapshot) -> Snapshot {
    Snapshot {
        vault_meta: merge_records(&local.vault_meta, &remote.vault_meta),
        categories: merge_records(&local.categories, &remote.categories),
        category_fields: merge_records(&local.category_fields, &remote.category_fields),
        tags: merge_records(&local.tags, &remote.tags),
        items: merge_records(&local.items, &remote.items),
        item_fields: merge_records(&local.item_fields, &remote.item_fields),
        item_tags: merge_records(&local.item_tags, &remote.item_tags),
        note_blocks: merge_records(&local.note_blocks, &remote.note_blocks),
        note_images: merge_images(&local.note_images, &remote.note_images),
    }
}

/// Largest amount (ms) by which any record's `updated_at` exceeds `now_ms`; 0 if none do.
/// Use to warn about devices with a wrong clock before merging.
pub fn max_future_skew(s: &Snapshot, now_ms: i64) -> i64 {
    let times = s
        .vault_meta
        .iter()
        .map(|r| r.updated_at)
        .chain(s.categories.iter().map(|r| r.updated_at))
        .chain(s.category_fields.iter().map(|r| r.updated_at))
        .chain(s.tags.iter().map(|r| r.updated_at))
        .chain(s.items.iter().map(|r| r.updated_at))
        .chain(s.item_fields.iter().map(|r| r.updated_at))
        .chain(s.item_tags.iter().map(|r| r.updated_at))
        .chain(s.note_blocks.iter().map(|r| r.updated_at));
    times.map(|t| t - now_ms).max().unwrap_or(0).max(0)
}

macro_rules! versioned_by_id {
    ($($t:ty),*) => {$(
        impl Versioned for $t {
            fn key(&self) -> String {
                self.id.clone()
            }
            fn updated_at(&self) -> i64 {
                self.updated_at
            }
            fn updated_by(&self) -> &str {
                &self.updated_by
            }
        }
    )*};
}

versioned_by_id!(
    Category,
    CategoryField,
    Tag,
    ItemField,
    NoteBlock,
    VaultMeta
);

impl Versioned for ItemTag {
    fn key(&self) -> String {
        format!("{}/{}", self.item_id, self.tag_id)
    }
    fn updated_at(&self) -> i64 {
        self.updated_at
    }
    fn updated_by(&self) -> &str {
        &self.updated_by
    }
}

impl Versioned for Item {
    fn key(&self) -> String {
        self.id.clone()
    }
    fn updated_at(&self) -> i64 {
        self.updated_at
    }
    fn updated_by(&self) -> &str {
        &self.updated_by
    }
    fn absorb(&mut self, loser: &Self) {
        self.history.extend(loser.history.iter().cloned());
        self.use_count = self.use_count.max(loser.use_count);
        self.last_used_at = self.last_used_at.max(loser.last_used_at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{BlockKind, CategoryField, HistoryEntry, ItemType};
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    fn item(id: &str, body: &str, t: i64, dev: &str, del: Option<i64>) -> Item {
        Item {
            id: id.into(),
            category_id: None,
            item_type: ItemType::Credential,
            title: body.into(),
            url: None,
            color: None,
            favorite: false,
            created_at: 0,
            updated_at: t,
            updated_by: dev.into(),
            deleted_at: del,
            trashed_at: None,
            use_count: 0,
            last_used_at: None,
            history: BTreeSet::new(),
        }
    }

    fn snap(items: Vec<Item>) -> Snapshot {
        Snapshot {
            items,
            ..Default::default()
        }
    }

    #[test]
    fn merge_keeps_newer_updated_at() {
        let m = merge(
            &snap(vec![item("a", "old", 1, "d1", None)]),
            &snap(vec![item("a", "new", 2, "d2", None)]),
        );
        assert_eq!(m.items[0].title, "new");
    }

    #[test]
    fn merge_unions_disjoint_items() {
        let m = merge(
            &snap(vec![item("a", "x", 1, "d1", None)]),
            &snap(vec![item("b", "y", 1, "d2", None)]),
        );
        assert_eq!(
            m.items.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
    }

    #[test]
    fn tie_on_timestamp_is_broken_by_device_id_deterministically() {
        let a = snap(vec![item("a", "from-d1", 5, "d1", None)]);
        let b = snap(vec![item("a", "from-d2", 5, "d2", None)]);
        assert_eq!(merge(&a, &b).items[0].title, "from-d2");
        assert_eq!(merge(&b, &a).items[0].title, "from-d2");
    }

    #[test]
    fn newer_tombstone_propagates_and_newer_edit_resurrects() {
        let live = item("a", "x", 1, "d1", None);
        let dead = item("a", "x", 2, "d2", Some(2));
        assert!(
            merge(&snap(vec![live.clone()]), &snap(vec![dead.clone()])).items[0]
                .deleted_at
                .is_some()
        );
        let revived = item("a", "y", 3, "d1", None);
        assert!(merge(&snap(vec![dead]), &snap(vec![revived])).items[0]
            .deleted_at
            .is_none());
    }

    #[test]
    fn password_history_is_unioned_even_when_loser_has_extra_entries() {
        let h = |id: &str, t: i64| HistoryEntry {
            id: id.into(),
            field_id: None,
            password: format!("fake-{id}"),
            changed_at: t,
        };
        let mut a = item("a", "x", 1, "d1", None);
        a.history.insert(h("h1", 1));
        let mut b = item("a", "y", 2, "d2", None);
        b.history.insert(h("h2", 2));
        let m = merge(&snap(vec![a]), &snap(vec![b]));
        assert_eq!(m.items[0].title, "y");
        assert_eq!(m.items[0].history.len(), 2);
    }

    #[test]
    fn future_skew_is_reported() {
        let s = snap(vec![item("a", "x", 10_000, "d", None)]);
        assert_eq!(max_future_skew(&s, 4_000), 6_000);
        assert_eq!(max_future_skew(&s, 20_000), 0);
    }

    fn arb_item() -> impl Strategy<Value = Item> {
        (
            0u8..4,
            "[a-c]{0,2}",
            0i64..4,
            0u8..3,
            proptest::option::of(0i64..4),
            (0i64..5, proptest::option::of(0i64..5)),
            proptest::collection::btree_set((0u8..4, 0i64..3), 0..3),
        )
            .prop_map(|(id, title, t, dev, del, (uses, last), hist)| {
                let mut it = item(&format!("i{id}"), &title, t, &format!("d{dev}"), del);
                it.use_count = uses;
                it.last_used_at = last;
                it.history = hist
                    .into_iter()
                    .map(|(h, c)| HistoryEntry {
                        id: format!("h{h}"),
                        field_id: None,
                        password: "fake".into(),
                        changed_at: c,
                    })
                    .collect();
                it
            })
    }

    fn arb_field() -> impl Strategy<Value = ItemField> {
        (
            0u8..3,
            "[a-c]{0,2}",
            0i64..4,
            0u8..3,
            proptest::option::of(0i64..4),
        )
            .prop_map(|(id, value, t, dev, del)| ItemField {
                id: format!("f{id}"),
                item_id: "i0".into(),
                name: "n".into(),
                kind: "text".into(),
                value,
                is_secret: false,
                sort_order: 0,
                updated_at: t,
                updated_by: format!("d{dev}"),
                deleted_at: del,
            })
    }

    fn arb_item_tag() -> impl Strategy<Value = ItemTag> {
        (
            0u8..3,
            any::<bool>(),
            0i64..4,
            0u8..3,
            proptest::option::of(0i64..4),
        )
            .prop_map(|(tag, auto, t, dev, del)| ItemTag {
                item_id: "i0".into(),
                tag_id: format!("t{tag}"),
                auto,
                updated_at: t,
                updated_by: format!("d{dev}"),
                deleted_at: del,
            })
    }

    fn arb_block() -> impl Strategy<Value = NoteBlock> {
        (
            0u8..3,
            "[a-c]{0,2}",
            0i64..4,
            0u8..3,
            proptest::option::of(0i64..4),
        )
            .prop_map(|(id, content, t, dev, del)| NoteBlock {
                id: format!("b{id}"),
                item_id: "i0".into(),
                position: 0,
                kind: BlockKind::Code,
                language: None,
                content,
                image_id: None,
                updated_at: t,
                updated_by: format!("d{dev}"),
                deleted_at: del,
            })
    }

    fn arb_category() -> impl Strategy<Value = Category> {
        (
            0u8..3,
            "[a-c]{0,2}",
            0i64..4,
            0u8..3,
            proptest::option::of(0i64..4),
        )
            .prop_map(|(id, name, t, dev, del)| Category {
                id: format!("c{id}"),
                name,
                color: "#000".into(),
                icon: "i".into(),
                icon_color: "#fff".into(),
                preset: None,
                sort_order: 0,
                created_at: 0,
                updated_at: t,
                updated_by: format!("d{dev}"),
                deleted_at: del,
            })
    }

    fn arb_category_field() -> impl Strategy<Value = CategoryField> {
        (
            0u8..3,
            "[a-c]{1,2}",
            0i64..4,
            0u8..3,
            proptest::option::of(0i64..4),
            any::<bool>(),
        )
            .prop_map(|(id, name, t, dev, del, core)| CategoryField {
                id: format!("cf{id}"),
                category_id: "c0".into(),
                name,
                kind: "text".into(),
                is_secret: false,
                is_core: core,
                sort_order: 0,
                updated_at: t,
                updated_by: format!("d{dev}"),
                deleted_at: del,
            })
    }

    fn arb_snap() -> impl Strategy<Value = Snapshot> {
        (
            proptest::collection::vec(arb_item(), 0..5),
            proptest::collection::vec(arb_field(), 0..4),
            proptest::collection::vec(arb_item_tag(), 0..4),
            proptest::collection::vec(arb_block(), 0..4),
            proptest::collection::vec(arb_category(), 0..3),
            proptest::collection::vec(arb_category_field(), 0..3),
        )
            .prop_map(
                |(items, item_fields, item_tags, note_blocks, categories, category_fields)| {
                    // Normalize duplicate keys inside one generated side.
                    merge(
                        &Snapshot::default(),
                        &Snapshot {
                            items,
                            item_fields,
                            item_tags,
                            note_blocks,
                            categories,
                            category_fields,
                            ..Default::default()
                        },
                    )
                },
            )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn merge_is_commutative(a in arb_snap(), b in arb_snap()) {
            prop_assert_eq!(merge(&a, &b), merge(&b, &a));
        }

        #[test]
        fn merge_is_idempotent(a in arb_snap(), b in arb_snap()) {
            let m = merge(&a, &b);
            prop_assert_eq!(merge(&m, &m), m.clone());
            prop_assert_eq!(merge(&m, &a), m.clone());
        }

        #[test]
        fn merge_is_associative(a in arb_snap(), b in arb_snap(), c in arb_snap()) {
            prop_assert_eq!(merge(&merge(&a, &b), &c), merge(&a, &merge(&b, &c)));
        }

        #[test]
        fn merge_loses_no_keys_history_or_usage(a in arb_snap(), b in arb_snap()) {
            let m = merge(&a, &b);
            for src in a.items.iter().chain(b.items.iter()) {
                let out = m.items.iter().find(|i| i.id == src.id);
                prop_assert!(out.is_some());
                let out = out.unwrap();
                prop_assert!(src.history.is_subset(&out.history));
                prop_assert!(out.use_count >= src.use_count);
                prop_assert!(out.last_used_at >= src.last_used_at);
            }
            for src in a.item_fields.iter().chain(b.item_fields.iter()) {
                prop_assert!(m.item_fields.iter().any(|f| f.id == src.id));
            }
            for src in a.item_tags.iter().chain(b.item_tags.iter()) {
                prop_assert!(m.item_tags.iter().any(|l| l.tag_id == src.tag_id));
            }
            for src in a.note_blocks.iter().chain(b.note_blocks.iter()) {
                prop_assert!(m.note_blocks.iter().any(|x| x.id == src.id));
            }
        }
    }

    #[test]
    fn usage_counters_survive_when_the_other_side_wins_lww() {
        let mut stale = item("a", "old", 1, "d1", None);
        stale.use_count = 7;
        stale.last_used_at = Some(90);
        let fresh = item("a", "new", 2, "d2", None);
        let m = merge(&snap(vec![stale]), &snap(vec![fresh]));
        assert_eq!(m.items[0].title, "new");
        assert_eq!(m.items[0].use_count, 7);
        assert_eq!(m.items[0].last_used_at, Some(90));
    }

    #[test]
    fn tombstoned_field_with_newer_timestamp_beats_live_edit() {
        let live = ItemField {
            id: "f".into(),
            item_id: "i".into(),
            name: "pw".into(),
            kind: "password".into(),
            value: "fake-live".into(),
            is_secret: true,
            sort_order: 0,
            updated_at: 1,
            updated_by: "d1".into(),
            deleted_at: None,
        };
        let mut dead = live.clone();
        dead.value = String::new();
        dead.updated_at = 2;
        dead.updated_by = "d2".into();
        dead.deleted_at = Some(2);
        let m = merge(
            &Snapshot {
                item_fields: vec![live],
                ..Default::default()
            },
            &Snapshot {
                item_fields: vec![dead],
                ..Default::default()
            },
        );
        assert_eq!(m.item_fields[0].deleted_at, Some(2));
        assert!(m.item_fields[0].value.is_empty());
    }

    #[test]
    fn debug_output_never_contains_secret_values() {
        let f = ItemField {
            id: "f".into(),
            item_id: "i".into(),
            name: "pw".into(),
            kind: "password".into(),
            value: "fake-secret-value".into(),
            is_secret: true,
            sort_order: 0,
            updated_at: 1,
            updated_by: "d".into(),
            deleted_at: None,
        };
        let h = HistoryEntry {
            id: "h".into(),
            field_id: None,
            password: "fake-old-secret".into(),
            changed_at: 1,
        };
        let out = format!("{f:?} {h:?}");
        assert!(!out.contains("fake-secret-value") && !out.contains("fake-old-secret"));
    }
}
