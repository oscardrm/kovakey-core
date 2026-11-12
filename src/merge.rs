//! Item-level last-writer-wins merge.
//!
//! `merge(a, b)` is a pure function that is **commutative, associative and idempotent**:
//! * the winner of two versions of a record is the maximum under a *total order*
//!   `(updated_at, updated_by, full-record Ord)`, so ties are broken deterministically;
//! * password history is the set union of both sides, so entries are never dropped;
//! * deletes are tombstones carried in the record, so they propagate like any other edit;
//! * output is sorted by id.
//!
//! Merge never touches disk; callers decrypt both vaults in memory and re-encrypt the result.
//! Clock skew: a device with a clock far in the future always wins; callers can detect this with
//! [`max_future_skew`] and warn (a hybrid logical clock is a candidate ADR).

use std::collections::BTreeMap;

use crate::models::{Category, Item, Snapshot, Tag};

/// A record that participates in LWW merge.
pub trait Versioned: Clone + Ord {
    /// Stable record id.
    fn id(&self) -> &str;
    /// Primary ordering key (modification time).
    fn updated_at(&self) -> i64;
    /// Secondary ordering key (writer device id).
    fn updated_by(&self) -> &str;
    /// Hook for merging side data after the winner is chosen (e.g. history union).
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

/// Merge two record collections by id.
pub fn merge_records<T: Versioned>(a: &[T], b: &[T]) -> Vec<T> {
    let mut map: BTreeMap<String, T> = BTreeMap::new();
    for r in a.iter().chain(b.iter()) {
        match map.get(r.id()) {
            Some(existing) => {
                let merged = pick_winner(existing, r);
                map.insert(r.id().to_string(), merged);
            }
            None => {
                map.insert(r.id().to_string(), r.clone());
            }
        }
    }
    map.into_values().collect()
}

/// Merge two vault snapshots.
pub fn merge(local: &Snapshot, remote: &Snapshot) -> Snapshot {
    Snapshot {
        items: merge_records(&local.items, &remote.items),
        categories: merge_records(&local.categories, &remote.categories),
        tags: merge_records(&local.tags, &remote.tags),
    }
}

/// Largest amount (ms) by which any record's `updated_at` exceeds `now_ms`; 0 if none do.
/// Use to warn about devices with a wrong clock before merging.
pub fn max_future_skew(s: &Snapshot, now_ms: i64) -> i64 {
    let it = s.items.iter().map(|r| r.updated_at);
    let ca = s.categories.iter().map(|r| r.updated_at);
    let tg = s.tags.iter().map(|r| r.updated_at);
    it.chain(ca)
        .chain(tg)
        .map(|t| t - now_ms)
        .max()
        .unwrap_or(0)
        .max(0)
}

impl Versioned for Item {
    fn id(&self) -> &str {
        &self.id
    }
    fn updated_at(&self) -> i64 {
        self.updated_at
    }
    fn updated_by(&self) -> &str {
        &self.updated_by
    }
    fn absorb(&mut self, loser: &Self) {
        self.history.extend(loser.history.iter().cloned());
    }
}

impl Versioned for Category {
    fn id(&self) -> &str {
        &self.id
    }
    fn updated_at(&self) -> i64 {
        self.updated_at
    }
    fn updated_by(&self) -> &str {
        &self.updated_by
    }
}

impl Versioned for Tag {
    fn id(&self) -> &str {
        &self.id
    }
    fn updated_at(&self) -> i64 {
        self.updated_at
    }
    fn updated_by(&self) -> &str {
        &self.updated_by
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::HistoryEntry;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    fn item(id: &str, body: &str, t: i64, dev: &str, del: Option<i64>) -> Item {
        Item {
            id: id.into(),
            title: "t".into(),
            body: body.into(),
            updated_at: t,
            updated_by: dev.into(),
            deleted_at: del,
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
        assert_eq!(m.items[0].body, "new");
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
        assert_eq!(merge(&a, &b).items[0].body, "from-d2");
        assert_eq!(merge(&b, &a).items[0].body, "from-d2");
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
            password: format!("fake-{id}"),
            changed_at: t,
        };
        let mut a = item("a", "x", 1, "d1", None);
        a.history.insert(h("h1", 1));
        let mut b = item("a", "y", 2, "d2", None);
        b.history.insert(h("h2", 2));
        let m = merge(&snap(vec![a]), &snap(vec![b]));
        assert_eq!(m.items[0].body, "y");
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
            proptest::collection::btree_set((0u8..4, 0i64..3), 0..3),
        )
            .prop_map(|(id, body, t, dev, del, hist)| Item {
                id: format!("i{id}"),
                title: "t".into(),
                body,
                updated_at: t,
                updated_by: format!("d{dev}"),
                deleted_at: del,
                history: hist
                    .into_iter()
                    .map(|(h, c)| HistoryEntry {
                        id: format!("h{h}"),
                        password: "fake".into(),
                        changed_at: c,
                    })
                    .collect(),
            })
    }

    fn arb_snap() -> impl Strategy<Value = Snapshot> {
        proptest::collection::vec(arb_item(), 0..6)
            .prop_map(|items| merge(&Snapshot::default(), &snap(items)))
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
        fn merge_loses_no_ids_or_history(a in arb_snap(), b in arb_snap()) {
            let m = merge(&a, &b);
            for src in a.items.iter().chain(b.items.iter()) {
                let out = m.items.iter().find(|i| i.id == src.id);
                prop_assert!(out.is_some());
                prop_assert!(src.history.is_subset(&out.unwrap().history));
            }
        }
    }
}
