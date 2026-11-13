//! Integration tests: snapshot load/save and transactional merge over the encrypted database.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::{ctx, db, key, login};
use vault_core::crypto::SecretKey;
use vault_core::db::{BlockInput, Database, FieldInput, ItemUpdate, NewCategory, NewItem};
use vault_core::models::{BlockKind, ItemField, ItemType, Snapshot, VaultMeta};
use vault_core::Error;

fn populated(device: &str) -> Database {
    let mut d = db();
    let cat = d
        .create_category(
            &ctx(device, 100),
            &NewCategory {
                name: "Finance".into(),
                color: "#112233".into(),
                icon: "bank".into(),
                icon_color: "#445566".into(),
                fields: vec![],
            },
        )
        .unwrap();
    let id = login(&mut d, device, 110, "My Bank", "fake-pw-1");
    d.update_item(
        &ctx(device, 120),
        &id,
        &ItemUpdate {
            category_id: Some(Some(cat.id.clone())),
            fields: Some(vec![
                FieldInput::new("username", "text", "user@example.test", false),
                FieldInput::new("password", "password", "fake-pw-2", true),
            ]),
            ..Default::default()
        },
    )
    .unwrap();
    let img = d
        .add_note_image(&ctx(device, 130), "image/png", &[1, 2, 3, 4])
        .unwrap();
    let mut note = NewItem::new(ItemType::Note, "Runbook");
    note.blocks = vec![
        BlockInput {
            id: None,
            kind: BlockKind::Code,
            language: None,
            content: "SELECT 1;".into(),
            image_id: None,
        },
        BlockInput {
            id: None,
            kind: BlockKind::Image,
            language: None,
            content: String::new(),
            image_id: Some(img),
        },
    ];
    d.create_item(&ctx(device, 140), &note).unwrap();
    let doomed = login(&mut d, device, 150, "Old Account", "fake-doomed");
    d.delete_item(&ctx(device, 160), &doomed).unwrap();
    d.record_use(&ctx(device, 170), &id).unwrap();
    d
}

fn with_meta(mut s: Snapshot) -> Snapshot {
    s.vault_meta.push(VaultMeta {
        id: "vault-1".into(),
        name: "Personal".into(),
        color: "#3B82F6".into(),
        badge: Some("P".into()),
        created_at: 1,
        updated_at: 1,
        updated_by: "dev-a".into(),
        deleted_at: None,
    });
    s
}

#[test]
fn snapshot_round_trips_through_a_fresh_database_without_loss() {
    let src = populated("dev-a");
    let snap = with_meta(src.load_snapshot().unwrap());
    assert!(!snap.items.is_empty() && !snap.item_fields.is_empty());
    assert!(!snap.note_blocks.is_empty() && !snap.note_images.is_empty());
    assert!(!snap.item_tags.is_empty() && !snap.categories.is_empty());

    let mut dst = db();
    dst.save_snapshot(&snap).unwrap();
    assert_eq!(dst.load_snapshot().unwrap(), snap);
}

#[test]
fn saving_the_same_snapshot_twice_is_idempotent() {
    let snap = populated("dev-a").load_snapshot().unwrap();
    let mut dst = db();
    dst.save_snapshot(&snap).unwrap();
    dst.save_snapshot(&snap).unwrap();
    assert_eq!(dst.load_snapshot().unwrap(), snap);
}

#[test]
fn snapshot_persists_across_reopen_of_the_database_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.db");
    let snap = populated("dev-a").load_snapshot().unwrap();
    {
        let mut d = Database::open(&path, &key()).unwrap();
        d.save_snapshot(&snap).unwrap();
    }
    let d = Database::open(&path, &key()).unwrap();
    assert_eq!(d.load_snapshot().unwrap(), snap);
    assert!(matches!(
        Database::open(&path, &SecretKey::from_bytes([9; 32])),
        Err(Error::Decryption)
    ));
}

#[test]
fn save_snapshot_rolls_back_everything_when_a_foreign_key_dangles() {
    let mut snap = populated("dev-a").load_snapshot().unwrap();
    let mut orphan: ItemField = snap.item_fields[0].clone();
    orphan.id = "orphan".into();
    orphan.item_id = "no-such-item".into();
    snap.item_fields.push(orphan);

    let mut dst = db();
    assert_eq!(dst.save_snapshot(&snap), Err(Error::Database));
    // Rolled back: only the default vault that every fresh database starts with remains.
    let after = dst.load_snapshot().unwrap();
    assert_eq!(after.vault_meta.len(), 1);
    assert_eq!(
        after,
        Snapshot {
            vault_meta: after.vault_meta.clone(),
            ..Snapshot::default()
        }
    );
}

#[test]
fn save_snapshot_never_hard_deletes_rows_missing_from_the_snapshot() {
    let mut d = populated("dev-a");
    let before = d.load_snapshot().unwrap();
    d.save_snapshot(&Snapshot::default()).unwrap();
    assert_eq!(d.load_snapshot().unwrap(), before);
}

#[test]
fn save_snapshot_does_not_overwrite_newer_local_edits_with_a_stale_snapshot() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "Mail", "fake-pw");
    let stale = d.load_snapshot().unwrap();
    d.update_item(
        &ctx("dev-a", 200),
        &id,
        &ItemUpdate {
            title: Some("Mail (work)".into()),
            ..Default::default()
        },
    )
    .unwrap();
    d.save_snapshot(&stale).unwrap();
    assert_eq!(d.get_item(&id).unwrap().summary.title, "Mail (work)");
}

#[test]
fn merge_remote_converges_two_devices_that_edited_different_and_same_items() {
    let mut a = db();
    let shared = login(&mut a, "dev-a", 100, "Shared", "fake-pw");
    let only_a = login(&mut a, "dev-a", 101, "OnlyA", "fake-a");
    let mut b = db();
    b.save_snapshot(&a.load_snapshot().unwrap()).unwrap();

    // Concurrent edits: A edits the shared item early, B edits it later (B wins).
    a.update_item(
        &ctx("dev-a", 200),
        &shared,
        &ItemUpdate {
            title: Some("Shared (A)".into()),
            ..Default::default()
        },
    )
    .unwrap();
    b.update_item(
        &ctx("dev-b", 300),
        &shared,
        &ItemUpdate {
            title: Some("Shared (B)".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let only_b = login(&mut b, "dev-b", 310, "OnlyB", "fake-b");
    a.delete_item(&ctx("dev-a", 400), &only_a).unwrap();

    let (sa, sb) = (a.load_snapshot().unwrap(), b.load_snapshot().unwrap());
    a.merge_remote(&sb).unwrap();
    b.merge_remote(&sa).unwrap();

    let merged = a.load_snapshot().unwrap();
    assert_eq!(merged, b.load_snapshot().unwrap(), "devices must converge");
    assert_eq!(a.get_item(&shared).unwrap().summary.title, "Shared (B)");
    assert!(a.get_item(&only_b).is_ok());
    assert_eq!(a.get_item(&only_a), Err(Error::NotFound));
    assert_eq!(b.get_item(&only_a), Err(Error::NotFound));
}

#[test]
fn merge_remote_unions_password_history_and_keeps_the_max_usage_counter() {
    let mut a = db();
    let id = login(&mut a, "dev-a", 100, "Site", "fake-v1");
    let mut b = db();
    b.save_snapshot(&a.load_snapshot().unwrap()).unwrap();
    let pw_field = |d: &Database| {
        d.get_item(&id)
            .unwrap()
            .fields
            .into_iter()
            .find(|f| f.kind == "password")
            .unwrap()
            .id
    };
    let change = |d: &mut Database, dev: &str, t: i64, pw: &str, fid: &str| {
        d.update_item(
            &ctx(dev, t),
            &id,
            &ItemUpdate {
                fields: Some(vec![
                    FieldInput::new("username", "text", "user@example.test", false)
                        .with_id(&d.get_item(&id).unwrap().fields[0].id),
                    FieldInput::new("password", "password", pw, true).with_id(fid),
                ]),
                ..Default::default()
            },
        )
        .unwrap();
    };
    let fid = pw_field(&a);
    change(&mut a, "dev-a", 200, "fake-v2-a", &fid);
    change(&mut b, "dev-b", 300, "fake-v2-b", &fid);
    for t in [210, 220, 230] {
        a.record_use(&ctx("dev-a", t), &id).unwrap();
    }
    b.record_use(&ctx("dev-b", 310), &id).unwrap();

    let (sa, sb) = (a.load_snapshot().unwrap(), b.load_snapshot().unwrap());
    a.merge_remote(&sb).unwrap();
    b.merge_remote(&sa).unwrap();
    assert_eq!(a.load_snapshot().unwrap(), b.load_snapshot().unwrap());

    let hist: Vec<String> = a
        .reveal_password_history(&id)
        .unwrap()
        .into_iter()
        .map(|h| h.password.clone())
        .collect();
    assert_eq!(hist.len(), 2, "both devices' previous values survive");
    assert!(hist.iter().all(|p| p == "fake-v1"));
    // Both devices replaced the same v1 value, so each recorded one entry (distinct ids).
    assert_eq!(a.get_item(&id).unwrap().summary.use_count, 3);
    assert_eq!(a.reveal_field(&id, &fid).unwrap().as_str(), "fake-v2-b");
}

#[test]
fn merge_remote_propagates_tombstones_and_scrubbed_values() {
    let mut a = db();
    let id = login(&mut a, "dev-a", 100, "Doomed", "fake-secret");
    let mut b = db();
    b.save_snapshot(&a.load_snapshot().unwrap()).unwrap();
    b.delete_item(&ctx("dev-b", 200), &id).unwrap();

    a.merge_remote(&b.load_snapshot().unwrap()).unwrap();
    let snap = a.load_snapshot().unwrap();
    assert!(snap.items[0].deleted_at.is_some());
    assert!(snap
        .item_fields
        .iter()
        .all(|f| f.deleted_at.is_some() && f.value.is_empty()));
    assert!(a.list_items().unwrap().is_empty());
}

#[test]
fn merge_remote_accepts_same_named_tags_created_on_two_devices() {
    let mut a = db();
    let mut b = db();
    a.create_tag(&ctx("dev-a", 100), "#project", "#111111")
        .unwrap();
    b.create_tag(&ctx("dev-b", 100), "#project", "#222222")
        .unwrap();

    a.merge_remote(&b.load_snapshot().unwrap()).unwrap();
    b.merge_remote(&a.load_snapshot().unwrap()).unwrap();
    assert_eq!(a.load_snapshot().unwrap(), b.load_snapshot().unwrap());
    assert_eq!(a.list_tags().unwrap().len(), 2);
}

#[test]
fn merge_remote_is_all_or_nothing_when_the_remote_snapshot_is_inconsistent() {
    let mut a = db();
    login(&mut a, "dev-a", 100, "Local", "fake-pw");
    let before = a.load_snapshot().unwrap();

    let mut remote = populated("dev-b").load_snapshot().unwrap();
    let mut orphan = remote.item_fields[0].clone();
    orphan.id = "orphan".into();
    orphan.item_id = "missing".into();
    remote.item_fields.push(orphan);

    assert!(a.merge_remote(&remote).is_err());
    assert_eq!(a.load_snapshot().unwrap(), before);
}

#[test]
fn merge_remote_with_itself_changes_nothing() {
    let mut d = populated("dev-a");
    let snap = d.load_snapshot().unwrap();
    d.merge_remote(&snap).unwrap();
    assert_eq!(d.load_snapshot().unwrap(), snap);
}
