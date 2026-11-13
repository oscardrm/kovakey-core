use super::common::{ctx, login};
use vault_core::db::{
    BlockInput, CategoryFieldInput, CategoryUpdate, FieldInput, ItemUpdate, NewCategory, NewItem, VaultStore,
};
use vault_core::ops::VaultUpdate;
use vault_core::models::{BlockKind, InputKind, ItemType};
use vault_core::Error;

// Included twice by `crud.rs`: once per `VaultStore` backend. `Store` and `db()` are defined there.
fn field_id(d: &Store, item: &str, kind: &str) -> String {
    d.get_item(item)
        .unwrap()
        .fields
        .into_iter()
        .find(|f| f.kind == kind)
        .unwrap()
        .id
}

fn set_password(d: &mut Store, item: &str, now: i64, pw: &str) -> vault_core::Result<()> {
    let user = field_id(d, item, "text");
    let pass = field_id(d, item, "password");
    d.update_item(
        &ctx("dev-a", now),
        item,
        &ItemUpdate {
            fields: Some(vec![
                FieldInput::new("username", "text", "user@example.test", false).with_id(&user),
                FieldInput::new("password", "password", pw, true).with_id(&pass),
            ]),
            ..Default::default()
        },
    )
}

fn tags_of(d: &Store, item: &str) -> Vec<String> {
    d.get_item(item).unwrap().summary.tags
}

// ---- reads / secrets --------------------------------------------------------------------

#[test]
fn get_item_withholds_secret_values_and_reveal_returns_them() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "Mail", "fake-secret-1");
    let detail = d.get_item(&id).unwrap();
    let pw = detail.fields.iter().find(|f| f.kind == "password").unwrap();
    assert_eq!(pw.value, None);
    let user = detail.fields.iter().find(|f| f.kind == "text").unwrap();
    assert_eq!(user.value.as_deref(), Some("user@example.test"));
    assert_eq!(
        d.reveal_field(&id, &pw.id).unwrap().as_str(),
        "fake-secret-1"
    );
    assert!(!format!("{detail:?}").contains("fake-secret-1"));
}

#[test]
fn list_items_is_sorted_by_title_and_excludes_deleted() {
    let mut d = db();
    let b = login(&mut d, "dev-a", 100, "banana", "fake");
    login(&mut d, "dev-a", 101, "Apple", "fake");
    d.delete_item(&ctx("dev-a", 200), &b).unwrap();
    let titles: Vec<_> = d
        .list_items()
        .unwrap()
        .into_iter()
        .map(|s| s.title)
        .collect();
    assert_eq!(titles, ["Apple"]);
}

// ---- password history -------------------------------------------------------------------

#[test]
fn changing_a_password_records_the_old_value_in_history() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "Mail", "fake-v1");
    set_password(&mut d, &id, 200, "fake-v2").unwrap();
    set_password(&mut d, &id, 300, "fake-v3").unwrap();
    let hist = d.reveal_password_history(&id).unwrap();
    let values: Vec<_> = hist.iter().map(|h| h.password.as_str()).collect();
    assert_eq!(values, ["fake-v2", "fake-v1"], "newest first");
    assert!(hist.iter().all(|h| h.field_id.is_some()));
    let pass = field_id(&d, &id, "password");
    assert_eq!(d.reveal_field(&id, &pass).unwrap().as_str(), "fake-v3");
}

#[test]
fn rewriting_the_same_password_adds_no_history_and_keeps_updated_at() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "Mail", "fake-v1");
    let before = d.get_item(&id).unwrap().summary.updated_at;
    set_password(&mut d, &id, 200, "fake-v1").unwrap();
    assert!(d.reveal_password_history(&id).unwrap().is_empty());
    assert_eq!(d.get_item(&id).unwrap().summary.updated_at, before);
}

#[test]
fn changing_a_non_password_field_adds_no_history() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "Mail", "fake-v1");
    let user = field_id(&d, &id, "text");
    let pass = field_id(&d, &id, "password");
    d.update_item(
        &ctx("dev-a", 200),
        &id,
        &ItemUpdate {
            fields: Some(vec![
                FieldInput::new("username", "text", "other@example.test", false).with_id(&user),
                FieldInput::new("password", "password", "fake-v1", true).with_id(&pass),
            ]),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(d.reveal_password_history(&id).unwrap().is_empty());
}

#[test]
fn failed_update_rolls_back_history_and_field_changes() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "Mail", "fake-v1");
    let pass = field_id(&d, &id, "password");
    let snapshot = d.snapshot().unwrap();
    let res = d.update_item(
        &ctx("dev-a", 200),
        &id,
        &ItemUpdate {
            fields: Some(vec![
                FieldInput::new("password", "password", "fake-v2", true).with_id(&pass),
                FieldInput::new("bogus", "text", "x", false).with_id("no-such-field"),
            ]),
            ..Default::default()
        },
    );
    assert_eq!(res, Err(Error::NotFound));
    assert_eq!(d.snapshot().unwrap(), snapshot);
    assert!(d.reveal_password_history(&id).unwrap().is_empty());
}

// ---- tombstones -------------------------------------------------------------------------

#[test]
fn delete_item_tombstones_children_scrubs_secrets_and_keeps_history() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "My Bank", "fake-v1");
    set_password(&mut d, &id, 150, "fake-v2").unwrap();
    d.delete_item(&ctx("dev-a", 200), &id).unwrap();

    let snap = d.snapshot().unwrap();
    let item = snap.items.iter().find(|i| i.id == id).unwrap();
    assert!(item.deleted_at.is_some());
    assert_eq!(item.history.len(), 1, "history survives deletion");
    assert!(!snap.item_fields.is_empty());
    assert!(snap
        .item_fields
        .iter()
        .all(|f| f.deleted_at.is_some() && f.value.is_empty()));
    assert!(
        snap.item_tags.iter().all(|l| l.deleted_at.is_some()),
        "tag links tombstoned"
    );
    assert_eq!(d.get_item(&id), Err(Error::NotFound));
    assert!(d.list_items().unwrap().is_empty());
    assert_eq!(d.delete_item(&ctx("dev-a", 300), &id), Err(Error::NotFound));
}

// ---- trash ------------------------------------------------------------------------------

#[test]
fn trashed_items_keep_their_content_and_leave_the_lists() {
    let mut d = db();
    let keep = login(&mut d, "dev-a", 100, "Keep", "fake-keep");
    let id = login(&mut d, "dev-a", 110, "Bank", "fake-bank");
    d.trash_item(&ctx("dev-a", 200), &id).unwrap();

    let titles: Vec<String> = d.list_items().unwrap().into_iter().map(|i| i.title).collect();
    assert_eq!(titles, ["Keep"]);
    let trashed = d.list_trashed_items().unwrap();
    assert_eq!(trashed.len(), 1);
    assert_eq!(trashed[0].id, id);
    assert!(trashed[0].trashed_at.is_some());

    // Content is intact and still revealable (so the Trash screen can show and copy it).
    let detail = d.get_item(&id).unwrap();
    assert_eq!(detail.summary.trashed_at, trashed[0].trashed_at);
    let pw = field_id(&d, &id, "password");
    assert_eq!(d.reveal_field(&id, &pw).unwrap().as_str(), "fake-bank");
    let snap = d.snapshot().unwrap();
    assert!(snap
        .item_fields
        .iter()
        .filter(|f| f.item_id == id)
        .all(|f| f.deleted_at.is_none() && !f.value.is_empty()));
    assert!(d.get_item(&keep).unwrap().summary.trashed_at.is_none());
}

#[test]
fn trashed_items_are_read_only_until_restored() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "Bank", "fake-bank");
    d.trash_item(&ctx("dev-a", 200), &id).unwrap();
    let rename = ItemUpdate {
        title: Some("Renamed".into()),
        ..Default::default()
    };
    assert_eq!(
        d.update_item(&ctx("dev-a", 210), &id, &rename),
        Err(Error::InvalidInput)
    );
    assert_eq!(d.record_use(&ctx("dev-a", 210), &id), Err(Error::InvalidInput));

    d.restore_item(&ctx("dev-a", 300), &id).unwrap();
    d.update_item(&ctx("dev-a", 310), &id, &rename).unwrap();
    assert_eq!(d.list_items().unwrap()[0].title, "Renamed");
    assert!(d.list_trashed_items().unwrap().is_empty());
    assert!(d.get_item(&id).unwrap().summary.trashed_at.is_none());
}

#[test]
fn trash_and_restore_are_idempotent_and_bump_updated_at() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "Bank", "fake-bank");
    d.trash_item(&ctx("dev-a", 200), &id).unwrap();
    let first = d.get_item(&id).unwrap().summary;
    d.trash_item(&ctx("dev-a", 250), &id).unwrap();
    assert_eq!(d.get_item(&id).unwrap().summary, first, "second trash is a no-op");
    assert!(first.updated_at >= 200);

    d.restore_item(&ctx("dev-a", 300), &id).unwrap();
    let restored = d.get_item(&id).unwrap().summary;
    assert!(restored.updated_at > first.updated_at);
    d.restore_item(&ctx("dev-a", 400), &id).unwrap();
    assert_eq!(d.get_item(&id).unwrap().summary, restored, "restoring a live item is a no-op");
}

#[test]
fn trashing_or_restoring_a_missing_item_is_not_found() {
    let mut d = db();
    assert_eq!(d.trash_item(&ctx("dev-a", 1), "nope"), Err(Error::NotFound));
    assert_eq!(d.restore_item(&ctx("dev-a", 1), "nope"), Err(Error::NotFound));
}

#[test]
fn deleting_a_trashed_item_purges_it_for_good() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "Bank", "fake-bank");
    d.trash_item(&ctx("dev-a", 200), &id).unwrap();
    d.delete_item(&ctx("dev-a", 300), &id).unwrap();

    assert!(d.list_trashed_items().unwrap().is_empty());
    assert_eq!(d.get_item(&id), Err(Error::NotFound));
    assert_eq!(d.restore_item(&ctx("dev-a", 400), &id), Err(Error::NotFound));
    let snap = d.snapshot().unwrap();
    let item = snap.items.iter().find(|i| i.id == id).unwrap();
    assert!(item.deleted_at.is_some() && item.trashed_at.is_none());
    assert!(snap.item_fields.iter().all(|f| f.value.is_empty()));
}

#[test]
fn trash_is_listed_newest_first_and_emptied_on_demand() {
    let mut d = db();
    let a = login(&mut d, "dev-a", 100, "A", "fake-a");
    let b = login(&mut d, "dev-a", 110, "B", "fake-b");
    let live = login(&mut d, "dev-a", 120, "Live", "fake-l");
    d.trash_item(&ctx("dev-a", 200), &a).unwrap();
    d.trash_item(&ctx("dev-a", 300), &b).unwrap();
    let ids: Vec<String> = d.list_trashed_items().unwrap().into_iter().map(|i| i.id).collect();
    assert_eq!(ids, [b, a]);

    assert_eq!(vault_core::db::empty_trash(&mut d, &ctx("dev-a", 400)).unwrap(), 2);
    assert!(d.list_trashed_items().unwrap().is_empty());
    assert_eq!(d.list_items().unwrap()[0].id, live, "live items are untouched");
}

#[test]
fn expired_trash_is_purged_by_retention_and_zero_keeps_everything() {
    const DAY: i64 = 86_400_000;
    let mut d = db();
    let old = login(&mut d, "dev-a", 100, "Old", "fake-o");
    let fresh = login(&mut d, "dev-a", 110, "Fresh", "fake-f");
    d.trash_item(&ctx("dev-a", 1_000), &old).unwrap();
    d.trash_item(&ctx("dev-a", 1_000 + 20 * DAY), &fresh).unwrap();

    let now = 1_000 + 31 * DAY;
    assert_eq!(vault_core::db::purge_expired_trash(&mut d, &ctx("dev-a", now), 0).unwrap(), 0);
    assert_eq!(vault_core::db::purge_expired_trash(&mut d, &ctx("dev-a", now), 30).unwrap(), 1);
    let left: Vec<String> = d.list_trashed_items().unwrap().into_iter().map(|i| i.id).collect();
    assert_eq!(left, [fresh], "only the item past the retention window is purged");
    assert_eq!(d.get_item(&old), Err(Error::NotFound));
}

#[test]
fn trash_state_survives_a_snapshot_merge() {
    let mut a = db();
    let id = login(&mut a, "dev-a", 100, "Bank", "fake-bank");
    let mut b = db();
    b.merge_remote(&a.snapshot().unwrap()).unwrap();
    a.trash_item(&ctx("dev-a", 200), &id).unwrap();
    b.merge_remote(&a.snapshot().unwrap()).unwrap();
    assert_eq!(b.list_trashed_items().unwrap().len(), 1);
    assert!(b.list_items().unwrap().is_empty());

    // Restoring on the other device later wins the last-writer merge.
    b.restore_item(&ctx("dev-b", 300), &id).unwrap();
    a.merge_remote(&b.snapshot().unwrap()).unwrap();
    assert!(a.list_trashed_items().unwrap().is_empty());
    assert_eq!(a.list_items().unwrap().len(), 1);
}

#[test]
fn removing_a_field_or_block_tombstones_and_scrubs_it() {
    let mut d = db();
    let mut n = NewItem::new(ItemType::Note, "Notes");
    n.fields = vec![FieldInput::new("pin", "text", "fake-1234", true)];
    n.blocks = vec![BlockInput {
        id: None,
        kind: BlockKind::RichText,
        language: None,
        content: "fake-note-body".into(),
        image_id: None,
    }];
    let id = d.create_item(&ctx("dev-a", 100), &n).unwrap();
    d.update_item(
        &ctx("dev-a", 200),
        &id,
        &ItemUpdate {
            fields: Some(vec![]),
            blocks: Some(vec![]),
            ..Default::default()
        },
    )
    .unwrap();
    let snap = d.snapshot().unwrap();
    assert!(snap.item_fields[0].value.is_empty() && snap.item_fields[0].deleted_at.is_some());
    assert!(snap.note_blocks[0].content.is_empty() && snap.note_blocks[0].deleted_at.is_some());
    let detail = d.get_item(&id).unwrap();
    assert!(detail.fields.is_empty() && detail.blocks.is_empty());
}

#[test]
fn updated_at_strictly_increases_even_if_the_clock_moves_backwards() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 1_000, "Mail", "fake");
    for (now, title) in [(500, "one"), (500, "two")] {
        let before = d.get_item(&id).unwrap().summary.updated_at;
        d.update_item(
            &ctx("dev-a", now),
            &id,
            &ItemUpdate {
                title: Some(title.into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(d.get_item(&id).unwrap().summary.updated_at > before);
    }
}

// ---- auto-tagger ------------------------------------------------------------------------

#[test]
fn create_item_applies_auto_tags_flagged_auto() {
    let mut d = db();
    let mut n = NewItem::new(ItemType::Credential, "My Bank");
    n.fields = vec![FieldInput::new("otp", "totp", "JBSWY3DPEHPK3PXP", true)];
    let id = d.create_item(&ctx("dev-a", 100), &n).unwrap();
    let tags = tags_of(&d, &id);
    assert!(tags.contains(&"#bank".to_string()), "{tags:?}");
    assert!(tags.contains(&"#2fa".to_string()), "{tags:?}");
    let snap = d.snapshot().unwrap();
    assert!(snap.item_tags.iter().all(|l| l.auto));
}

#[test]
fn update_reapplies_tagger_for_new_title() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "Misc", "fake");
    assert!(!tags_of(&d, &id).contains(&"#bank".to_string()));
    d.update_item(
        &ctx("dev-a", 200),
        &id,
        &ItemUpdate {
            title: Some("PayPal".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(tags_of(&d, &id).contains(&"#bank".to_string()));
}

#[test]
fn a_tag_the_user_removed_is_not_readded_by_the_tagger() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "My Bank", "fake");
    let bank = d
        .list_tags()
        .unwrap()
        .into_iter()
        .find(|t| t.name == "#bank")
        .unwrap();
    d.remove_tag(&ctx("dev-a", 200), &id, &bank.id).unwrap();
    assert!(!tags_of(&d, &id).contains(&"#bank".to_string()));

    d.update_item(
        &ctx("dev-a", 300),
        &id,
        &ItemUpdate {
            title: Some("My Bank (new)".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        !tags_of(&d, &id).contains(&"#bank".to_string()),
        "rejection respected"
    );
}

#[test]
fn explicitly_adding_a_removed_tag_revives_it_as_a_user_choice() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "My Bank", "fake");
    let bank = d
        .list_tags()
        .unwrap()
        .into_iter()
        .find(|t| t.name == "#bank")
        .unwrap();
    d.remove_tag(&ctx("dev-a", 200), &id, &bank.id).unwrap();
    d.add_tag(&ctx("dev-a", 300), &id, &bank.id).unwrap();
    assert!(tags_of(&d, &id).contains(&"#bank".to_string()));
    let snap = d.snapshot().unwrap();
    assert!(snap.item_tags.iter().all(|l| !l.auto));
}

#[test]
fn a_deleted_tag_is_not_recreated_by_the_tagger_for_other_items() {
    let mut d = db();
    let first = login(&mut d, "dev-a", 100, "My Bank", "fake");
    let bank = d
        .list_tags()
        .unwrap()
        .into_iter()
        .find(|t| t.name == "#bank")
        .unwrap();
    d.delete_tag(&ctx("dev-a", 200), &bank.id).unwrap();
    assert!(!tags_of(&d, &first).contains(&"#bank".to_string()));

    let second = login(&mut d, "dev-a", 300, "Other Bank", "fake");
    assert!(!tags_of(&d, &second).contains(&"#bank".to_string()));
    assert!(d.list_tags().unwrap().iter().all(|t| t.name != "#bank"));
}

#[test]
fn create_tag_returns_the_existing_live_tag_with_the_same_name() {
    let mut d = db();
    let a = d
        .create_tag(&ctx("dev-a", 100), "#work", "#111111")
        .unwrap();
    let b = d
        .create_tag(&ctx("dev-a", 200), "#work", "#999999")
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(d.list_tags().unwrap().len(), 1);
}

#[test]
fn update_tag_renames_and_recolors_and_items_follow() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "My Bank", "fake");
    let bank = d.list_tags().unwrap().into_iter().find(|t| t.name == "#bank").unwrap();
    let t = d
        .update_tag(&ctx("dev-a", 200), &bank.id, Some("#money"), Some("#123456"))
        .unwrap();
    assert_eq!((t.name.as_str(), t.color.as_str()), ("#money", "#123456"));
    assert!(t.updated_at > bank.updated_at);
    assert!(tags_of(&d, &id).contains(&"#money".to_string()));
    assert!(!tags_of(&d, &id).contains(&"#bank".to_string()));
    // Color-only update keeps the name.
    let t = d.update_tag(&ctx("dev-a", 300), &bank.id, None, Some("#abcdef")).unwrap();
    assert_eq!((t.name.as_str(), t.color.as_str()), ("#money", "#abcdef"));
}

#[test]
fn update_tag_rejects_empty_duplicate_and_missing() {
    let mut d = db();
    let a = d.create_tag(&ctx("dev-a", 100), "#a", "#111111").unwrap();
    let b = d.create_tag(&ctx("dev-a", 110), "#b", "#222222").unwrap();
    assert!(matches!(
        d.update_tag(&ctx("dev-a", 200), &a.id, Some("  "), None),
        Err(Error::InvalidInput)
    ));
    assert!(matches!(
        d.update_tag(&ctx("dev-a", 200), &a.id, Some("#b"), None),
        Err(Error::InvalidInput)
    ));
    assert!(matches!(
        d.update_tag(&ctx("dev-a", 200), "missing", Some("#x"), None),
        Err(Error::NotFound)
    ));
    // Renaming to its own name is fine; a deleted tag cannot be edited.
    d.update_tag(&ctx("dev-a", 210), &a.id, Some("#a"), None).unwrap();
    d.delete_tag(&ctx("dev-a", 220), &b.id).unwrap();
    assert!(matches!(
        d.update_tag(&ctx("dev-a", 230), &b.id, Some("#c"), None),
        Err(Error::NotFound)
    ));
}

// ---- usage counters ---------------------------------------------------------------------

#[test]
fn record_use_increments_counters_without_touching_updated_at() {
    let mut d = db();
    let id = login(&mut d, "dev-a", 100, "Mail", "fake");
    let before = d.get_item(&id).unwrap().summary;
    d.record_use(&ctx("dev-a", 500), &id).unwrap();
    d.record_use(&ctx("dev-a", 600), &id).unwrap();
    let after = d.get_item(&id).unwrap().summary;
    assert_eq!((after.use_count, after.last_used_at), (2, Some(600)));
    assert_eq!(after.updated_at, before.updated_at);
}

// ---- categories -------------------------------------------------------------------------

fn new_cat(name: &str) -> NewCategory {
    NewCategory {
        name: name.into(),
        color: "#101010".into(),
        icon: "folder".into(),
        icon_color: "#f0f0f0".into(),
        fields: vec![],
    }
}

#[test]
fn categories_keep_independent_icon_color_and_support_reordering() {
    let mut d = db();
    let a = d
        .create_category(&ctx("dev-a", 100), &new_cat("A"))
        .unwrap();
    let b = d
        .create_category(&ctx("dev-a", 101), &new_cat("B"))
        .unwrap();
    assert_eq!((a.sort_order, b.sort_order), (0, 1));
    assert_ne!(a.color, a.icon_color);

    d.reorder_categories(&ctx("dev-a", 200), &[b.id.clone(), a.id.clone()])
        .unwrap();
    let names: Vec<_> = d
        .list_categories()
        .unwrap()
        .into_iter()
        .map(|c| c.name)
        .collect();
    assert_eq!(names, ["B", "A"]);

    d.update_category(
        &ctx("dev-a", 300),
        &a.id,
        &CategoryUpdate {
            icon_color: Some("#abcdef".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let a2 = d
        .list_categories()
        .unwrap()
        .into_iter()
        .find(|c| c.id == a.id)
        .unwrap();
    assert_eq!(
        (a2.color.as_str(), a2.icon_color.as_str()),
        ("#101010", "#abcdef")
    );
}

#[test]
fn deleting_a_category_hides_it_from_items_and_rejects_new_assignments() {
    let mut d = db();
    let cat = d
        .create_category(&ctx("dev-a", 100), &new_cat("Work"))
        .unwrap();
    let mut n = NewItem::new(ItemType::Credential, "Intranet");
    n.category_id = Some(cat.id.clone());
    let id = d.create_item(&ctx("dev-a", 110), &n).unwrap();
    assert_eq!(
        d.get_item(&id).unwrap().summary.category_id,
        Some(cat.id.clone())
    );

    d.delete_category(&ctx("dev-a", 200), &cat.id).unwrap();
    assert_eq!(d.get_item(&id).unwrap().summary.category_id, None);
    assert!(d.list_categories().unwrap().is_empty());
    assert_eq!(d.create_item(&ctx("dev-a", 300), &n), Err(Error::NotFound));
}

// ---- notes ------------------------------------------------------------------------------

#[test]
fn code_blocks_get_a_detected_language_and_image_blocks_need_a_real_image() {
    let mut d = db();
    let mut n = NewItem::new(ItemType::Note, "Snippets");
    n.blocks = vec![BlockInput {
        id: None,
        kind: BlockKind::Code,
        language: None,
        content: "{\"a\": 1}".into(),
        image_id: None,
    }];
    let id = d.create_item(&ctx("dev-a", 100), &n).unwrap();
    assert_eq!(
        d.get_item(&id).unwrap().blocks[0].language.as_deref(),
        Some("json")
    );

    n.blocks = vec![BlockInput {
        id: None,
        kind: BlockKind::Image,
        language: None,
        content: String::new(),
        image_id: Some("missing".into()),
    }];
    assert_eq!(d.create_item(&ctx("dev-a", 200), &n), Err(Error::NotFound));
    let img = d
        .add_note_image(&ctx("dev-a", 210), "image/png", &[9, 9, 9])
        .unwrap();
    n.blocks[0].image_id = Some(img.clone());
    assert!(d.create_item(&ctx("dev-a", 220), &n).is_ok());
    assert_eq!(d.note_image(&img).unwrap().1.as_slice(), &[9, 9, 9]);
}

// ---- validation -------------------------------------------------------------------------

#[test]
fn invalid_input_is_rejected_without_side_effects() {
    let mut d = db();
    assert_eq!(
        d.create_item(&ctx("dev-a", 100), &NewItem::new(ItemType::Note, "  ")),
        Err(Error::InvalidInput)
    );
    assert_eq!(
        d.create_item(&ctx("", 100), &NewItem::new(ItemType::Note, "x")),
        Err(Error::InvalidInput)
    );
    assert_eq!(
        d.create_item(&ctx("dev-a", -1), &NewItem::new(ItemType::Note, "x")),
        Err(Error::InvalidInput)
    );
    let mut n = NewItem::new(ItemType::Note, "x");
    n.fields = vec![FieldInput::new("a", "text", "v", false).with_id("preset")];
    assert_eq!(
        d.create_item(&ctx("dev-a", 100), &n),
        Err(Error::InvalidInput)
    );
    assert!(d.list_items().unwrap().is_empty());
    // Nothing was written; only the default vault exists.
    let snap = d.snapshot().unwrap();
    assert_eq!(snap.vault_meta.len(), 1);
    let expected = vault_core::models::Snapshot {
        vault_meta: snap.vault_meta.clone(),
        ..Default::default()
    };
    assert_eq!(snap, expected);
}

#[test]
fn field_input_debug_never_prints_the_value() {
    let f = FieldInput::new("password", "password", "fake-do-not-print", true);
    assert!(!format!("{f:?}").contains("fake-do-not-print"));
}

// ---- preset categories and their editable field templates ---------------------------------

fn card(d: &Store) -> vault_core::models::Category {
    d.list_categories()
        .unwrap()
        .into_iter()
        .find(|c| c.preset.as_deref() == Some("card"))
        .unwrap()
}

#[test]
fn wifi_and_software_license_presets_are_seeded_with_their_templates() {
    let mut d = db();
    d.seed_default_categories(&ctx("dev-a", 100)).unwrap();
    let kinds = |preset: &str| -> Vec<(String, bool)> {
        let cat = d
            .list_categories()
            .unwrap()
            .into_iter()
            .find(|c| c.preset.as_deref() == Some(preset))
            .unwrap();
        d.list_category_fields(&cat.id)
            .unwrap()
            .into_iter()
            .map(|f| (f.kind, f.is_core))
            .collect()
    };
    let t = |k: &str, core: bool| (k.to_string(), core);
    // Network name and password are core: the QR export depends on them.
    assert_eq!(
        kinds("wifi"),
        [t("text", true), t("password", true), t("text", false)]
    );
    assert_eq!(
        kinds("software_license"),
        [
            t("text", false),
            t("key", false),
            t("text", false),
            t("date", false),
            t("date", false)
        ]
    );
    // Re-seeding adds nothing.
    let before = d.list_categories().unwrap().len();
    d.seed_default_categories(&ctx("dev-a", 200)).unwrap();
    assert_eq!(d.list_categories().unwrap().len(), before);
}

/// The category's template as inputs targeting the existing fields (an unchanged edit).
fn template(d: &Store, cat: &str) -> Vec<CategoryFieldInput> {
    d.list_category_fields(cat)
        .unwrap()
        .into_iter()
        .map(|f| CategoryFieldInput {
            id: Some(f.id),
            name: f.name,
            kind: f.kind,
            is_secret: f.is_secret,
        })
        .collect()
}

#[test]
fn seeding_creates_editable_preset_categories_once() {
    let mut d = db();
    d.seed_default_categories(&ctx("dev-a", 100)).unwrap();
    let n = d.list_categories().unwrap().len();
    assert!(n >= 7);
    d.seed_default_categories(&ctx("dev-b", 200)).unwrap();
    assert_eq!(d.list_categories().unwrap().len(), n);

    let c = card(&d);
    let fields = d.list_category_fields(&c.id).unwrap();
    let core: Vec<_> = fields.iter().filter(|f| f.is_core).map(|f| f.kind.as_str()).collect();
    assert_eq!(core, ["text", "card_number", "expiry", "cvv"]);

    // Fully editable like any category.
    d.update_category(
        &ctx("dev-a", 300),
        &c.id,
        &CategoryUpdate {
            name: Some("Cards".into()),
            icon: Some("star".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(card(&d).name, "Cards");

    // A deleted preset stays deleted.
    d.delete_category(&ctx("dev-a", 400), &c.id).unwrap();
    d.seed_default_categories(&ctx("dev-a", 500)).unwrap();
    assert!(d.list_categories().unwrap().iter().all(|x| x.id != c.id));
}

#[test]
fn core_inputs_cannot_be_deleted_but_extras_can_be_added_and_removed() {
    let mut d = db();
    d.seed_default_categories(&ctx("dev-a", 100)).unwrap();
    let c = card(&d);
    let base = template(&d, &c.id);

    // Omitting a core input fails and changes nothing.
    let mut without_core = base.clone();
    without_core.retain(|f| f.kind != "cvv");
    let r = d.update_category(
        &ctx("dev-a", 200),
        &c.id,
        &CategoryUpdate { fields: Some(without_core), ..Default::default() },
    );
    assert_eq!(r, Err(Error::InvalidInput));
    assert_eq!(d.list_category_fields(&c.id).unwrap().len(), base.len());

    // Core kind is fixed.
    let mut retyped = base.clone();
    for f in &mut retyped {
        if f.kind == "cvv" {
            f.kind = "text".into();
        }
    }
    let r = d.update_category(
        &ctx("dev-a", 210),
        &c.id,
        &CategoryUpdate { fields: Some(retyped), ..Default::default() },
    );
    assert_eq!(r, Err(Error::InvalidInput));

    // Extras: add one (with a chosen input type) ...
    let mut with_extra = base.clone();
    with_extra.push(CategoryFieldInput::new("Billing address", InputKind::SecureNote));
    d.update_category(
        &ctx("dev-a", 300),
        &c.id,
        &CategoryUpdate { fields: Some(with_extra), ..Default::default() },
    )
    .unwrap();
    let fields = d.list_category_fields(&c.id).unwrap();
    assert_eq!(fields.len(), base.len() + 1);
    let extra = fields.last().unwrap();
    assert_eq!((extra.kind.as_str(), extra.is_core, extra.is_secret), ("secure_note", false, true));

    // ... rename a core input (allowed) and remove the extra again.
    let mut edited = template(&d, &c.id);
    edited.pop();
    for f in &mut edited {
        if f.kind == "cvv" {
            f.name = "Security code".into();
        }
    }
    d.update_category(
        &ctx("dev-a", 400),
        &c.id,
        &CategoryUpdate { fields: Some(edited), ..Default::default() },
    )
    .unwrap();
    let fields = d.list_category_fields(&c.id).unwrap();
    assert_eq!(fields.len(), base.len());
    assert!(fields.iter().any(|f| f.name == "Security code" && f.is_core));
}

#[test]
fn custom_categories_take_extra_inputs_on_create_and_reject_bad_kinds() {
    let mut d = db();
    let mut new = new_cat("Wi-Fi");
    new.fields = vec![
        CategoryFieldInput::new("Network", InputKind::Text),
        CategoryFieldInput::new("Password", InputKind::Password),
    ];
    let c = d.create_category(&ctx("dev-a", 100), &new).unwrap();
    assert!(c.preset.is_none());
    let fields = d.list_category_fields(&c.id).unwrap();
    assert_eq!(fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(), ["Network", "Password"]);
    assert!(fields.iter().all(|f| !f.is_core));

    let mut bad = new_cat("Bad");
    bad.fields = vec![CategoryFieldInput {
        id: None,
        name: "x".into(),
        kind: "bogus".into(),
        is_secret: false,
    }];
    assert_eq!(d.create_category(&ctx("dev-a", 200), &bad).err(), Some(Error::InvalidInput));
    assert_eq!(d.list_categories().unwrap().len(), 1);

    // Extras are deletable on custom categories.
    d.update_category(
        &ctx("dev-a", 300),
        &c.id,
        &CategoryUpdate { fields: Some(vec![]), ..Default::default() },
    )
    .unwrap();
    assert!(d.list_category_fields(&c.id).unwrap().is_empty());
}

#[test]
fn category_templates_survive_snapshot_merge() {
    let mut a = db();
    a.seed_default_categories(&ctx("dev-a", 100)).unwrap();
    let c = card(&a);
    let mut inputs = template(&a, &c.id);
    inputs.push(CategoryFieldInput::new("Notes", InputKind::Text));
    a.update_category(
        &ctx("dev-a", 200),
        &c.id,
        &CategoryUpdate { fields: Some(inputs), ..Default::default() },
    )
    .unwrap();
    let mut b = db();
    b.seed_default_categories(&ctx("dev-b", 300)).unwrap();
    b.merge_remote(&a.snapshot().unwrap()).unwrap();
    // Same preset ids on both devices: no duplicates, and A's later edit wins over B's seed.
    assert_eq!(b.list_categories().unwrap().len(), a.list_categories().unwrap().len());
    assert_eq!(
        b.list_category_fields(&c.id).unwrap().len(),
        a.list_category_fields(&c.id).unwrap().len()
    );
}

// ---- vaults -------------------------------------------------------------------------------

fn vault_of(d: &Store, item: &str) -> String {
    d.get_item(item).unwrap().summary.vault_id
}

#[test]
fn a_new_store_has_the_default_vault_and_items_land_in_it() {
    let mut d = db();
    d.seed_default_categories(&ctx("dev-a", 50)).unwrap();
    let vaults = d.list_vaults().unwrap();
    assert_eq!(vaults.len(), 1);
    assert_eq!(vaults[0].id, "default");
    let id = login(&mut d, "dev-a", 100, "Mail", "fake");
    assert_eq!(vault_of(&d, &id), "default");
    // Seeding again never duplicates it.
    d.seed_default_categories(&ctx("dev-a", 60)).unwrap();
    assert_eq!(d.list_vaults().unwrap().len(), 1);
}

#[test]
fn vaults_are_created_updated_and_validated() {
    let mut d = db();
    let work = d.create_vault(&ctx("dev-a", 100), "  Work ", "#10B981", Some("W")).unwrap();
    assert_eq!((work.name.as_str(), work.badge.as_deref()), ("Work", Some("W")));
    // Default first, then by creation time.
    let ids: Vec<String> = d.list_vaults().unwrap().into_iter().map(|v| v.id).collect();
    assert_eq!(ids, vec!["default".to_string(), work.id.clone()]);

    for (name, color) in [("", "#000000"), ("work", "#000000"), ("X", "red"), ("Bad\nname", "#000000")] {
        assert_eq!(d.create_vault(&ctx("dev-a", 110), name, color, None).err(), Some(Error::InvalidInput), "{name}/{color}");
    }
    assert_eq!(d.create_vault(&ctx("dev-a", 110), "X", "#000000", Some("12345")).err(), Some(Error::InvalidInput));

    let u = d
        .update_vault(&ctx("dev-a", 200), &work.id, &VaultUpdate { name: Some("Clients".into()), badge: Some(None), ..Default::default() })
        .unwrap();
    assert_eq!((u.name.as_str(), u.badge), ("Clients", None));
    assert!(u.updated_at > work.updated_at);
    // No-op update keeps the timestamp; clash and unknown id are rejected.
    let same = d.update_vault(&ctx("dev-a", 300), &work.id, &VaultUpdate { name: Some("Clients".into()), ..Default::default() }).unwrap();
    assert_eq!(same.updated_at, u.updated_at);
    assert_eq!(
        d.update_vault(&ctx("dev-a", 400), &work.id, &VaultUpdate { name: Some("PERSONAL".into()), ..Default::default() }).err(),
        Some(Error::InvalidInput)
    );
    assert_eq!(d.update_vault(&ctx("dev-a", 400), "nope", &VaultUpdate::default()).err(), Some(Error::NotFound));
}

#[test]
fn items_are_created_in_and_moved_between_vaults() {
    let mut d = db();
    let work = d.create_vault(&ctx("dev-a", 100), "Work", "#10B981", None).unwrap();
    let mut new = NewItem::new(ItemType::Credential, "Jira");
    new.vault_id = Some(work.id.clone());
    let id = d.create_item(&ctx("dev-a", 200), &new).unwrap();
    assert_eq!(vault_of(&d, &id), work.id);

    let mut bad = NewItem::new(ItemType::Credential, "X");
    bad.vault_id = Some("nope".into());
    assert_eq!(d.create_item(&ctx("dev-a", 210), &bad).err(), Some(Error::NotFound));

    let before = d.get_item(&id).unwrap().summary.updated_at;
    d.update_item(&ctx("dev-a", 300), &id, &ItemUpdate { vault_id: Some("default".into()), ..Default::default() }).unwrap();
    assert_eq!(vault_of(&d, &id), "default");
    assert!(d.get_item(&id).unwrap().summary.updated_at > before);
    assert_eq!(
        d.update_item(&ctx("dev-a", 310), &id, &ItemUpdate { vault_id: Some("nope".into()), ..Default::default() }).err(),
        Some(Error::NotFound)
    );
    assert_eq!(vault_of(&d, &id), "default");
}

#[test]
fn deleting_a_vault_moves_its_items_including_trashed_ones() {
    let mut d = db();
    let work = d.create_vault(&ctx("dev-a", 100), "Work", "#10B981", None).unwrap();
    let mk = |d: &mut Store, t: &str, now: i64| {
        let mut n = NewItem::new(ItemType::Credential, t);
        n.vault_id = Some(work.id.clone());
        d.create_item(&ctx("dev-a", now), &n).unwrap()
    };
    let live = mk(&mut d, "Live", 200);
    let trashed = mk(&mut d, "Trashed", 210);
    d.trash_item(&ctx("dev-a", 220), &trashed).unwrap();

    assert_eq!(d.delete_vault(&ctx("dev-a", 300), &work.id, &work.id).err(), Some(Error::InvalidInput));
    assert_eq!(d.delete_vault(&ctx("dev-a", 300), &work.id, "nope").err(), Some(Error::NotFound));
    d.delete_vault(&ctx("dev-a", 300), &work.id, "default").unwrap();

    assert_eq!(d.list_vaults().unwrap().len(), 1);
    assert_eq!(vault_of(&d, &live), "default");
    let t = d.list_trashed_items().unwrap();
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].vault_id, "default");
    // A deleted vault cannot be edited, used or deleted again.
    assert_eq!(d.update_vault(&ctx("dev-a", 400), &work.id, &VaultUpdate::default()).err(), Some(Error::NotFound));
    assert_eq!(d.delete_vault(&ctx("dev-a", 400), &work.id, "default").err(), Some(Error::NotFound));
    let mut n = NewItem::new(ItemType::Credential, "X");
    n.vault_id = Some(work.id.clone());
    assert_eq!(d.create_item(&ctx("dev-a", 410), &n).err(), Some(Error::NotFound));
    // Its name is free again.
    d.create_vault(&ctx("dev-a", 500), "Work", "#10B981", None).unwrap();
}

#[test]
fn vaults_and_item_moves_merge_between_devices() {
    let mut a = db();
    let mut b = db();
    a.seed_default_categories(&ctx("dev-a", 10)).unwrap();
    b.seed_default_categories(&ctx("dev-b", 10)).unwrap();
    let work = a.create_vault(&ctx("dev-a", 100), "Work", "#10B981", None).unwrap();
    let id = login(&mut a, "dev-a", 110, "Mail", "fake");
    a.update_item(&ctx("dev-a", 120), &id, &ItemUpdate { vault_id: Some(work.id.clone()), ..Default::default() }).unwrap();

    b.merge_remote(&a.snapshot().unwrap()).unwrap();
    assert_eq!(b.list_vaults().unwrap().len(), 2);
    assert_eq!(vault_of(&b, &id), work.id);
    // Both devices created the default vault independently: still exactly one.
    assert_eq!(b.list_vaults().unwrap().iter().filter(|v| v.id == "default").count(), 1);

    // B deletes the vault; A keeps working in it concurrently. Nothing is orphaned after merging.
    b.delete_vault(&ctx("dev-b", 200), &work.id, "default").unwrap();
    let mut n = NewItem::new(ItemType::Credential, "Late");
    n.vault_id = Some(work.id.clone());
    let late = a.create_item(&ctx("dev-a", 210), &n).unwrap();
    a.merge_remote(&b.snapshot().unwrap()).unwrap();
    b.merge_remote(&a.snapshot().unwrap()).unwrap();
    for s in [a.snapshot().unwrap(), b.snapshot().unwrap()] {
        assert!(s.items.iter().filter(|i| i.deleted_at.is_none()).all(|i| i.vault_id == "default"), "{:?}", s.items.iter().map(|i| &i.vault_id).collect::<Vec<_>>());
    }
    assert_eq!(vault_of(&a, &late), "default");
    assert_eq!(vault_of(&b, &late), "default");
    assert_eq!(a.list_vaults().unwrap().len(), 1);
    assert_eq!(b.list_vaults().unwrap().len(), 1);
}
