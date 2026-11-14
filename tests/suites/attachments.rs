use super::common::{ctx, login};
use vault_core::models::{MAX_ATTACHMENT_BYTES, MAX_VAULT_ATTACHMENT_BYTES};
use vault_core::ops::{check_attachment_size, sanitize_file_name};
use vault_core::{db::VaultStore, Error};

// Included twice by `attachments.rs`: once per `VaultStore` backend. `Store` and `db()` come from there.

fn pdf(d: &mut Store, item: &str, now: i64, data: &[u8]) -> String {
    d.add_attachment(&ctx("dev-a", now), item, "scan.pdf", "application/pdf", data)
        .unwrap()
}

#[test]
fn add_list_read_round_trip() {
    let mut d = db();
    let item = login(&mut d, "dev-a", 100, "Mail", "fake-secret-1");
    let a = pdf(&mut d, &item, 200, b"%PDF-fake-1");
    let b = pdf(&mut d, &item, 300, b"%PDF-fake-2");
    let list = d.list_attachments(&item).unwrap();
    assert_eq!(list.iter().map(|i| i.id.clone()).collect::<Vec<_>>(), [a.clone(), b]);
    assert_eq!(list[0].file_name, "scan.pdf");
    assert_eq!(list[0].mime_type, "application/pdf");
    assert_eq!(list[0].size, 11);
    let (info, bytes) = d.read_attachment(&a).unwrap();
    assert_eq!(info, list[0]);
    assert_eq!(bytes.as_slice(), b"%PDF-fake-1");
}

#[test]
fn attachments_are_scoped_to_their_item() {
    let mut d = db();
    let one = login(&mut d, "dev-a", 100, "One", "fake-1");
    let two = login(&mut d, "dev-a", 110, "Two", "fake-2");
    pdf(&mut d, &one, 200, b"x");
    assert!(d.list_attachments(&two).unwrap().is_empty());
    assert_eq!(d.list_attachments("nope"), Err(Error::NotFound));
}

#[test]
fn file_names_are_sanitized() {
    assert_eq!(sanitize_file_name("../../etc/passwd").unwrap(), "passwd");
    assert_eq!(sanitize_file_name("C:\\Users\\me\\tax.pdf").unwrap(), "tax.pdf");
    assert_eq!(sanitize_file_name("  ..hidden.txt \t").unwrap(), "hidden.txt");
    assert_eq!(sanitize_file_name("a\u{0}b\nc.txt").unwrap(), "abc.txt");
    // A right-to-left override can disguise the real extension.
    assert_eq!(sanitize_file_name("invoice\u{202e}fdp.exe").unwrap(), "invoicefdp.exe");
    for bad in ["", "   ", "..", "...", "dir/", "\u{202e}"] {
        assert_eq!(sanitize_file_name(bad), Err(Error::InvalidInput), "{bad:?}");
    }
    let long = "é".repeat(400);
    let out = sanitize_file_name(&long).unwrap();
    assert!(out.len() <= 255 && out.chars().all(|c| c == 'é'));
}

#[test]
fn stored_name_is_the_sanitized_one() {
    let mut d = db();
    let item = login(&mut d, "dev-a", 100, "Mail", "fake-1");
    let id = d
        .add_attachment(&ctx("dev-a", 200), &item, "../../x/evil.sh", "text/plain", b"echo")
        .unwrap();
    assert_eq!(d.read_attachment(&id).unwrap().0.file_name, "evil.sh");
}

#[test]
fn invalid_inputs_are_rejected_and_change_nothing() {
    let mut d = db();
    let item = login(&mut d, "dev-a", 100, "Mail", "fake-1");
    let before = d.snapshot().unwrap();
    let c = ctx("dev-a", 200);
    assert_eq!(d.add_attachment(&c, &item, "a.bin", "application/octet-stream", b""), Err(Error::InvalidInput));
    let too_big = vec![0u8; MAX_ATTACHMENT_BYTES + 1];
    assert_eq!(d.add_attachment(&c, &item, "a.bin", "application/octet-stream", &too_big), Err(Error::InvalidInput));
    assert_eq!(d.add_attachment(&c, &item, "..", "text/plain", b"x"), Err(Error::InvalidInput));
    for mime in ["", "text", "text/", "/plain", "a/b/c", "text/pla in", "text/plain\n"] {
        assert_eq!(d.add_attachment(&c, &item, "a.txt", mime, b"x"), Err(Error::InvalidInput), "{mime:?}");
    }
    assert_eq!(d.add_attachment(&c, "ghost", "a.txt", "text/plain", b"x"), Err(Error::NotFound));
    assert_eq!(d.snapshot().unwrap(), before);
}

#[test]
fn a_file_at_the_limit_is_accepted() {
    let mut d = db();
    let item = login(&mut d, "dev-a", 100, "Mail", "fake-1");
    let data = vec![7u8; MAX_ATTACHMENT_BYTES];
    let id = d.add_attachment(&ctx("dev-a", 200), &item, "big.bin", "application/octet-stream", &data).unwrap();
    assert_eq!(d.read_attachment(&id).unwrap().0.size, MAX_ATTACHMENT_BYTES as u64);
}

#[test]
fn per_vault_limit_counts_live_bytes() {
    assert_eq!(check_attachment_size(1, MAX_VAULT_ATTACHMENT_BYTES - 1), Ok(()));
    assert_eq!(check_attachment_size(1, MAX_VAULT_ATTACHMENT_BYTES), Err(Error::InvalidInput));
    assert_eq!(check_attachment_size(10, MAX_VAULT_ATTACHMENT_BYTES - 5), Err(Error::InvalidInput));
    assert_eq!(check_attachment_size(0, 0), Err(Error::InvalidInput));
    assert_eq!(check_attachment_size(MAX_ATTACHMENT_BYTES + 1, 0), Err(Error::InvalidInput));
}

#[test]
fn rename_updates_name_and_bumps_time_monotonically() {
    let mut d = db();
    let item = login(&mut d, "dev-a", 100, "Mail", "fake-1");
    let id = pdf(&mut d, &item, 500, b"x");
    // Clock went backwards: the timestamp must still increase.
    d.rename_attachment(&ctx("dev-a", 10), &id, "../renamed.pdf").unwrap();
    let info = d.read_attachment(&id).unwrap().0;
    assert_eq!(info.file_name, "renamed.pdf");
    assert!(info.updated_at > 500);
    assert_eq!(d.rename_attachment(&ctx("dev-a", 900), &id, ".."), Err(Error::InvalidInput));
    assert_eq!(d.rename_attachment(&ctx("dev-a", 900), "ghost", "a"), Err(Error::NotFound));
}

#[test]
fn delete_tombstones_and_scrubs_the_bytes() {
    let mut d = db();
    let item = login(&mut d, "dev-a", 100, "Mail", "fake-1");
    let id = pdf(&mut d, &item, 200, b"top-secret-scan");
    d.delete_attachment(&ctx("dev-a", 300), &id).unwrap();
    assert!(d.list_attachments(&item).unwrap().is_empty());
    assert_eq!(d.read_attachment(&id).err(), Some(Error::NotFound));
    assert_eq!(d.delete_attachment(&ctx("dev-a", 400), &id), Err(Error::NotFound));
    let snap = d.snapshot().unwrap();
    let row = snap.attachments.iter().find(|a| a.id == id).unwrap();
    assert!(row.deleted_at.is_some());
    assert!(row.data.is_empty() && row.size == 0);
}

#[test]
fn deleting_an_item_tombstones_and_scrubs_its_attachments() {
    let mut d = db();
    let item = login(&mut d, "dev-a", 100, "Mail", "fake-1");
    let keep = login(&mut d, "dev-a", 110, "Other", "fake-2");
    let a = pdf(&mut d, &item, 200, b"one");
    let b = pdf(&mut d, &keep, 210, b"two");
    d.delete_item(&ctx("dev-a", 300), &item).unwrap();
    assert_eq!(d.read_attachment(&a).err(), Some(Error::NotFound));
    assert_eq!(d.list_attachments(&item).err(), Some(Error::NotFound));
    let snap = d.snapshot().unwrap();
    let row = snap.attachments.iter().find(|x| x.id == a).unwrap();
    assert!(row.deleted_at.is_some() && row.data.is_empty());
    assert_eq!(d.read_attachment(&b).unwrap().1.as_slice(), b"two");
}

#[test]
fn a_trashed_item_keeps_its_attachments_until_purged() {
    let mut d = db();
    let item = login(&mut d, "dev-a", 100, "Mail", "fake-1");
    let id = pdf(&mut d, &item, 200, b"keep-me");
    d.trash_item(&ctx("dev-a", 300), &item).unwrap();
    d.restore_item(&ctx("dev-a", 400), &item).unwrap();
    assert_eq!(d.read_attachment(&id).unwrap().1.as_slice(), b"keep-me");
}

#[test]
fn snapshot_derives_hash_and_size_and_debug_hides_content() {
    let mut d = db();
    let item = login(&mut d, "dev-a", 100, "Mail", "fake-1");
    let id = d
        .add_attachment(&ctx("dev-a", 200), &item, "private-name.pdf", "application/pdf", b"abc")
        .unwrap();
    let snap = d.snapshot().unwrap();
    let row = snap.attachments.iter().find(|a| a.id == id).unwrap();
    assert_eq!(row.size, 3);
    assert_eq!(row.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    let dbg = format!("{row:?}");
    assert!(!dbg.contains("private-name") && !dbg.contains("abc"));
}

#[test]
fn merge_carries_attachments_and_lww_resolves_rename_vs_delete() {
    let mut a = db();
    let mut b = db();
    let item = login(&mut a, "dev-a", 100, "Mail", "fake-1");
    b.merge_remote(&a.snapshot().unwrap()).unwrap();
    let id = pdf(&mut a, &item, 200, b"payload");
    b.merge_remote(&a.snapshot().unwrap()).unwrap();
    assert_eq!(b.read_attachment(&id).unwrap().1.as_slice(), b"payload");

    // Concurrent: A renames at 300, B deletes at 400. The later write (delete) wins everywhere.
    a.rename_attachment(&ctx("dev-a", 300), &id, "renamed.pdf").unwrap();
    b.delete_attachment(&ctx("dev-b", 400), &id).unwrap();
    let (sa, sb) = (a.snapshot().unwrap(), b.snapshot().unwrap());
    a.merge_remote(&sb).unwrap();
    b.merge_remote(&sa).unwrap();
    for d in [&a, &b] {
        assert_eq!(d.read_attachment(&id).err(), Some(Error::NotFound));
        let snap = d.snapshot().unwrap();
        let row = snap.attachments.iter().find(|x| x.id == id).unwrap();
        assert!(row.deleted_at.is_some() && row.data.is_empty());
    }
    assert_eq!(a.snapshot().unwrap().attachments, b.snapshot().unwrap().attachments);
}

#[test]
fn merge_rejects_an_attachment_of_an_unknown_item() {
    let mut a = db();
    let item = login(&mut a, "dev-a", 100, "Mail", "fake-1");
    pdf(&mut a, &item, 200, b"x");
    let mut snap = a.snapshot().unwrap();
    snap.attachments[0].item_id = "ghost".into();
    let mut b = db();
    // The SQL backend reports the foreign-key violation, the portable one `Corrupted`; both reject
    // the whole merge and leave the store untouched.
    assert!(b.merge_remote(&snap).is_err());
    assert!(b.snapshot().unwrap().attachments.is_empty());
}
