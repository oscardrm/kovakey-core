//! SQLCipher-backed storage: raw-key unlock, explicit cipher settings, forward-only
//! numbered migrations tracked with `PRAGMA user_version`.
//!
//! * [`Database::load_snapshot`] / [`Database::save_snapshot`] / [`Database::merge_remote`]
//!   convert between the database and the merge [`crate::models::Snapshot`] (ADR 0001).
//! * The CRUD layer (items, fields, tags, categories, notes) lives in `store`.

mod snapshot;
mod store;

pub use crate::ops::{
    BlockInput, CategoryUpdate, FieldInput, FieldView, ItemDetail, ItemSummary, ItemUpdate,
    NewCategory, NewItem, VaultStore, WriteCtx,
};

use std::path::Path;

use rusqlite::Connection;
use zeroize::Zeroizing;

use crate::crypto::SecretKey;
use crate::error::{Error, Result};

/// Ordered, forward-only migrations. Index + 1 == resulting `user_version`.
const MIGRATIONS: &[&str] = &[
    include_str!("migrations/001_initial.sql"),
    include_str!("migrations/002_sync_columns.sql"),
];

/// Latest schema version known to this build.
pub const LATEST_VERSION: u32 = MIGRATIONS.len() as u32;

/// An open, unlocked vault database. Dropping it closes the connection (lock).
pub struct Database {
    conn: Connection,
}

fn db_err(_: rusqlite::Error) -> Error {
    Error::Database
}

impl Database {
    /// Open (or create) the encrypted database at `path` using the raw `key`.
    /// A wrong key or a non-SQLCipher file yields [`Error::Decryption`].
    pub fn open(path: &Path, key: &SecretKey) -> Result<Self> {
        Self::init(Connection::open(path).map_err(db_err)?, key)
    }

    /// In-memory encrypted database (tests / transient merges).
    pub fn open_in_memory(key: &SecretKey) -> Result<Self> {
        Self::init(Connection::open_in_memory().map_err(db_err)?, key)
    }

    fn init(conn: Connection, key: &SecretKey) -> Result<Self> {
        let mut db = Self::init_unmigrated(conn, key)?;
        db.migrate_to(LATEST_VERSION)?;
        Ok(db)
    }

    /// Unlock and verify the key without migrating.
    fn init_unmigrated(conn: Connection, key: &SecretKey) -> Result<Self> {
        let hex = Zeroizing::new(data_encoding::HEXLOWER.encode(key.expose()));
        // Raw key syntax: the 256-bit key is used directly, bypassing SQLCipher's own KDF.
        let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", hex.as_str()));
        conn.execute_batch(&pragma).map_err(|_| Error::Database)?;
        conn.execute_batch(
            "PRAGMA cipher_page_size = 4096;
             PRAGMA cipher_hmac_algorithm = HMAC_SHA512;
             PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;
             PRAGMA foreign_keys = ON;",
        )
        .map_err(db_err)?;
        // First real read: fails if the key is wrong or the file is not a SQLCipher DB.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        })
        .map_err(|_| Error::Decryption)?;
        Ok(Self { conn })
    }

    /// Current `PRAGMA user_version`.
    pub fn schema_version(&self) -> Result<u32> {
        self.conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(db_err)
    }

    /// Apply pending migrations up to `target`, each in its own transaction. Refuses
    /// newer-than-known files. Production code always migrates to [`LATEST_VERSION`].
    fn migrate_to(&mut self, target: u32) -> Result<()> {
        let current = self.schema_version()?;
        if current > LATEST_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        for (i, sql) in MIGRATIONS
            .iter()
            .enumerate()
            .take(target as usize)
            .skip(current as usize)
        {
            let tx = self.conn.transaction().map_err(db_err)?;
            tx.execute_batch(sql).map_err(db_err)?;
            tx.pragma_update(None, "user_version", i as u32 + 1)
                .map_err(db_err)?;
            tx.commit().map_err(db_err)?;
        }
        Ok(())
    }

    /// Borrow the connection (crate-internal).
    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Mutable connection, for transactions (crate-internal).
    pub(crate) fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> SecretKey {
        SecretKey::from_bytes([b; 32])
    }

    /// Create a database file frozen at schema `version` (simulates an older app build).
    fn open_at_version(path: &Path, key: &SecretKey, version: u32) -> Database {
        let mut db = Database::init_unmigrated(Connection::open(path).unwrap(), key).unwrap();
        db.migrate_to(version).unwrap();
        db
    }

    #[test]
    fn migrating_from_every_prior_version_reaches_latest_and_preserves_data() {
        for from in 1..LATEST_VERSION {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("v.db");
            {
                let db = open_at_version(&path, &key(1), from);
                assert_eq!(db.schema_version().unwrap(), from);
                // v1-shaped rows (no updated_by / item_fields.deleted_at columns).
                db.conn()
                    .execute_batch(
                        "INSERT INTO categories(id,name,color,icon,icon_color,created_at,updated_at)
                           VALUES('c','Bank','#111','b','#222',1,1);
                         INSERT INTO tags(id,name,color,created_at,updated_at) VALUES('t','#bank','#fff',1,1);
                         INSERT INTO items(id,category_id,item_type,title,created_at,updated_at,updated_by)
                           VALUES('i','c','credential','Acme',1,5,'d1');
                         INSERT INTO item_fields(id,item_id,name,kind,value,is_secret,updated_at)
                           VALUES('f','i','password','password','fake-pw',1,5);
                         INSERT INTO item_tags(item_id,tag_id,auto,updated_at) VALUES('i','t',1,5);",
                    )
                    .unwrap();
            }
            let db = Database::open(&path, &key(1)).unwrap();
            assert_eq!(db.schema_version().unwrap(), LATEST_VERSION);
            let (name, by): (String, String) = db
                .conn()
                .query_row(
                    "SELECT name, updated_by FROM categories WHERE id='c'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!((name.as_str(), by.as_str()), ("Bank", ""));
            let (val, del): (String, Option<i64>) = db
                .conn()
                .query_row(
                    "SELECT value, deleted_at FROM item_fields WHERE id='f'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!((val.as_str(), del), ("fake-pw", None));
            // The migrated database round-trips through a snapshot.
            let snap = db.load_snapshot().unwrap();
            assert_eq!(snap.items.len(), 1);
            assert_eq!(snap.item_fields.len(), 1);
            assert_eq!(snap.item_tags.len(), 1);
        }
    }

    #[test]
    fn v2_allows_duplicate_live_tag_names_created_on_different_devices() {
        let db = Database::open_in_memory(&key(1)).unwrap();
        db.conn()
            .execute_batch(
                "INSERT INTO tags(id,name,color,created_at,updated_at,updated_by) VALUES('a','#x','#fff',1,1,'d1');
                 INSERT INTO tags(id,name,color,created_at,updated_at,updated_by) VALUES('b','#x','#fff',1,1,'d2');",
            )
            .unwrap();
    }

    #[test]
    fn open_creates_schema_at_latest_version() {
        let db = Database::open_in_memory(&key(1)).unwrap();
        assert_eq!(db.schema_version().unwrap(), LATEST_VERSION);
        let n: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='categories'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn reopen_is_idempotent_and_preserves_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");
        {
            let db = Database::open(&path, &key(1)).unwrap();
            db.conn()
                .execute(
                    "INSERT INTO tags(id,name,color,created_at,updated_at) VALUES('t','dev','#fff',1,1)",
                    [],
                )
                .unwrap();
        }
        let db = Database::open(&path, &key(1)).unwrap();
        let name: String = db
            .conn()
            .query_row("SELECT name FROM tags WHERE id='t'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(name, "dev");
        assert_eq!(db.schema_version().unwrap(), LATEST_VERSION);
    }

    #[test]
    fn wrong_key_returns_decryption_error_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");
        drop(Database::open(&path, &key(1)).unwrap());
        assert!(matches!(
            Database::open(&path, &key(2)),
            Err(Error::Decryption)
        ));
    }

    #[test]
    fn file_on_disk_is_not_plaintext_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");
        drop(Database::open(&path, &key(1)).unwrap());
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.starts_with(b"SQLite format 3"));
        assert!(!raw.windows(10).any(|w| w == b"categories"));
    }

    #[test]
    fn cipher_settings_are_applied() {
        let db = Database::open_in_memory(&key(1)).unwrap();
        // SQLCipher reports these pragmas as text, so read them as strings.
        let pragma = |name: &str| -> String {
            db.conn()
                .query_row(&format!("PRAGMA {name}"), [], |r| r.get::<_, String>(0))
                .unwrap()
        };
        assert_eq!(pragma("cipher_page_size"), "4096");
        assert_eq!(pragma("cipher_hmac_algorithm"), "HMAC_SHA512");
        assert_eq!(pragma("cipher_kdf_algorithm"), "PBKDF2_HMAC_SHA512");
    }

    #[test]
    fn newer_schema_version_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");
        {
            let db = Database::open(&path, &key(1)).unwrap();
            db.conn()
                .pragma_update(None, "user_version", LATEST_VERSION + 1)
                .unwrap();
        }
        assert!(matches!(
            Database::open(&path, &key(1)),
            Err(Error::UnsupportedVersion)
        ));
    }

    #[test]
    fn foreign_keys_and_item_type_check_are_enforced() {
        let db = Database::open_in_memory(&key(1)).unwrap();
        let bad_type = db.conn().execute(
            "INSERT INTO items(id,item_type,title,created_at,updated_at,updated_by) VALUES('i','bogus','t',1,1,'d')",
            [],
        );
        assert!(bad_type.is_err());
        let bad_fk = db.conn().execute(
            "INSERT INTO item_fields(id,item_id,name,kind,value,updated_at) VALUES('f','nope','n','text','v',1)",
            [],
        );
        assert!(bad_fk.is_err());
    }
}
