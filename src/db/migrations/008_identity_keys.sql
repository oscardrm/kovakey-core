-- Schema v8: identity keys for shared member vaults. The X25519 private key lives inside the
-- SQLCipher file; records are immutable except for the tombstone, which blanks `private_key`.

CREATE TABLE identity_keys (
    id           TEXT PRIMARY KEY,
    private_key  BLOB NOT NULL,
    public_key   BLOB NOT NULL,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    updated_by   TEXT NOT NULL DEFAULT '',
    deleted_at   INTEGER
) STRICT;
