-- Schema v7: passkeys (ADR 0020). ES256 private keys live inside the SQLCipher file; metadata
-- merges last-writer-wins like any child record and `private_key` is blanked when tombstoned.

CREATE TABLE passkeys (
    id             TEXT PRIMARY KEY,
    item_id        TEXT NOT NULL REFERENCES items(id),
    credential_id  BLOB NOT NULL,
    rp_id          TEXT NOT NULL,
    user_name      TEXT NOT NULL,
    user_handle    BLOB NOT NULL,
    private_key    BLOB NOT NULL,
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL,
    updated_by     TEXT NOT NULL DEFAULT '',
    deleted_at     INTEGER
) STRICT;
CREATE INDEX idx_passkeys_item ON passkeys(item_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_passkeys_rp ON passkeys(rp_id) WHERE deleted_at IS NULL;
