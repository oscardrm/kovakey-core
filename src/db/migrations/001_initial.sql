-- Schema v1. Timestamps: INTEGER, Unix epoch milliseconds, UTC.
-- Ids: TEXT UUIDv7 (merge-safe across devices). Deletes are tombstones (deleted_at).

CREATE TABLE vault_meta (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    color       TEXT NOT NULL DEFAULT '#3B82F6',
    badge       TEXT,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
) STRICT;

CREATE TABLE categories (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    color       TEXT NOT NULL,
    icon        TEXT NOT NULL,
    icon_color  TEXT NOT NULL,           -- independent from `color`
    sort_order  INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    deleted_at  INTEGER
) STRICT;

CREATE TABLE items (
    id            TEXT PRIMARY KEY,
    category_id   TEXT REFERENCES categories(id),
    item_type     TEXT NOT NULL CHECK (item_type IN
                    ('credential','card','identity','travel','database','dev_secret','note')),
    title         TEXT NOT NULL,
    url           TEXT,
    color         TEXT,
    favorite      INTEGER NOT NULL DEFAULT 0 CHECK (favorite IN (0,1)),
    use_count     INTEGER NOT NULL DEFAULT 0,
    last_used_at  INTEGER,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    updated_by    TEXT NOT NULL,         -- device id, deterministic merge tie-break
    deleted_at    INTEGER
) STRICT;
CREATE INDEX idx_items_category ON items(category_id);
CREATE INDEX idx_items_updated  ON items(updated_at);

-- Typed fields (username, password, totp secret, host, port, card number, ...).
CREATE TABLE item_fields (
    id          TEXT PRIMARY KEY,
    item_id     TEXT NOT NULL REFERENCES items(id),
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL,           -- 'text','password','totp','url','hash','key','env',...
    value       TEXT NOT NULL,
    is_secret   INTEGER NOT NULL DEFAULT 0 CHECK (is_secret IN (0,1)),
    sort_order  INTEGER NOT NULL DEFAULT 0,
    updated_at  INTEGER NOT NULL
) STRICT;
CREATE INDEX idx_fields_item ON item_fields(item_id);

-- Append-only; merge unions by id, never drops entries.
CREATE TABLE password_history (
    id          TEXT PRIMARY KEY,
    item_id     TEXT NOT NULL REFERENCES items(id),
    field_id    TEXT,
    password    TEXT NOT NULL,
    changed_at  INTEGER NOT NULL
) STRICT;
CREATE INDEX idx_history_item ON password_history(item_id, changed_at);

CREATE TABLE tags (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    color       TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    deleted_at  INTEGER
) STRICT;
CREATE UNIQUE INDEX idx_tags_name ON tags(name) WHERE deleted_at IS NULL;

CREATE TABLE item_tags (
    item_id     TEXT NOT NULL REFERENCES items(id),
    tag_id      TEXT NOT NULL REFERENCES tags(id),
    auto        INTEGER NOT NULL DEFAULT 0 CHECK (auto IN (0,1)),  -- 1 = suggested by auto-tagger
    updated_at  INTEGER NOT NULL,
    deleted_at  INTEGER,
    PRIMARY KEY (item_id, tag_id)
) STRICT;

-- Rich notes: an ordered list of blocks per note item.
CREATE TABLE note_blocks (
    id          TEXT PRIMARY KEY,
    item_id     TEXT NOT NULL REFERENCES items(id),
    position    INTEGER NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('rich_text','code','table','image')),
    language    TEXT,                    -- code blocks: detected/selected language
    content     TEXT NOT NULL DEFAULT '',-- rich text (serialized), code, or table JSON
    image_id    TEXT REFERENCES note_images(id),
    updated_at  INTEGER NOT NULL,
    deleted_at  INTEGER
) STRICT;
CREATE INDEX idx_blocks_item ON note_blocks(item_id, position);

CREATE TABLE note_images (
    id          TEXT PRIMARY KEY,
    mime_type   TEXT NOT NULL,
    data        BLOB NOT NULL,           -- stored inside the encrypted database
    created_at  INTEGER NOT NULL
) STRICT;
