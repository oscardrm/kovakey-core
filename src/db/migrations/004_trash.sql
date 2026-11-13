-- Schema v4: Trash (PRD 9.3). A trashed item keeps its content and is hidden from the lists until it
-- is restored or purged (purging is the existing tombstone: deleted_at set, content wiped).

ALTER TABLE items ADD COLUMN trashed_at INTEGER;
