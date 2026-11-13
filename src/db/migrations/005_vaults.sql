-- Schema v5: vaults as sections of one account (PRD §3). Items belong to a vault; all vaults share
-- the account password and data key. Existing items land in the fixed `default` vault, which is
-- created here with a fixed id so devices that migrate independently converge on the same record
-- (its timestamps are 0, so any later rename wins the merge).

ALTER TABLE vault_meta ADD COLUMN deleted_at INTEGER;
ALTER TABLE items ADD COLUMN vault_id TEXT NOT NULL DEFAULT 'default';
CREATE INDEX idx_items_vault ON items(vault_id);

INSERT OR IGNORE INTO vault_meta(id,name,color,badge,created_at,updated_at,updated_by)
VALUES('default','Personal','#2563EB',NULL,0,0,'');
