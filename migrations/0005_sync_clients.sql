-- The computers of the sync client: the identity of their sync engine, given when they pair.
ALTER TABLE devices ADD COLUMN sync_id TEXT CHECK (sync_id IS NULL OR length(sync_id) = 63);

CREATE UNIQUE INDEX devices_by_sync_id ON devices (sync_id) WHERE sync_id IS NOT NULL;

-- Engines of revoked computers the sync application has not dropped yet: retried until it does.
CREATE TABLE sync_revocations (
    sync_id TEXT    NOT NULL PRIMARY KEY CHECK (length(sync_id) = 63),
    since   INTEGER NOT NULL
) STRICT;
