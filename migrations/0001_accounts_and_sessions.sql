-- Accounts and sessions for the NAS gateway.
CREATE TABLE accounts (
    username      TEXT    NOT NULL PRIMARY KEY,
    password_hash TEXT    NOT NULL,
    created_at    INTEGER NOT NULL,
    email         TEXT,
    recovery      INTEGER NOT NULL DEFAULT 0 CHECK (recovery IN (0, 1))
) STRICT;

-- Open sessions, stored as the SHA-256 of the opaque token kept in the cookie.
CREATE TABLE sessions (
    token_hash TEXT    NOT NULL PRIMARY KEY,
    username   TEXT    NOT NULL REFERENCES accounts (username) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    seen_at    INTEGER NOT NULL
) STRICT;
