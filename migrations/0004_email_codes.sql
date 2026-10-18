-- Email verification and password reset codes for accounts.
CREATE TABLE email_codes (
    purpose    TEXT    NOT NULL CHECK (purpose IN ('verify', 'reset')),
    username   TEXT    NOT NULL REFERENCES accounts (username) ON DELETE CASCADE,
    email      TEXT    NOT NULL,
    code_hash  TEXT    NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (purpose, username)
) STRICT;
