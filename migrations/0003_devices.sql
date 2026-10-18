-- Devices allowed to reach the NAS when mTLS is on, each known by the certificates it was given.
CREATE TABLE devices (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 60),
    icon       TEXT    NOT NULL CHECK (icon IN ('tv', 'desktop', 'laptop', 'phone', 'projector')),
    created_at INTEGER NOT NULL
) STRICT;

-- Certificates issued to devices.
CREATE TABLE device_certificates (
    fingerprint  TEXT    NOT NULL PRIMARY KEY CHECK (length(fingerprint) = 64),
    device_id    INTEGER NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    state        TEXT    NOT NULL CHECK (state IN ('pending', 'active', 'revoked')),
    issued_at    INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    activated_at INTEGER,
    seen_at      INTEGER,
    revoked_at   INTEGER
) STRICT;

CREATE INDEX device_certificates_by_device ON device_certificates (device_id);

-- Mutual TLS (mTLS) configuration for the NAS gateway.
CREATE TABLE mtls (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1))
) STRICT;

INSERT INTO mtls (id, enabled) VALUES (1, 0);
