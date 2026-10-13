-- Lock of an address after repeated refused sign-ins, chosen in the access settings.
CREATE TABLE sign_in_policy (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    enabled      INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    attempts     INTEGER NOT NULL CHECK (attempts BETWEEN 1 AND 20),
    lock_minutes INTEGER NOT NULL CHECK (lock_minutes BETWEEN 1 AND 1440)
) STRICT;

INSERT INTO sign_in_policy (id, enabled, attempts, lock_minutes) VALUES (1, 1, 5, 1);
