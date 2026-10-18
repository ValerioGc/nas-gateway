-- Add mobile clients support
ALTER TABLE devices ADD COLUMN mobile INTEGER NOT NULL DEFAULT 0 CHECK (mobile IN (0, 1));
