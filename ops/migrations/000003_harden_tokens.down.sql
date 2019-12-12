ALTER TABLE ONLY tokens ADD COLUMN expires_at timestamp with time zone;
ALTER TABLE ONLY tokens DROP COLUMN hash;
ALTER TABLE ONLY tokens ALTER COLUMN token type text;
