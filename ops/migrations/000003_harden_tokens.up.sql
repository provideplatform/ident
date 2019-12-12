ALTER TABLE ONLY tokens ADD COLUMN hash char(64);
UPDATE tokens SET hash = (SELECT encode(digest(t.token, 'sha256'), 'hex') from tokens t WHERE tokens.id = t.id);

ALTER TABLE ONLY tokens DROP COLUMN expires_at;
ALTER TABLE ONLY tokens ALTER COLUMN token type bytea using (token::bytea);
