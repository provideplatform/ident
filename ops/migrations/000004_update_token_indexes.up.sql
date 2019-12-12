DROP INDEX idx_tokens_token;

ALTER TABLE ONLY tokens ALTER COLUMN hash SET NOT NULL;
CREATE INDEX idx_tokens_hash ON tokens USING btree (hash);
