DROP INDEX idx_tokens_hash;
CREATE INDEX idx_tokens_token ON public.tokens USING btree (token);

ALTER TABLE ONLY tokens ALTER COLUMN hash DROP NOT NULL;
