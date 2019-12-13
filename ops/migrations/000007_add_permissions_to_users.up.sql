ALTER TABLE ONLY users ADD COLUMN expires_at timestamp with time zone;
ALTER TABLE ONLY users ADD COLUMN permissions integer DEFAULT 0;
