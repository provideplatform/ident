ALTER TABLE ONLY users ALTER COLUMN permissions DROP NOT NULL;
UPDATE users SET permissions = NULL;
