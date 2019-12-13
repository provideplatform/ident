UPDATE users SET permissions = 0;
ALTER TABLE ONLY users ALTER COLUMN permissions SET NOT NULL;
