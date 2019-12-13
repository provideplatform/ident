ALTER TABLE ONLY tokens ADD COLUMN permissions integer DEFAULT 0;
UPDATE tokens SET permissions = 0;
ALTER TABLE ONLY tokens ALTER COLUMN permissions SET NOT NULL;

