ALTER TABLE ONLY applications ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE ONLY kyc_applications ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE ONLY tokens ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE ONLY users ALTER COLUMN created_at SET DEFAULT now();
