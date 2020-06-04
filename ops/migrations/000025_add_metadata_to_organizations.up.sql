ALTER TABLE ONLY organizations ADD COLUMN metadata json DEFAULT '{}';
UPDATE organizations SET metadata = '{}';
