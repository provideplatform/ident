ALTER TABLE ONLY applications ADD COLUMN type char(32);
CREATE INDEX idx_applications_type ON applications USING btree (type);
