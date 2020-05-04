ALTER TABLE ONLY organizations ADD COLUMN enabled boolean DEFAULT true;
UPDATE organizations SET enabled = true;
ALTER TABLE ONLY organizations ALTER COLUMN enabled SET NOT NULL;
CREATE INDEX idx_organizations_enabled ON organizations USING btree (enabled);
