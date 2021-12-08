ALTER TABLE ONLY applications ADD COLUMN organization_id uuid;
CREATE INDEX idx_applications_organization_id ON applications USING btree (organization_id);
ALTER TABLE ONLY applications ADD CONSTRAINT applications_organization_id_organizations_id_foreign FOREIGN KEY (organization_id) REFERENCES organizations(id) ON UPDATE CASCADE ON DELETE SET NULL;
