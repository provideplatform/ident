ALTER TABLE ONLY tokens ADD COLUMN organization_id uuid;

CREATE INDEX idx_tokens_user_id ON tokens USING btree (user_id);
CREATE INDEX idx_tokens_application_id ON tokens USING btree (application_id);
CREATE INDEX idx_tokens_organization_id ON tokens USING btree (organization_id);
CREATE INDEX idx_tokens_application_id_organization_id ON tokens USING btree (application_id, organization_id);
CREATE INDEX idx_tokens_application_id_user_id ON tokens USING btree (application_id, user_id);

ALTER TABLE ONLY tokens ADD CONSTRAINT tokens_organization_id_organizations_id_foreign FOREIGN KEY (organization_id) REFERENCES organization(id) ON UPDATE CASCADE ON DELETE CASCADE;
