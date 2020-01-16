ALTER TABLE ONLY organizations_users DROP CONSTRAINT tokens_organization_id_organizations_id_foreign;

DROP INDEX idx_tokens_user_id;
DROP INDEX idx_tokens_application_id;
DROP INDEX idx_tokens_organization_id;
DROP INDEX idx_tokens_application_id_organization_id;
DROP INDEX idx_tokens_application_id_user_id;

ALTER TABLE ONLY tokens DROP COLUMN organization_id;
