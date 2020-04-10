DROP INDEX idx_keys_vault_id;
DROP INDEX idx_keys_type;

DROP INDEX idx_vaults_application_id;
DROP INDEX idx_vaults_organization_id;
DROP INDEX idx_vaults_user_id;

ALTER TABLE ONLY keys DROP CONSTRAINT keys_vault_id_vaults_id_foreign;

ALTER TABLE ONLY vaults DROP CONSTRAINT vaults_application_id_applications_id_foreign;
ALTER TABLE ONLY vaults DROP CONSTRAINT vaults_organization_id_organizations_id_foreign;
ALTER TABLE ONLY vaults DROP CONSTRAINT vaults_user_id_users_id_foreign;

DROP TABLE keys;
DROP TABLE vaults;
