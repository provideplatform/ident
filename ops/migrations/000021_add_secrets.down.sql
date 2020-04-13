DROP INDEX idx_secrets_vault_id;
DROP INDEX idx_secrets_type;

ALTER TABLE ONLY secrets DROP CONSTRAINT secrets_vault_id_vaults_id_foreign;

DROP TABLE secrets;
