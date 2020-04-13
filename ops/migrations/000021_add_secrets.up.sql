-- secrets

CREATE TABLE secrets (
    id uuid DEFAULT uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone NOT NULL,
    vault_id uuid,
    name text NOT NULL,
    description text,
    type varchar(32),
    data bytea
);

ALTER TABLE ONLY secrets ADD CONSTRAINT secrets_pkey PRIMARY KEY (id);

CREATE INDEX idx_secrets_vault_id ON secrets USING btree (vault_id);
CREATE INDEX idx_secrets_type ON secrets USING btree (type);

ALTER TABLE ONLY secrets ADD CONSTRAINT secrets_vault_id_vaults_id_foreign FOREIGN KEY (vault_id) REFERENCES vaults(id) ON UPDATE CASCADE ON DELETE SET NULL;
