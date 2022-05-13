/*
 * Copyright 2017-2022 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

-- vaults

CREATE TABLE vaults (
    id uuid DEFAULT uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone NOT NULL,
    application_id uuid,
    organization_id uuid,
    user_id uuid,
    master_key_id uuid,
    name text NOT NULL,
    description text
);

ALTER TABLE ONLY vaults ADD CONSTRAINT vaults_pkey PRIMARY KEY (id);

CREATE INDEX idx_vaults_application_id ON vaults USING btree (application_id);
ALTER TABLE ONLY vaults ADD CONSTRAINT vaults_application_id_applications_id_foreign FOREIGN KEY (application_id) REFERENCES applications(id) ON UPDATE CASCADE ON DELETE SET NULL;

CREATE INDEX idx_vaults_organization_id ON vaults USING btree (organization_id);
ALTER TABLE ONLY vaults ADD CONSTRAINT vaults_organization_id_organizations_id_foreign FOREIGN KEY (organization_id) REFERENCES organizations(id) ON UPDATE CASCADE ON DELETE SET NULL;

CREATE INDEX idx_vaults_user_id ON vaults USING btree (user_id);
ALTER TABLE ONLY vaults ADD CONSTRAINT vaults_user_id_users_id_foreign FOREIGN KEY (user_id) REFERENCES users(id) ON UPDATE CASCADE ON DELETE SET NULL;

-- keys

CREATE TABLE keys (
    id uuid DEFAULT uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone NOT NULL,
    vault_id uuid,
    name text NOT NULL,
    description text,
    type varchar(32),
    usage varchar(32),
    seed bytea,
    public_key bytea,
    private_key bytea NOT NULL
);

ALTER TABLE ONLY keys ADD CONSTRAINT keys_pkey PRIMARY KEY (id);

CREATE INDEX idx_keys_vault_id ON keys USING btree (vault_id);
CREATE INDEX idx_keys_type ON keys USING btree (type);

ALTER TABLE ONLY keys ADD CONSTRAINT keys_vault_id_vaults_id_foreign FOREIGN KEY (vault_id) REFERENCES vaults(id) ON UPDATE CASCADE ON DELETE SET NULL;
