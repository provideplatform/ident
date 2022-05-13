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

ALTER TABLE ONLY tokens ADD COLUMN organization_id uuid;

CREATE INDEX idx_tokens_user_id ON tokens USING btree (user_id);
CREATE INDEX idx_tokens_application_id ON tokens USING btree (application_id);
CREATE INDEX idx_tokens_organization_id ON tokens USING btree (organization_id);
CREATE INDEX idx_tokens_application_id_organization_id ON tokens USING btree (application_id, organization_id);
CREATE INDEX idx_tokens_application_id_user_id ON tokens USING btree (application_id, user_id);

ALTER TABLE ONLY tokens ADD CONSTRAINT tokens_organization_id_organizations_id_foreign FOREIGN KEY (organization_id) REFERENCES organizations(id) ON UPDATE CASCADE ON DELETE CASCADE;
