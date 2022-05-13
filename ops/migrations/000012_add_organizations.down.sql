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

DROP INDEX idx_organizations_user_id;

ALTER TABLE ONLY organizations DROP CONSTRAINT organizations_user_id_users_id_foreign;

ALTER TABLE ONLY applications_organizations DROP CONSTRAINT applications_application_id_applications_id_foreign;
ALTER TABLE ONLY applications_organizations DROP CONSTRAINT applications_organization_id_organizations_id_foreign;

ALTER TABLE ONLY organizations_users DROP CONSTRAINT organizations_organization_id_organizations_id_foreign;
ALTER TABLE ONLY organizations_users DROP CONSTRAINT organizations_user_id_users_id_foreign;

DROP TABLE applications_organizations;
DROP TABLE organizations_users;
DROP TABLE organizations;
