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

UPDATE users SET first_name=userquery.first_name, last_name=userquery.last_name FROM (SELECT id, split_part(name, ' ', 1) AS first_name, split_part(name, ' ', 2) as last_name from users) AS userquery WHERE users.id=userquery.id;
ALTER TABLE ONLY users DROP COLUMN name;
