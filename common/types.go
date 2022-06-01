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

package common

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	uuid "github.com/kthomas/go.uuid"
)

// APICall for accounting purposes
type APICall struct {
	ApplicationID  string    `json:"application_id,omitempty"`
	UserID         string    `json:"user_id,omitempty"`
	OrganizationID string    `json:"organization_id,omitempty"`
	Method         string    `json:"method,omitempty"`
	Host           string    `json:"host,omitempty"`
	Path           string    `json:"path,omitempty"`
	RemoteAddr     string    `json:"remote_addr,omitempty"`
	Timestamp      time.Time `json:"timestamp,omitempty"`
	ContentLength  *uint     `json:"content_length,omitempty"`
	StatusCode     int       `json:"status_code,omitempty"`
	Sha256         *string   `json:"sha256,omitempty"`
	UserAgent      *string   `json:"user_agent,omitempty"`
}

// CalculateHash calculates the sha256 hash of the APICall instance using
// the given packet; if packet is nil, the json representation of APICall
// is used to calculate the hash; this is used to ensure no api call is
// accounted for twice
func (a *APICall) CalculateHash(packet *[]byte) error {
	representation := packet
	if packet == nil {
		apiCallJSON, _ := json.Marshal(a)
		packet = &apiCallJSON
	}

	digest := sha256.New()
	_, err := digest.Write(*representation)
	if err != nil {
		return err
	}
	hash := hex.EncodeToString(digest.Sum(nil))
	a.Sha256 = &hash
	return nil
}

// Model base class with uuid v4 primary key id
type Model struct {
	ID        uuid.UUID `sql:"primary_key;type:uuid;default:uuid_generate_v4()" json:"id"`
	CreatedAt time.Time `sql:"not null;default:now()" json:"created_at,omitempty"`
	Errors    []*Error  `sql:"-" json:"-"`
}

// Error struct
type Error struct {
	Message *string `json:"message"`
	Status  *int    `json:"status,omitempty"`
}
