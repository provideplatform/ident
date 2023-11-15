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

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/ident/common"
	api "github.com/provideplatform/provide-go/api"
)

type siaAPICall struct {
	SiaModel

	IdentApplicationID  string `gorm:"-" json:"application_id,omitempty"`
	IdentOrganizationID string `gorm:"-" json:"organization_id,omitempty"`
	IdentUserID         string `gorm:"-" json:"user_id,omitempty"`

	Method        string    `json:"method,omitempty"`
	Host          string    `json:"host,omitempty"`
	Path          string    `json:"path,omitempty"`
	RemoteAddr    string    `json:"remote_addr,omitempty"`
	Timestamp     time.Time `json:"timestamp,omitempty"`
	ContentLength *uint     `json:"content_length,omitempty"`
	StatusCode    int       `json:"status_code,omitempty"`
	Sha256        *string   `json:"sha256,omitempty"`
	UserAgent     *string   `json:"user_agent,omitempty"`

	Raw []byte `json:"raw"`

	// sia types
	AccountID      *uint //`json:"account_id"`
	ApplicationID  *uint //`json:"application_id"`
	OrganizationID *uint //`json:"organization_id"`
}

// CalculateHash calculates the sha256 hash of the APICall instance using
// the given packet; if packet is nil, the json representation of APICall
// is used to calculate the hash; this is used to ensure no api call is
// accounted for twice
func (a *siaAPICall) CalculateHash(packet *[]byte) error {
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

func (siaAPICall) TableName() string {
	return "api_calls"
}

type siaAccount struct {
	SiaModel
	Name           *string    `json:"name"`
	FirstName      *string    `gorm:"-" json:"first_name"`
	LastName       *string    `gorm:"-" json:"last_name"`
	Email          *string    `gorm:"-" json:"email"`
	ApplicationID  *uuid.UUID `gorm:"column:prvd_application_id" json:"prvd_application_id"`
	OrganizationID *uuid.UUID `gorm:"column:prvd_organization_id" json:"prvd_organization_id"`
	UserID         *uuid.UUID `gorm:"column:prvd_user_id" json:"prvd_user_id"`
}

func (siaAccount) TableName() string {
	return "accounts"
}

type siaContact struct {
	SiaModel
	Name            *string `json:"name"`
	FirstName       *string `gorm:"-" json:"first_name"`
	LastName        *string `gorm:"-" json:"last_name"`
	Email           *string `json:"email"`
	ContactableID   *uint   `json:"contactable_id"`
	ContactableType *string `json:"contactable_type"`
	TimeZoneID      *string `json:"time_zone_id"`
}

func (siaContact) TableName() string {
	return "contacts"
}

type siaApplication struct {
	SiaModel
	Name          *string    `json:"name"`
	AccountID     *uint      `json:"account_id"`
	ApplicationID *uuid.UUID `gorm:"column:prvd_application_id" json:"prvd_application_id"`
	UserID        *uuid.UUID `gorm:"column:prvd_user_id" json:"prvd_user_id"`
}

func (siaApplication) TableName() string {
	return "applications"
}

type siaOrganization struct {
	SiaModel
	Name           *string    `json:"name"`
	AccountID      *uint      `json:"account_id"`
	OrganizationID *uuid.UUID `gorm:"column:prvd_organization_id" json:"prvd_organization_id"`
}

func (siaOrganization) TableName() string {
	return "organizations"
}

// SiaModel is only exported to workaround a bug in the gorm library
type SiaModel struct {
	ID     uint         `gorm:"primary_key"`
	Errors []*api.Error `sql:"-" json:"-"`
}

func (call *siaAPICall) enrich(db *gorm.DB) {
	tmpCall := &siaAPICall{}
	db.Where("sha256 = ?", *call.Sha256).Find(&tmpCall)
	if tmpCall != nil && tmpCall.ID != 0 { // FIXME- use int?
		common.Log.Warningf("API call event exists for hash: %s", *call.Sha256)
		// msg.Ack()
		return
	}

	isApplicationSub := false
	isUserSub := false
	isOrgSub := false

	var _sub string
	if _sub == "" {
		if call.IdentUserID != "" {
			_sub = fmt.Sprintf("user:%s", call.IdentUserID)
		} else if call.IdentApplicationID != "" {
			_sub = fmt.Sprintf("application:%s", call.IdentApplicationID)
		} else if call.IdentOrganizationID != "" {
			_sub = fmt.Sprintf("organization:%s", call.IdentOrganizationID)
		}
	}

	subjectParts := make([]string, 0)
	if _sub != "" {
		subjectParts = strings.Split(_sub, ":")

		isApplicationSub = subjectParts[0] == "application"
		isUserSub = subjectParts[0] == "user"
		isOrgSub = subjectParts[0] == "organization"
	}

	account := &siaAccount{} // responsible billing account
	var resolverErr error

	resolveApplication := func(applicationUUID uuid.UUID) error {
		var resolveApplicationErr error
		common.Log.Debugf("resolving responsible account from call db for application: %s", applicationUUID)
		application := &siaApplication{}
		db.Where("prvd_application_id = ?", applicationUUID).Find(&application)
		if application != nil && application.ID != 0 && application.UserID != nil && *application.UserID != uuid.Nil {
			call.ApplicationID = &application.ID
			common.Log.Debugf("resolving responsible application owner's account from call db for user: %s; application id: %s", application.UserID, application.ApplicationID)
			db.Where("prvd_user_id = ?", application.UserID).Find(&account)
		} else if application != nil && application.ID != 0 {
			resolveApplicationErr = fmt.Errorf("failed to resolve responsible application owner's account from call db for user: %s; application id: %s", application.UserID, application.ApplicationID)
		} else {
			resolveApplicationErr = fmt.Errorf("failed to resolve responsible application: %s", applicationUUID)
		}
		return resolveApplicationErr
	}

	resolveOrganization := func(organizationUUID uuid.UUID) error {
		var resolveOrganizationErr error
		common.Log.Debugf("resolving responsible account from sia db for organization: %s", organizationUUID)
		organization := &siaOrganization{}
		db.Where("prvd_organization_id = ?", organizationUUID).Find(&organization)
		if organization != nil && organization.ID != 0 {
			call.OrganizationID = &organization.ID
			common.Log.Debugf("resolving responsible organization account from sia db for organization id: %s", organization.OrganizationID)
			db.Where("id = ?", organization.AccountID).Find(&account)
		} else if organization != nil && organization.ID != 0 {
			resolveOrganizationErr = fmt.Errorf("failed to resolve responsible organization account from sia db for organization: %s", organization.OrganizationID)
		} else {
			resolveOrganizationErr = fmt.Errorf("failed to resolve responsible organization: %s", organizationUUID)
		}
		return resolveOrganizationErr
	}

	if isApplicationSub {
		applicationID := subjectParts[1]
		applicationUUID, err := uuid.FromString(applicationID)
		if err != nil {
			resolverErr = fmt.Errorf("failed to resolve responsible application; %s", err.Error())
		} else {
			resolverErr = resolveApplication(applicationUUID)
		}
	} else if isOrgSub {
		organizationID := subjectParts[1]
		organizationUUID, err := uuid.FromString(organizationID)
		if err != nil {
			resolverErr = fmt.Errorf("failed to resolve responsible organization; %s", err.Error())
		} else {
			resolverErr = resolveOrganization(organizationUUID)
		}
	} else if isUserSub {
		userID := subjectParts[1]
		userUUID, err := uuid.FromString(userID)
		if err == nil {
			common.Log.Debugf("resolving responsible account from sia db for user: %s", userUUID)
			db.Where("prvd_user_id = ?", userUUID).Find(&account)

			if account != nil && account.ApplicationID != nil && *account.ApplicationID != uuid.Nil {
				resolverErr = resolveApplication(*account.ApplicationID)
			}
		}
	}

	if account == nil || account.ID == 0 {
		resolverErr = fmt.Errorf("failed to resolve responsible account for API call event: %s", *call.Sha256)
	}

	if resolverErr != nil {
		common.Log.Warningf("failed to persist API call event: %s; %s", *call.Sha256, resolverErr.Error())
		return
	}

	call.AccountID = &account.ID
	common.Log.Debugf("resolved responsible account %d for API call event: %s", *call.AccountID, *call.Sha256)
}
