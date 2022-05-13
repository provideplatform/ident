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

// +build integration ident failing

package integration

import (
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	identcommon "github.com/provideplatform/ident/common"
	identuser "github.com/provideplatform/ident/user"
	provide "github.com/provideplatform/provide-go/api/ident"
)

type User struct {
	firstName string
	lastName  string
	email     string
	password  string
}

type Application struct {
	name        string
	description string
}

type Organization struct {
	name        string
	description string
}

func permissionedUserFactory(firstName, lastName, email, password string, permissions identcommon.Permission) (*provide.User, error) {
	user, err := provide.CreateUser("", map[string]interface{}{
		"first_name": firstName,
		"last_name":  lastName,
		"email":      email,
		"password":   password,
	})
	if err != nil {
		return nil, err
	}

	usr := &identuser.User{}
	db := dbconf.DatabaseConnection()
	db.Where("id = ?", user.ID.String()).Find(&usr)
	usr.Permissions = permissions
	db.Save(usr)

	return user, nil
}

func userFactory(firstName, lastName, email, password string) (*provide.User, error) {
	return provide.CreateUser("", map[string]interface{}{
		"first_name": firstName,
		"last_name":  lastName,
		"email":      email,
		"password":   password,
	})
}

func appFactory(token, name, desc string) (*provide.Application, error) {
	return provide.CreateApplication(token, map[string]interface{}{
		"name":        name,
		"description": desc,
	})
}

func orgFactory(token, name, desc string) (*provide.Organization, error) {
	return provide.CreateOrganization(token, map[string]interface{}{
		"name":        name,
		"description": desc,
	})
}

func apporgFactory(token, applicationID, organizationID string) error {
	return provide.CreateApplicationOrganization(token, applicationID, map[string]interface{}{
		"organization_id": organizationID,
	})
}

func appTokenFactory(auth string, applicationID uuid.UUID) (*provide.Token, error) {
	return provide.CreateToken(auth, map[string]interface{}{
		"application_id": applicationID,
	})
}

func orgTokenFactory(auth string, organizationID uuid.UUID) (*provide.Token, error) {
	return provide.CreateToken(auth, map[string]interface{}{
		"organization_id": organizationID,
	})
}

func orgUserTokenFactory(auth string, organizationID, userID uuid.UUID) (*provide.Token, error) {
	return provide.CreateToken(auth, map[string]interface{}{
		"organization_id": organizationID,
		"user_id":         userID,
	})
}
