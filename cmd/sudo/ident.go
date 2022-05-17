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
	"fmt"
	"sync"

	"github.com/jinzhu/gorm"
	"github.com/kthomas/go-auth0"
	dbconf "github.com/kthomas/go-db-config"
	"github.com/provideplatform/ident/common"
	identuser "github.com/provideplatform/ident/user"
)

var siaDB *gorm.DB
var siaDBConfig *dbconf.DBConfig
var siaConfigOnce sync.Once
var siaDBOnce sync.Once

func syncIdentUsers(db *gorm.DB) error {
	var users []*identuser.User
	db.Where("application_id IS NULL").Find(&users)

	common.Log.Debugf("synchronizing %d ident users with auth0...", len(users))
	for _, usr := range users {
		err := createAuth0User(usr, db)
		if err != nil {
			common.Log.Warningf("failed to synchronize user within auth0: %s", usr.ID.String())
			return err
		}
	}
	return nil
}

// createAuth0User attempts to create an auth0 user for the given ident user; ephemeral params are passed through
func createAuth0User(u *identuser.User, db *gorm.DB) error {
	u.Enrich()

	params := &identuser.EphemeralUserMetadata{
		Name:  common.StringOrNil(*u.Name),
		Email: *u.Email,
	}

	if params.Email == "" {
		params.Email = *u.Email
	}

	if params.Password == nil {
		params.Password = common.StringOrNil(common.RandomString(20)) // require password reset
	}

	if params.AppMetadata == nil {
		params.AppMetadata = map[string]interface{}{}
	}
	params.AppMetadata[identUserIDKey] = u.ID

	_params := map[string]interface{}{
		"connection":    auth0ConnectionTypeUsernamePassword,
		"email":         params.Email,
		"password":      params.Password,
		"user_metadata": map[string]interface{}{},
		"app_metadata":  map[string]interface{}{},
	}
	if params.Name != nil {
		_params["name"] = params.Name
	}
	if params.AppMetadata != nil {
		_params["app_metadata"] = params.AppMetadata
	}
	if params.UserMetadata != nil {
		_params["user_metadata"] = params.UserMetadata
	}
	_, err := auth0.CreateUser(_params)
	if err != nil && !common.Auth0IntegrationCustomDatabase {
		return fmt.Errorf("failed to create auth0 user: %s; %s", params.Email, err.Error())
	}

	// HACK!! attempt authentication if custom db integration is enabled
	u.Password = params.Password
	db.Save(&u)
	_, err = auth0.AuthenticateUser(params.Email, *params.Password)
	if err != nil {
		return fmt.Errorf("failed to authenticate auth0 user: %s; %s", params.Email, err.Error())
	}

	return nil
}
