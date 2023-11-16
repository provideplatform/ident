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
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/kthomas/go-auth0"
	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/ident/application"
	"github.com/provideplatform/ident/common"
	"github.com/provideplatform/ident/organization"
	"github.com/provideplatform/ident/token"
	"github.com/provideplatform/ident/user"
)

const defaultLegacyAuthTokenLength = 64

// when this grows to be complex we can migrate to viper

const createSudoerCmd = "createsudoer"
const createUserCmd = "createuser"
const deleteUserCmd = "deleteuser"
const natsPublishCmd = "natspublish"
const syncAuth0Cmd = "syncauth0"
const syncIdentCmd = "syncident"
const vendTokenCmd = "vendtoken"
const vendApplicationTokenCmd = "vendapptoken"
const vendOrganizationTokenCmd = "vendorgtoken"

func init() {
	auth0.RequireAuth0()
}

func exit(message string, code int) {
	common.Log.Warning(message)
	os.Exit(code)
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("sudo cmd failed; %s", r)
			os.Exit(1)
		}
	}()

	argv := os.Args[1:]
	if len(argv) == 0 {
		common.Log.Warningf("sudo cmd not provided")
		os.Exit(1)
	}

	cmd := argv[0]
	var rawjson *string // memory to which an optional string argument will be read if the cmd supports raw json

	switch cmd {
	case createUserCmd, createSudoerCmd:
		email := strings.ToLower(argv[1])
		permission := common.DefaultUserPermission
		if cmd == createSudoerCmd {
			permission = common.DefaultSudoerPermission
		}

		if len(argv) == 3 {
			rawjson = &argv[2]
		}

		createUser(email, permission, rawjson)
	case deleteUserCmd:
		email := strings.ToLower(argv[1])
		deleteUser(email)
	case natsPublishCmd:
		subject := argv[1]
		payload := argv[2]
		streaming := false
		if len(argv) == 4 {
			streaming = argv[3] == "--streaming"
		}
		natsPublish(subject, payload, streaming)
	case syncAuth0Cmd:
		syncAuth0()
	case syncIdentCmd:
		syncIdent()
	case vendTokenCmd:
		email := strings.ToLower(argv[1])

		var ttl *int
		if len(argv) == 3 {
			parsedttl, err := strconv.Atoi(argv[2])
			if err != nil {
				exit(fmt.Sprintf("failed to vend auth token for user: %s; could not parse ttl for expiration; %s", email, err.Error()), 1)
			}
			ttl = &parsedttl
		}

		appclaims := map[string]interface{}{}
		if len(argv) == 4 {
			err := json.Unmarshal([]byte(argv[3]), &appclaims)
			if err != nil {
				exit(fmt.Sprintf("failed to vend auth token for user: %s; could not parse application claims; %s", email, err.Error()), 1)
			}
		}

		vendToken(email, ttl, appclaims)
	case vendApplicationTokenCmd:
		appID := strings.ToLower(argv[1])

		var ttl *int
		if len(argv) == 3 {
			parsedttl, err := strconv.Atoi(argv[2])
			if err != nil {
				exit(fmt.Sprintf("failed to vend auth token for application: %s; could not parse ttl for expiration; %s", appID, err.Error()), 1)
			}
			ttl = &parsedttl
		}

		appclaims := map[string]interface{}{}
		if len(argv) == 4 {
			err := json.Unmarshal([]byte(argv[3]), &appclaims)
			if err != nil {
				exit(fmt.Sprintf("failed to vend auth token for application: %s; could not parse application claims; %s", appID, err.Error()), 1)
			}
		}

		vendApplicationToken(appID, ttl, appclaims)
	case vendOrganizationTokenCmd:
		orgID := strings.ToLower(argv[1])

		var ttl *int
		if len(argv) == 3 {
			parsedttl, err := strconv.Atoi(argv[2])
			if err != nil {
				exit(fmt.Sprintf("failed to vend auth token for organization: %s; could not parse ttl for expiration; %s", orgID, err.Error()), 1)
			}
			ttl = &parsedttl
		}

		appclaims := map[string]interface{}{}
		if len(argv) == 4 {
			err := json.Unmarshal([]byte(argv[3]), &appclaims)
			if err != nil {
				exit(fmt.Sprintf("failed to vend auth token for organization: %s; could not parse application claims; %s", orgID, err.Error()), 1)
			}
		}

		vendOrganizationToken(orgID, ttl, appclaims)
	default:
		common.Log.Warningf("sudo cmd not implemented: %s", cmd)
		os.Exit(1)
	}
}

func createUser(email string, permission common.Permission, rawjson *string) {
	ephemeralUserParams := &user.EphemeralUserMetadata{}
	if rawjson != nil {
		err := json.Unmarshal([]byte(*rawjson), &ephemeralUserParams)
		if err != nil {
			exit(fmt.Sprintf("failed to parse ephemeral auth0 user params as json; %s", err.Error()), 1)
		}

		if ephemeralUserParams.Email != "" && strings.ToLower(ephemeralUserParams.Email) != email {
			exit(fmt.Sprintf("failed to create user: %s; ephemeral user params included non-matching email address", email), 1)
		}
		ephemeralUserParams.Email = strings.ToLower(email)

		firstName, firstNameOk := ephemeralUserParams.UserMetadata["firstName"].(string)
		lastName, lastNameOk := ephemeralUserParams.UserMetadata["lastName"].(string)
		if firstNameOk && lastNameOk {
			name := strings.Trim(fmt.Sprintf("%s %s", firstName, lastName), " ")
			ephemeralUserParams.Name = &name
		}
	}

	usr := &user.User{
		Email:             common.StringOrNil(email),
		Permissions:       permission,
		EphemeralMetadata: ephemeralUserParams,
	}

	if !usr.Create(dbconf.DatabaseConnection(), true) {
		exit(fmt.Sprintf("failed to create user: %s", email), 1)
	}

	common.Log.Debugf("granted %d permission to user: %s", permission, email)

	if permission.Has(common.Sudo) {
		common.Log.Debugf("granted sudo permission to user: %s", email)
	}

	vendToken(email, nil, map[string]interface{}{})
}

func deleteUser(email string) {
	usr := user.FindByEmail(email, nil, nil)
	if usr == nil {
		exit(fmt.Sprintf("failed to delete user: %s; user does not exist", email), 1)
	}

	db := dbconf.DatabaseConnection()

	userTokens := make([]*token.Token, 0)
	db.Where("user_id = ?", usr.ID).Find(&userTokens)
	for _, token := range userTokens {
		if token.Delete(nil) {
			common.Log.Debugf("deleted legacy token %s for user: %s", *token.Token, *usr.Email)
		}
	}

	if usr.Delete() {
		common.Log.Debugf("deleted user: %s", *usr.Email)
	}
}

func natsPublish(subject, payload string, streaming bool) {
	if !streaming {
		err := natsutil.NatsPublish(subject, []byte(payload))
		if err != nil {
			common.Log.Warningf("failed to publish %d-byte NATS message on subject: %s; %s", len(payload), subject, err.Error())
		} else {
			common.Log.Debugf("published %d-byte NATS streaming message on subject: %s", len(payload), subject)
		}
	} else {
		_, err := natsutil.NatsJetstreamPublish(subject, []byte(payload))
		if err != nil {
			common.Log.Warningf("failed to publish %d-byte NATS streaming message on subject: %s; %s", len(payload), subject, err.Error())
		} else {
			common.Log.Debugf("published %d-byte NATS streaming message on subject: %s", len(payload), subject)
		}
	}
}

func syncAuth0() {
	common.Log.Debugf("attempting to sync auth0 users to ident system of record")
	err := syncAuth0UsersAndLegacyTokens(dbconf.DatabaseConnection())
	if err != nil {
		exit(fmt.Sprintf("failed to sync auth0 users; %s", err.Error()), 1)
	}
	common.Log.Debug("auth0 sync completed successfully")
}

func syncIdent() {
	common.Log.Debugf("attempting to sync ident users in auth0")
	err := syncIdentUsers(dbconf.DatabaseConnection())
	if err != nil {
		exit(fmt.Sprintf("failed to sync ident users; %s", err.Error()), 1)
	}
	common.Log.Debug("ident -> auth0 sync completed successfully")
}

func vendToken(email string, ttl *int, appclaims map[string]interface{}) {
	user := user.FindByEmail(email, nil, nil)
	if user == nil {
		exit(fmt.Sprintf("user does not exist: %s", email), 1)
	}

	common.Log.Debugf("attempting to vend bearer token for user: %s", email)
	token := &token.Token{
		UserID:            &user.ID,
		Permissions:       user.Permissions,
		ApplicationClaims: appclaims,
	}
	if ttl != nil {
		token.TTL = ttl
	}
	if !token.Vend() {
		exit(fmt.Sprintf("failed to vend bearer token for user: %s", email), 1)
	}

	common.Log.Debugf("bearer token created for user: %s\n\n\t%s\n\nPlease keep this in a safe place and treat it as you would other private keys.", email, *token.Token)
	if token.HasPermission(common.Sudo) {
		common.Log.Debug("with great power comes great responsibility...")
	}
}

func vendApplicationToken(appID string, ttl *int, appclaims map[string]interface{}) {
	appUUID, _ := uuid.FromString(appID)
	app := application.FindByID(appUUID)
	if app == nil {
		exit(fmt.Sprintf("app does not exist: %s", appID), 1)
	}

	common.Log.Debugf("attempting to vend bearer token for application: %s", appID)
	token := &token.Token{
		ApplicationID:     &app.ID,
		ApplicationClaims: appclaims,
	}
	if ttl != nil {
		token.TTL = ttl
	}
	if !token.Vend() {
		exit(fmt.Sprintf("failed to vend bearer token for application: %s", appID), 1)
	}

	common.Log.Debugf("bearer token created for application: %s\n\n\t%s\n\nPlease keep this in a safe place and treat it as you would other private keys.", appID, *token.Token)
}

func vendOrganizationToken(orgID string, ttl *int, appclaims map[string]interface{}) {
	orgUUID, _ := uuid.FromString(orgID)
	org := organization.Find(orgUUID)
	if org == nil {
		exit(fmt.Sprintf("org does not exist: %s", orgID), 1)
	}

	common.Log.Debugf("attempting to vend bearer token for organization: %s", orgID)
	token := &token.Token{
		OrganizationID:    &org.ID,
		Scope:             common.StringOrNil("offline_access"),
		ApplicationClaims: appclaims,
	}
	if ttl != nil {
		token.TTL = ttl
	}
	if !token.Vend() {
		exit(fmt.Sprintf("failed to vend bearer token for organization: %s", orgID), 1)
	}

	common.Log.Debugf("bearer token created for organization: %s\n\n\t%s\n\nPlease keep this in a safe place and treat it as you would other private keys.", orgID, *token.Token)
}
