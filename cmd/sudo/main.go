package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/kthomas/go-auth0"
	dbconf "github.com/kthomas/go-db-config"
	"github.com/provideapp/ident/common"
	"github.com/provideapp/ident/token"
	"github.com/provideapp/ident/user"
)

const defaultLegacyAuthTokenLength = 64

// when this grows to be complex we can migrate to viper

const createSudoerCmd = "createsudoer"
const createUserCmd = "createuser"
const deleteUserCmd = "deleteuser"
const syncAuth0Cmd = "syncauth0"
const vendTokenCmd = "vendtoken"

func init() {
	auth0.RequireAuth0()
	common.RequireJWT()
}

func exit(message string, code int) {
	common.Log.Warning(message)
	os.Exit(1)
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
	case syncAuth0Cmd:
		syncAuth0()
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
		vendToken(email, ttl)
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

	vendToken(email, nil)
}

func deleteUser(email string) {
	usr := user.FindByEmail(email, nil)
	if usr == nil {
		exit(fmt.Sprintf("failed to delete user: %s; user does not exist", email), 1)
	}

	db := dbconf.DatabaseConnection()

	userTokens := make([]*token.Token, 0)
	db.Where("user_id = ?", usr.ID).Find(&userTokens)
	for _, token := range userTokens {
		if token.Delete() {
			common.Log.Debugf("deleted legacy token %s for user: %s", *token.Token, *usr.Email)
		}
	}

	if usr.Delete() {
		common.Log.Debugf("deleted user: %s", *usr.Email)
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

func vendToken(email string, ttl *int) {
	user := user.FindByEmail(email, nil)
	if user == nil {
		exit(fmt.Sprintf("user does not exist: %s", email), 1)
	}

	common.Log.Debugf("attempting to vend bearer token for user: %s", email)
	token := &token.Token{
		UserID:      &user.ID,
		Permissions: user.Permissions,
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
