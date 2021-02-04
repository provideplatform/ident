package main

import (
	"fmt"
	"sync"

	"github.com/jinzhu/gorm"
	"github.com/kthomas/go-auth0"
	dbconf "github.com/kthomas/go-db-config"
	"github.com/provideapp/ident/common"
	identuser "github.com/provideapp/ident/user"
	"github.com/provideservices/provide-go/api/ident"
)

var siaDB *gorm.DB
var siaDBConfig *dbconf.DBConfig
var siaConfigOnce sync.Once
var siaDBOnce sync.Once

func syncIdentUsers(db *gorm.DB) error {
	var users []*ident.User
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
	// params := u.Metadata
	params := &identuser.EphemeralUserMetadata{
		Name:  common.StringOrNil(*u.Email),
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
	if err != nil {
		// HACK!!
		u.Password = params.Password
		db.Save(&u)
		_, err := auth0.AuthenticateUser(params.Email, *params.Password)
		if err != nil {
			return fmt.Errorf("failed to create auth0 user: %s; %s", params.Email, err.Error())
		}
	}

	return nil
}
