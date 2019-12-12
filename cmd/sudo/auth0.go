package main

import (
	"fmt"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/kthomas/go-auth0"
	"github.com/provideapp/ident/common"
	"github.com/provideapp/ident/user"
)

const identUserIDKey = "ident_user_id"

// syncAuth0 synchronizes data in Auth0 with local Postgres by
// paging through all users and ensuring a record exists for each
func syncAuth0UsersAndLegacyTokens(db *gorm.DB) error {
	if !common.Auth0IntegrationEnabled {
		err := fmt.Errorf("unable to sync auth0 users when AUTH0_INTEGRATION_ENABLED is not true")
		common.Log.Warning(err.Error())
		return err
	}

	common.Log.Debugf("syncing auth0 users...")
	users, err := auth0.ExportUsers()
	if err != nil {
		common.Log.Warningf("failed to sync auth0 users; %s", err.Error())
		return err
	}

	for i := range users {
		auth0User := users[i].(map[string]interface{})
		email := auth0User["email"].(string)
		createdAt, createdAtErr := time.Parse(time.RFC3339Nano, auth0User["created_at"].(string))
		// appMetadata, appMetadataOk := auth0User["app_metadata"].(map[string]interface{})

		var usr *user.User

		if !user.Exists(email, nil) {
			common.Log.Debugf("importing auth0 user %s", email)
			usr = &user.User{
				Email:       &email,
				Permissions: common.DefaultUserPermission,
			}
			if createdAtErr != nil {
				usr.CreatedAt = createdAt
			}
			success, _ := usr.Create(false)
			if success {
				common.Log.Debugf("imported user %s", email)
			} else {
				common.Log.Warningf("failed to import user: %s", email)
			}
		} else {
			common.Log.Debugf("skipping import of existing user %s", email)
			usr = user.FindByEmail(email, nil)
		}

		if usr != nil {
			if createdAtErr == nil {
				usr.CreatedAt = createdAt
				if usr.EphemeralMetadata == nil {
					usr.EphemeralMetadata = &user.EphemeralUserMetadata{}
				}
				if usr.EphemeralMetadata.AppMetadata == nil {
					usr.EphemeralMetadata.AppMetadata = map[string]interface{}{} // auth0 handles this as one would expect from a PATCH operation
				}
				usr.EphemeralMetadata.AppMetadata[identUserIDKey] = usr.ID

				if usr.Update() {
					common.Log.Debugf("updated created_at timestamp (%s) for user: %s", createdAt, email)
				}
			}
		}
	}

	return nil
}
