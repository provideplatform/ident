package user

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kthomas/go-auth0"
	"github.com/provideapp/ident/common"
)

const auth0ConnectionTypeUsernamePassword = "Username-Password-Authentication"

// EphemeralUserMetadata are passed through ident during auth0 user creation
type EphemeralUserMetadata struct {
	ID           *string                `json:"user_id,omitempty"`
	Name         *string                `json:"name"`
	Email        string                 `json:"email"`
	Password     *string                `json:"password,omitempty"`
	AppMetadata  map[string]interface{} `json:"app_metadata"`
	UserMetadata map[string]interface{} `json:"user_metadata"`
}

// createAuth0User creates a Username-Password-Authentication connection in auth0
func createAuth0User(userParams *EphemeralUserMetadata) error {
	params := map[string]interface{}{
		"connection":    auth0ConnectionTypeUsernamePassword,
		"email":         userParams.Email,
		"password":      userParams.Password,
		"user_metadata": map[string]interface{}{},
		"app_metadata":  map[string]interface{}{},
	}
	if userParams.Name != nil {
		params["name"] = userParams.Name
	}
	if userParams.AppMetadata != nil {
		params["app_metadata"] = userParams.AppMetadata
	}
	if userParams.UserMetadata != nil {
		params["user_metadata"] = userParams.UserMetadata
	}
	_, err := auth0.CreateUser(params)
	return err
}

// updateAuth0User updates an auth0 user's user_metadata and app_metadata
func updateAuth0User(auth0UserID string, userParams *EphemeralUserMetadata) error {
	params := map[string]interface{}{}
	if userParams.AppMetadata != nil {
		params["app_metadata"] = userParams.AppMetadata
	}
	if userParams.UserMetadata != nil {
		params["user_metadata"] = userParams.UserMetadata
	}
	_, err := auth0.UpdateUser(auth0UserID, params)
	return err
}

// deleteAuth0User deletes an auth0 user by email address
func deleteAuth0User(email string) error {
	resp, err := auth0.GetUserByEmail(email)
	if err != nil {
		return err
	}
	if auth0Users, auth0UsersOk := resp.([]interface{}); auth0UsersOk {
		if len(auth0Users) != 1 {
			msg := fmt.Sprintf("auth0 user-by-email query %s returned %d users; expected one", email, len(auth0Users))
			common.Log.Warning(msg)
			return errors.New(msg)
		}
		if auth0User, auth0UserOk := auth0Users[0].(map[string]interface{}); auth0UserOk {
			if auth0UserID, auth0UserIDOk := auth0User["user_id"].(string); auth0UserIDOk {
				_, err := auth0.DeleteUser(auth0UserID)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// fetchAuth0User retrieves an auth0 user by email address
func fetchAuth0User(email string) (*EphemeralUserMetadata, error) {
	var usr *EphemeralUserMetadata
	resp, err := auth0.GetUserByEmail(email)
	if err != nil {
		return nil, err
	}
	if auth0Users, auth0UsersOk := resp.([]interface{}); auth0UsersOk {
		if len(auth0Users) != 1 {
			msg := fmt.Sprintf("auth0 user-by-email query %s returned %d users; expected one", email, len(auth0Users))
			common.Log.Warning(msg)
			return nil, errors.New(msg)
		}
		usr = &EphemeralUserMetadata{}
		auth0UserRaw, _ := json.Marshal(auth0Users[0]) // HACK
		err := json.Unmarshal(auth0UserRaw, &usr)
		if err != nil {
			return nil, err
		}
	}
	return usr, nil
}
