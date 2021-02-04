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
	ID            *string                `json:"user_id,omitempty"`
	Name          *string                `json:"name"`
	Email         string                 `json:"email"`
	EmailVerified bool                   `json:"email_verified"`
	Password      *string                `json:"password,omitempty"`
	AppMetadata   map[string]interface{} `json:"app_metadata"`
	UserMetadata  map[string]interface{} `json:"user_metadata"`
}

// createAuth0User creates a Username-Password-Authentication connection in auth0
func createAuth0User(userParams *EphemeralUserMetadata) error {
	params := map[string]interface{}{
		"connection":     auth0ConnectionTypeUsernamePassword,
		"email":          userParams.Email,
		"email_verified": userParams.EmailVerified,
		"password":       userParams.Password,
		"user_metadata":  map[string]interface{}{},
		"app_metadata":   map[string]interface{}{},
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

// createAuth0User attempts to create an associated auth0 user, passing through any ephemeral params
func (u *User) createAuth0User() error {
	params := u.EphemeralMetadata
	if params == nil {
		params = &EphemeralUserMetadata{
			Name:  u.Email,
			Email: *u.Email,
		}
	}

	if params.Email == "" {
		params.Email = *u.Email
	}

	if params.Password == nil {
		if u.Password != nil {
			params.Password = u.Password
		} else {
			params.Password = common.StringOrNil(common.RandomString(20)) // require password reset
		}
	}

	if params.AppMetadata == nil {
		params.AppMetadata = map[string]interface{}{}
	}
	params.AppMetadata[identUserIDKey] = u.ID

	err := createAuth0User(params)
	if err != nil {
		return fmt.Errorf("failed to create auth0 user: %s; %s", *u.Email, err.Error())
	}

	return nil
}

// deleteAuth0User attempts to delete the associated auth0 user
func (u *User) deleteAuth0User() error {
	err := deleteAuth0User(*u.Email)
	if err != nil {
		err := fmt.Errorf("failed to delete auth0 user: %s; %s", *u.Email, err.Error())
		common.Log.Warning(err.Error())
		return err
	}

	return nil
}

// fetchAuth0User attempts to fetch the associated auth0 user
func (u *User) fetchAuth0User() (*EphemeralUserMetadata, error) {
	auth0User, err := fetchAuth0User(*u.Email)
	if err != nil {
		err := fmt.Errorf("failed to enrich auth0 user: %s; %s", *u.Email, err.Error())
		common.Log.Warning(err.Error())
		return nil, err
	}
	if auth0User != nil && auth0User.ID == nil {
		err := fmt.Errorf("failed to enrich auth0 user: %s", *u.Email)
		common.Log.Warning(err.Error())
		return nil, err
	}

	return auth0User, nil
}

// updateAuth0User attempts to update the associated auth0 user, passing through any ephemeral params
func (u *User) updateAuth0User() error {
	params := u.EphemeralMetadata
	if params == nil {
		err := errors.New("not updating auth0 user without ephemeral params")
		common.Log.Debug(err.Error())
		return err
	}

	if params.AppMetadata == nil {
		params.AppMetadata = map[string]interface{}{}
	}
	params.AppMetadata[identUserIDKey] = u.ID

	// deep copy the params
	auth0Params := &EphemeralUserMetadata{}
	rawparams, _ := json.Marshal(params)
	json.Unmarshal(rawparams, &auth0Params)

	// enrich the user to make sure the proper auth0 id is used
	err := u.Enrich()
	if err != nil {
		err := fmt.Errorf("failed to update auth0 user: %s; %s", *u.Email, err.Error())
		common.Log.Warning(err.Error())
		return err
	}

	err = updateAuth0User(*u.EphemeralMetadata.ID, auth0Params)
	if err != nil {
		err := fmt.Errorf("failed to update auth0 user: %s; %s", *u.Email, err.Error())
		common.Log.Warning(err.Error())
		return err
	}

	return nil
}
