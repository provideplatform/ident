// +build integration

package test

import (
	"encoding/json"
	"fmt"
	"testing"

	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideservices/provide-go/api/ident"
)

func userFactory(firstName, lastName, email, password string) (*provide.User, error) {
	user, err := provide.CreateUser("", map[string]interface{}{
		"first_name": firstName,
		"last_name":  lastName,
		"email":      email,
		"password":   password,
	})

	return user, err
}

func orgTokenFactory(auth string, organizationID uuid.UUID) (*provide.Token, error) {

	token, err := provide.CreateToken(auth, map[string]interface{}{
		"organization_id": organizationID,
	})
	return token, err
}

func appTokenFactory(auth string, applicationID uuid.UUID) (*provide.Token, error) {

	token, err := provide.CreateToken(auth, map[string]interface{}{
		"application_id": applicationID,
	})
	return token, err
}

func TestCreateUser(t *testing.T) {
	tt := []struct {
		firstName string
		lastName  string
		email     string
		password  string
	}{
		{"first", "last", "first.last@email.com", "secrit_password"},
		{"joey", "joe joe", "j.j.j@email.com", "joeyjoejoe"},
	}

	for _, tc := range tt {
		user, err := userFactory(tc.firstName, tc.lastName, tc.email, tc.password)
		if err != nil {
			t.Errorf("user creation failed. Error: %s", err.Error())
			return
		}

		if user == nil {
			t.Errorf("no user returned")
			return
		}
	}
}

func TestAuthenticateUser(t *testing.T) {
	tt := []struct {
		firstName string
		lastName  string
		email     string
		password  string
	}{
		{"first", "last", "first.last.auth@email.com", "secrit_password"},
		{"joey", "joe joe", "j.j.j.auth@email.com", "joeyjoejoe"},
	}

	for _, tc := range tt {
		_, err := userFactory(tc.firstName, tc.lastName, tc.email, tc.password)
		if err != nil {
			t.Errorf("user creation failed. Error: %s", err.Error())
			return
		}

		auth, err := provide.Authenticate(tc.email, tc.password)
		if err != nil {
			t.Errorf("user authentication failed. Error: %s", err.Error())
		}

		if auth == nil {
			t.Errorf("user not authenticated")
		}
	}
}
func TestCreateOrganization(t *testing.T) {

	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	type organization struct {
		name        string
		description string
	}
	userOrg := organization{
		"Org " + testId.String(),
		"Org " + testId.String() + " Decription",
	}

	tt := []struct {
		firstName string
		lastName  string
		email     string
		password  string
	}{
		{"first", "last", "first.last.auth@email.com", "secrit_password"},
		{"joey", "joe joe", "j.j.j.auth@email.com", "joeyjoejoe"},
	}

	// create the users and add them to the organization
	for _, tc := range tt {
		user, err := userFactory(tc.firstName, tc.lastName, tc.email, tc.password)
		if err != nil {
			t.Errorf("user creation failed. Error: %s", err.Error())
			return
		}

		// get the auth token
		auth, err := provide.Authenticate(tc.email, tc.password)
		if err != nil {
			t.Errorf("user authentication failed for user %s. error: %s", tc.email, err.Error())
		}

		// create the org with that user (for the moment...)
		org, err := provide.CreateOrganization(string(*auth.Token.Token), map[string]interface{}{
			"name":        userOrg.name,
			"description": userOrg.description,
			"user_id":     user.ID,
		})
		if err != nil {
			t.Errorf("error creating organisation for user id %s", user.ID)
		}

		if org == nil {
			t.Errorf("no org created")
			return
		}
	}
}

func TestCreateApplication(t *testing.T) {

	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	type application struct {
		name        string
		description string
	}
	userApp := application{
		"App " + testId.String(),
		"App " + testId.String() + " Decription",
	}

	tt := []struct {
		firstName string
		lastName  string
		email     string
		password  string
	}{
		{"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password"},
		{"joey", "joe joe", "j.j" + testId.String() + "@email.com", "joeyjoejoe"},
	}

	for _, tc := range tt {
		user, err := userFactory(tc.firstName, tc.lastName, tc.email, tc.password)
		if err != nil {
			t.Errorf("user creation failed. Error: %s", err.Error())
			return
		}

		// get the auth token
		auth, err := provide.Authenticate(tc.email, tc.password)
		if err != nil {
			t.Errorf("user authentication failed for user %s. error: %s", tc.email, err.Error())
		}

		// Create an Application for that org
		app, err := provide.CreateApplication(string(*auth.Token.Token), map[string]interface{}{
			"name":        userApp.name,
			"description": userApp.description,
			"user_id":     user.ID,
		})
		if err != nil {
			t.Errorf("error creation application for user id %s", user.ID)
		}

		if app == nil {
			t.Errorf("no application created")
			return
		}
	}
}

func TestListApplicationUsers(t *testing.T) {

	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	//t.Logf("*** test list users *** using testid %s", testId)

	type application struct {
		name        string
		description string
	}
	userApp := application{
		"App " + testId.String(),
		"App " + testId.String() + " Decription",
	}

	tt := []struct {
		firstName string
		lastName  string
		email     string
		password  string
	}{
		{"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password"},
		{"joey", "joe joe", "j.j" + testId.String() + "@email.com", "joeyjoejoe"},
		{"joey2", "joe joe2", "j.j2" + testId.String() + "@email.com", "joeyjoejoe2"},
	}

	appToken := &provide.Token{}
	userApplication := &provide.Application{}

	for _, tc := range tt {

		// create the user
		user, err := userFactory(tc.firstName, tc.lastName, tc.email, tc.password)
		if err != nil {
			t.Errorf("user creation failed. Error: %s", err.Error())
			return
		}

		// get the auth token
		auth, err := provide.Authenticate(tc.email, tc.password)
		if err != nil {
			t.Errorf("user authentication failed for user %s. error: %s", tc.email, err.Error())
			return
		}

		// Create an Application if it doesn't exist
		if userApplication.Name == nil {
			userApplication, err = provide.CreateApplication(string(*auth.Token.Token), map[string]interface{}{
				"name":        userApp.name,
				"description": userApp.description,
				"user_id":     user.ID,
			})
			if err != nil {
				t.Errorf("error creation application for user id %s", user.ID)
				return
			}

			// create a token for that application
			t.Logf("creating token")
			appToken, err = appTokenFactory(*auth.Token.Token, userApplication.ID)
			if err != nil {
				t.Errorf("token creation failed for application id %s. error: %s", userApplication.ID, err.Error())
				return
			}

		} else {
			// let's add this user to the application as the creating user is automatically added...
			// access the add user path through the hackyhack
			// FIXME should be available in provide-go
			path := fmt.Sprintf("applications/%s/users/", userApplication.ID.String())

			status, resp, err := provide.InitIdentService(appToken.Token).Post(path, map[string]interface{}{
				"user_id": user.ID,
			})
			if err != nil {
				t.Errorf("failed to add user %s to organization %s; status: %v; %s", userApplication.ID.String(), user.ID, status, err.Error())
				return
			}

			if status != 204 {
				t.Errorf("failed to add user to application; status: %v; resp: %v", status, resp)
				return
			}
		}
	}

	if appToken != nil {
		users, err := provide.ListUsers(string(*appToken.Token), map[string]interface{}{})
		if err != nil {
			t.Errorf("error getting users list %s", err.Error())
			return
		}
		if len(users) != len(tt) {
			t.Errorf("incorrect number of users returned, expected %d, got %d", len(tt), len(users))
			return
		}
	}
}

func TestUserAccessRefreshToken(t *testing.T) {
	testId, err := uuid.NewV4()
	if err != nil {
		t.Errorf("error creating uuid; %s", err.Error())
		return
	}

	email := fmt.Sprintf("%s@prvd.local", testId.String())
	passwd := "passw0rd"

	user, err := userFactory("joe", "user", email, passwd)
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// get the auth token
	// FIXME should be available in provide-go (offline_access param)
	status, resp, err := provide.InitIdentService(nil).Post("authenticate", map[string]interface{}{
		"email":    email,
		"password": passwd,
		"scope":    "offline_access",
	})
	if err != nil {
		t.Errorf("failed to authenticate user; status: %v; %s", status, err.Error())
		return
	}
	auth := &provide.AuthenticationResponse{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &auth)
	if err != nil {
		t.Errorf("failed to authenticate user; status: %v; %s", status, err.Error())
	}

	accessRefreshToken := auth.Token
	if accessRefreshToken == nil {
		t.Error("user authenticate request with offline_access token scope failed to return access_token/refresh_token")
		return
	}

	// this authenticate response returns an access token
	if accessRefreshToken.Token != nil {
		t.Errorf("token returned for offline_access token scope; should only contain access_token and refresh_token. token present: %+v", accessRefreshToken)
		return
	}

	if accessRefreshToken.AccessToken == nil {
		t.Error("access token not returned for offline_access token scope")
		return
	}

	if accessRefreshToken.RefreshToken == nil {
		t.Error("refresh token not returned for offline_access token scope")
		return
	}

	if accessRefreshToken.ExpiresIn == nil {
		t.Error("expires_in not returned for offline_access token scope")
		return
	}

	// use the refresh token to vend a new access token
	accessToken, err := provide.CreateToken(string(*accessRefreshToken.RefreshToken), map[string]interface{}{
		"grant_type": "refresh_token",
	})
	if err != nil {
		t.Errorf("error refreshing token for user %s", user.ID)
		return
	}

	if accessToken.Token != nil {
		t.Error("token returned for access token authorized by refresh_token token grant; should only contain access_token and optional refresh_token")
		return
	}

	if accessToken.AccessToken == nil {
		t.Error("access token not returned for access token authorized by refresh_token token grant")
		return
	}

	if accessToken.RefreshToken != nil {
		t.Error("refresh token returned for access token authorized by refresh_token token grant")
		return
	}

	if accessToken.ExpiresIn == nil {
		t.Error("expires_in not returned for access token authorized by refresh_token token grant")
		return
	}
}

func TestOrgAccessRefreshToken(t *testing.T) {
	testId, err := uuid.NewV4()
	if err != nil {
		t.Errorf("error creating uuid; %s", err.Error())
		return
	}

	email := fmt.Sprintf("%s@prvd.local", testId.String())
	user, err := userFactory("joe", "user", email, "passw0rd")
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// get the auth token
	auth, err := provide.Authenticate(email, "passw0rd")
	if err != nil {
		t.Errorf("user authentication failed for user %s. error: %s", email, err.Error())
		return
	}

	// create an org
	org, err := provide.CreateOrganization(string(*auth.Token.Token), map[string]interface{}{
		"name": "ABC Corp",
	})
	if err != nil {
		t.Errorf("error creating organization for user id %s", user.ID)
		return
	}

	// create an access/refresh token
	accessRefreshToken, err := provide.CreateToken(string(*auth.Token.Token), map[string]interface{}{
		"organization_id": org.ID.String(),
		"scope":           "offline_access",
	})
	if err != nil {
		t.Errorf("error creating token for org id %s", org.ID.String())
		return
	}

	if accessRefreshToken.Token != nil {
		t.Error("token returned for offline_access token scope; should only contain access_token and refresh_token")
		return
	}

	if accessRefreshToken.AccessToken == nil {
		t.Error("access token not returned for offline_access token scope")
		return
	}

	if accessRefreshToken.RefreshToken == nil {
		t.Error("refresh token not returned for offline_access token scope")
		return
	}

	if accessRefreshToken.ExpiresIn == nil {
		t.Error("expires_in not returned for offline_access token scope")
		return
	}

	// use the refresh token to vend a new access token
	accessToken, err := provide.CreateToken(string(*accessRefreshToken.RefreshToken), map[string]interface{}{
		"grant_type": "refresh_token",
	})
	if err != nil {
		t.Errorf("error refreshing token for org %s", org.ID)
		return
	}

	if accessToken.Token != nil {
		t.Error("token returned for refresh_token token grant; should only contain access_token and optional refresh_token")
		return
	}

	if accessToken.AccessToken == nil {
		t.Error("access token not returned for refresh_token token grant")
		return
	}

	if accessToken.RefreshToken != nil {
		t.Error("refresh token returned for refresh_token token grant")
		return
	}

	if accessToken.ExpiresIn == nil {
		t.Error("expires_in not returned for refresh_token token grant")
		return
	}
}

func TestListOrganisationUsers(t *testing.T) {

	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	//t.Logf("*** test list users *** using testid %s", testId)

	type organization struct {
		name        string
		description string
	}
	userOrg := organization{
		"Org " + testId.String(),
		"Org " + testId.String() + " Decription",
	}

	tt := []struct {
		firstName string
		lastName  string
		email     string
		password  string
	}{
		{"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password"},
		{"joey", "joe joe", "j.j" + testId.String() + "@email.com", "joeyjoejoe"},
		{"joey2", "joe joe2", "j.j2" + testId.String() + "@email.com", "joeyjoejoe2"},
	}

	appToken := &provide.Token{}
	userOrganization := &provide.Organization{}

	for _, tc := range tt {

		// create the user
		user, err := userFactory(tc.firstName, tc.lastName, tc.email, tc.password)
		if err != nil {
			t.Errorf("user creation failed. Error: %s", err.Error())
			return
		}

		// get the auth token
		auth, err := provide.Authenticate(tc.email, tc.password)
		if err != nil {
			t.Errorf("user authentication failed for user %s. error: %s", tc.email, err.Error())
			return
		}

		// Create an Organization if it doesn't exist
		if userOrganization.Name == nil {

			userOrganization, err = provide.CreateOrganization(string(*auth.Token.Token), map[string]interface{}{
				"name":        userOrg.name,
				"description": userOrg.description,
				"user_id":     user.ID,
			})
			if err != nil {
				t.Errorf("error creation organization for user id %s", user.ID)
				return
			}

			// create a token for that organization
			appToken, err = orgTokenFactory(*auth.Token.Token, userOrganization.ID)
			if err != nil {
				t.Errorf("token creation failed for organization id %s. error: %s", userOrganization.ID, err.Error())
				return
			}

		} else {
			//let's add this user to the organization as the creating user is automatically added...

			// access the add user path through the hackyhack
			//FIXME should be available in provide-go
			path := fmt.Sprintf("organizations/%s/users/", userOrganization.ID.String())

			status, resp, err := provide.InitIdentService(appToken.Token).Post(path, map[string]interface{}{
				"user_id": user.ID,
			})
			if err != nil {
				t.Errorf("failed to add user %s to organization %s; status: %v; %s", userOrganization.ID.String(), user.ID, status, err.Error())
				return
			}

			if status != 204 {
				t.Errorf("failed to add user to organization; status: %v; resp: %v", status, resp)
				return
			}
		}
	}

	if appToken != nil {
		users, err := provide.ListUsers(string(*appToken.Token), map[string]interface{}{})
		if err != nil {
			t.Errorf("error getting users list %s", err.Error())
		}
		if len(users) != len(tt) {
			t.Errorf("incorrect number of users returned, expected %d, got %d", len(tt), len(users))
		}
		t.Logf("got correct number of organization users back %d", len(users))
	}
}

func TestUserDetails(t *testing.T) {

	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	tt := []struct {
		firstName string
		lastName  string
		email     string
		password  string
	}{
		{"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password"},
		{"joey", "joe joe", "j.j" + testId.String() + "@email.com", "joeyjoejoe"},
		{"joey2", "joe joe2", "j.j2" + testId.String() + "@email.com", "joeyjoejoe2"},
	}

	for _, tc := range tt {
		// create the user
		user, err := userFactory(tc.firstName, tc.lastName, tc.email, tc.password)
		if err != nil {
			t.Errorf("user creation failed. Error: %s", err.Error())
			return
		}

		// get the auth token
		auth, err := provide.Authenticate(tc.email, tc.password)
		if err != nil {
			t.Errorf("user authentication failed for user %s. error: %s", tc.email, err.Error())
			return
		}

		// get the user details
		deets, err := provide.GetUserDetails(*auth.Token.Token, user.ID.String(), map[string]interface{}{})
		if err != nil {
			t.Errorf("error getting details for user id %s. Error: %s", user.ID, err.Error())
			return
		}

		// fail if they're not the same!
		if deets.Email != user.Email {
			t.Errorf("user email not returned correctly. expected %s, got %s", user.Email, deets.Email)
			return
		}

		if deets.FirstName != user.FirstName {
			t.Errorf("user first name not returned correctly. expected %s, got %s", user.FirstName, deets.FirstName)
			return
		}

		if deets.LastName != user.LastName {
			t.Errorf("user last name not returned correctly. expected %s, got %s", user.LastName, deets.LastName)
			return
		}

		if deets.Name != user.Name {
			t.Errorf("user name not returned correctly. expected %s, got %s", user.Name, deets.Name)
			return
		}
	}
}

func TestUserUpdate(t *testing.T) {
	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	tt := []struct {
		firstName string
		lastName  string
		email     string
		password  string
	}{
		{"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password"},
		{"joey", "joe joe", "j.j" + testId.String() + "@email.com", "joeyjoejoe"},
		{"joey2", "joe joe2", "j.j2" + testId.String() + "@email.com", "joeyjoejoe2"},
	}

	for _, tc := range tt {
		// create the user
		user, err := userFactory(tc.firstName, tc.lastName, tc.email, tc.password)
		if err != nil {
			t.Errorf("user creation failed. Error: %s", err.Error())
			return
		}

		// get the auth token
		auth, err := provide.Authenticate(tc.email, tc.password)
		if err != nil {
			t.Errorf("user authentication failed for user %s. error: %s", tc.email, err.Error())
			return
		}

		// update the user's details
		updatedFirstName := fmt.Sprintf("%s%s", tc.firstName, testId.String())
		updatedLastName := fmt.Sprintf("%s%s", tc.lastName, testId.String())
		updatedName := fmt.Sprintf("%s%s %s%s", tc.firstName, testId.String(), tc.lastName, testId.String())
		updatedEmail := fmt.Sprintf("%s%s", tc.email, testId.String())
		updatedPassword := fmt.Sprintf("%s%s", tc.password, testId.String())

		err = provide.UpdateUser(*auth.Token.Token, user.ID.String(), map[string]interface{}{
			"first_name": updatedFirstName,
			"last_name":  updatedLastName,
			"email":      updatedEmail,
			"password":   updatedPassword,
		})
		if err != nil {
			t.Errorf("error updating user details. Error: %s", err.Error())
		}

		// get the user details
		deets, err := provide.GetUserDetails(*auth.Token.Token, user.ID.String(), map[string]interface{}{})
		if err != nil {
			t.Errorf("error getting details for user id %s. Error: %s", user.ID, err.Error())
			return
		}

		if deets.FirstName != updatedFirstName {
			t.Errorf("user first name not returned correctly. expected %s, got %s", updatedFirstName, deets.FirstName)
			return
		}

		if deets.LastName != updatedLastName {
			t.Errorf("user last name not returned correctly. expected %s, got %s", updatedLastName, deets.LastName)
			return
		}

		if deets.Name != updatedName {
			t.Errorf("user name not returned correctly. expected %s, got %s", updatedName, deets.Name)
			return
		}

		if deets.Email != updatedEmail {
			t.Errorf("user email not returned correctly. expected %s, got %s", updatedEmail, deets.Name)
			return
		}

		//check the updated password
		auth, err = provide.Authenticate(updatedEmail, updatedPassword)
		if err != nil {
			t.Errorf("user authentication failed for user %s. error: %s", updatedEmail, err.Error())
			return
		}

		if auth.Token == nil {
			t.Errorf("no token returned for updated user %s", updatedEmail)
			return
		}

	}
}
