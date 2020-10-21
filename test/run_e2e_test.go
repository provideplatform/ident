// +build integration

package test

import (
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

func tokenFactory(auth string, applicationID uuid.UUID) (*provide.Token, error) {

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
		t.Logf("user returned: %+v", user)
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
		t.Logf("user authenticated: %+v", auth)
		t.Logf("user returned from auth: %+v", *auth.User)
		t.Logf("token returned from auth: %s", *auth.Token.Token)
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

		//orgSample := provide.Organization{}

		// create the org with that user (for the moment...)
		org, err := provide.CreateOrganization(string(*auth.Token.Token), map[string]interface{}{
			"name":        userOrg.name,
			"description": userOrg.description,
			"user_id":     user.ID,
		})
		if err != nil {
			t.Errorf("error creating organisation for user id %s", user.ID)
		}

		t.Logf("org created %+v", org)
	}
}

func TestCreateApplication(t *testing.T) {

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

		// create the org with that user
		org, err := provide.CreateOrganization(string(*auth.Token.Token), map[string]interface{}{
			"name":        userOrg.name,
			"description": userOrg.description,
			"user_id":     user.ID,
		})
		if err != nil {
			t.Errorf("error creating organisation for user id %s", user.ID)
		}

		t.Logf("TestCreateApplication: org created %+v", org)

		// Create an Application for that org
		app, err := provide.CreateApplication(string(*auth.Token.Token), map[string]interface{}{
			"name":        userApp.name,
			"description": userApp.description,
			"user_id":     user.ID,
		})
		if err != nil {
			t.Errorf("error creation application for user id %s", user.ID)
		}
		t.Logf("TestCreateApplication: app created %+v", *app)
	}
}

func TestListUsers(t *testing.T) {
	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	t.Logf("testId: %s", testId.String())
	type organization struct {
		name        string
		description string
	}
	userOrg := organization{
		"Org " + testId.String(),
		"Org " + testId.String() + " Decription",
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

	appToken := &provide.Token{}
	userApplication := &provide.Application{}

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

		// create the org with that user
		org, err := provide.CreateOrganization(string(*auth.Token.Token), map[string]interface{}{
			"name":        userOrg.name,
			"description": userOrg.description,
			"user_id":     user.ID,
		})
		if err != nil {
			t.Errorf("error creating organisation for user id %s", user.ID)
		}

		t.Logf("TestCreateApplication: org created %+v", org)

		// refresh the auth token
		auth, err = provide.Authenticate(tc.email, tc.password)
		if err != nil {
			t.Errorf("user authentication failed for user %s. error: %s", tc.email, err.Error())
		}

		t.Logf("** user application name %+v", userApplication)
		// Create an Application
		if userApplication.Name == nil {
			t.Logf("*******no user application created, creating...")

			userApplication, err = provide.CreateApplication(string(*auth.Token.Token), map[string]interface{}{
				"name":        userApp.name,
				"description": userApp.description,
				"user_id":     user.ID,
			})
			if err != nil {
				t.Errorf("error creation application for user id %s", user.ID)
			}

			t.Logf("app returned %+v", *userApplication)

		} else {
			t.Logf("********updating user app with user details")

			// get an auth token which will include the app
			appToken, err = tokenFactory(*auth.Token.Token, userApplication.ID)
			if err != nil {
				t.Errorf("token creation failed for application id %s. error: %s", userApplication.ID, err.Error())
			}

			err = provide.UpdateApplication(*appToken.Token, userApplication.ID.String(), map[string]interface{}{
				"name":        userApp.name,
				"description": userApp.description,
				"user_id":     user.ID,
			})
			if err != nil {
				t.Errorf("error creation application for user id %s", user.ID)
			}

			t.Logf("app returned %+v", *userApplication)
		}

		// get an auth token which will include the app
		appToken, err = tokenFactory(*auth.Token.Token, userApplication.ID)
		if err != nil {
			t.Errorf("token creation failed for application id %s. error: %s", userApplication.ID, err.Error())
		}
	}

	if appToken != nil {
		//t.Logf("token, possibly with application id %+v", *appToken.Token)
		users, err := provide.ListUsers(string(*appToken.Token), map[string]interface{}{})
		if err != nil {
			t.Errorf("error getting users list %s", err.Error())
		}
		if len(users) != len(tt) {
			t.Errorf("incorrect number of users returned, expected %d, got %d", len(tt), len(users))
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

	auth, err := provide.Authenticate(email, passwd)
	if err != nil {
		t.Errorf("error authenticating with ident. error %s", err.Error())
	}

	accessRefreshToken := auth.Token
	if accessRefreshToken == nil {
		t.Error("user authenticate request with offline_access token scope failed to return access_token/refresh_token")
		return
	}

	// this authenticate response returns an access token
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
