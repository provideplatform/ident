// +build integration

package test

import (
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
