// +build integration

package test

import (
	"fmt"
	"testing"

	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideservices/provide-go/api/ident"
)

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
