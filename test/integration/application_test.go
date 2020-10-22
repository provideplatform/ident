// +build integration

package integration

import (
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

// users must have sufficient permission on the application to create and list users...
// an app token does not current grant access to the list of users-- it is more intended
// to be a programmatic api token for interacting with application-owned resources *without*
// undermining the privacy of users who may be part of the application...
func TestListApplicationUsers(t *testing.T) {

	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	// t.Logf("*** test list users *** using testid %s", testId)

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

	var app *provide.Application
	var appToken *provide.Token

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
		if app == nil {
			app, err = provide.CreateApplication(string(*auth.Token.Token), map[string]interface{}{
				"name":        userApp.name,
				"description": userApp.description,
			})
			if err != nil {
				t.Errorf("error creation application for user id %s", user.ID)
				return
			}

			if appToken == nil {
				// create a token for the application
				apptkn, err := appTokenFactory(*auth.Token.Token, app.ID)
				if err != nil {
					t.Errorf("token creation failed for application id %s. error: %s", app.ID, err.Error())
					return
				}
				appToken = apptkn
			}
		} else {
			// let's add this user to the application as the creating user is automatically added...
			err := provide.CreateApplicationUser(*appToken.Token, app.ID.String(), map[string]interface{}{
				"user_id": user.ID.String(),
			})
			if err != nil {
				t.Errorf("failed to add user %s to application %s; %s", user.ID, app.ID.String(), err.Error())
				return
			}
		}
	}

	users, err := provide.ListApplicationUsers(string(*appToken.Token), app.ID.String(), map[string]interface{}{})
	if err == nil {
		t.Error("expected error attepting to fetch app users without an app access token")
		return
	}

	users, err = provide.ListApplicationUsers(string(*appToken.Token), app.ID.String(), map[string]interface{}{})
	if err != nil {
		t.Errorf("error getting users list %s", err.Error())
		return
	}
	if len(users) != len(tt) {
		t.Errorf("incorrect number of application users returned, expected %d, got %d", len(tt), len(users))
	}
	t.Logf("got correct number of application users back %d", len(users))
}
