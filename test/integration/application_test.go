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

	userApp := Application{
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

	userApp := Application{
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
	var userToken *provide.Token

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

		if userToken == nil {
			userToken = auth.Token
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

	users, err := provide.ListApplicationUsers(string(*userToken.Token), app.ID.String(), map[string]interface{}{})
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

func TestGetApplicationDetails(t *testing.T) {

	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	authUser := User{
		"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password",
	}

	tt := []struct {
		name        string
		description string
	}{
		{"App1" + testId.String(), "App1 Description" + testId.String()},
		{"App2" + testId.String(), "App2 Description" + testId.String()},
	}

	// set up the user that will create the application
	user, err := userFactory(authUser.firstName, authUser.lastName, authUser.email, authUser.password)
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// get the auth token for the auth user
	auth, err := provide.Authenticate(authUser.email, authUser.password)
	if err != nil {
		t.Errorf("user authentication failed for user %s. error: %s", authUser.email, err.Error())
	}

	for _, tc := range tt {

		// Create an Application for that org
		app, err := provide.CreateApplication(string(*auth.Token.Token), map[string]interface{}{
			"name":        tc.name,
			"description": tc.description,
			"user_id":     user.ID,
		})
		if err != nil {
			t.Errorf("error creation application for user id %s", user.ID)
		}

		if app == nil {
			t.Errorf("no application created")
			return
		}

		deets, err := provide.GetApplicationDetails(*auth.Token.Token, app.ID.String(), map[string]interface{}{})
		if err != nil {
			t.Errorf("error getting application details. Error: %s", err.Error())
			return
		}

		if *app.Name != *deets.Name {
			t.Errorf("Name mismatch. Expected %s, got %s", *app.Name, *deets.Name)
			return
		}

		if *app.Description != *deets.Description {
			t.Errorf("Description mismatch. Expected %s, got %s", *app.Description, *deets.Description)
			return
		}

		if app.UserID.String() != deets.UserID.String() {
			t.Errorf("UserID mismatch. Expected %s, got %s", app.UserID.String(), deets.UserID.String())
			return
		}
	}
}

func TestUpdateApplicationDetails(t *testing.T) {

	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	authUser := User{
		"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password",
	}

	tt := []struct {
		name        string
		description string
	}{
		{"App1" + testId.String(), "App1 Description" + testId.String()},
		{"App2" + testId.String(), "App2 Description" + testId.String()},
	}

	// set up the user that will create the application
	user, err := userFactory(authUser.firstName, authUser.lastName, authUser.email, authUser.password)
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// get the auth token for the auth user
	auth, err := provide.Authenticate(authUser.email, authUser.password)
	if err != nil {
		t.Errorf("user authentication failed for user %s. error: %s", authUser.email, err.Error())
	}

	// loop through apps and create, and update them
	for _, tc := range tt {

		// Create an Application for that org
		app, err := provide.CreateApplication(string(*auth.Token.Token), map[string]interface{}{
			"name":        tc.name,
			"description": tc.description,
			"user_id":     user.ID,
		})
		if err != nil {
			t.Errorf("error creation application for user id %s", user.ID)
		}

		if app == nil {
			t.Errorf("no application created")
			return
		}

		updatedName := tc.name + testId.String()
		updatedDescription := tc.description + testId.String()

		err = provide.UpdateApplication(string(*auth.Token.Token), app.ID.String(), map[string]interface{}{
			"name":        updatedName,
			"description": updatedDescription,
		})
		if err != nil {
			t.Errorf("error updating application details. Error: %s", err.Error())
		}

		deets, err := provide.GetApplicationDetails(*auth.Token.Token, app.ID.String(), map[string]interface{}{})
		if err != nil {
			t.Errorf("error getting application details. Error: %s", err.Error())
			return
		}

		if *deets.Name != updatedName {
			t.Errorf("Name mismatch. Expected %s, got %s", updatedName, *deets.Name)
			return
		}

		if *deets.Description != updatedDescription {
			t.Errorf("Description mismatch. Expected %s, got %s", updatedDescription, *deets.Description)
			return
		}

		if app.UserID.String() != deets.UserID.String() {
			t.Errorf("UserID mismatch. Expected %s, got %s", app.UserID.String(), deets.UserID.String())
			return
		}
	}
}

// CHECKME this test will check if I can view the application details
// by a user who has nothing to do with the application
// assumption is that they shouldn't be able to read the application details
func TestFetchAppDetailsFailsWithUnauthorizedUser(t *testing.T) {

	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	authUser := User{
		"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password",
	}

	nonAuthUser := User{
		"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password",
	}

	tt := []struct {
		name        string
		description string
	}{
		{"App1" + testId.String(), "App1 Description" + testId.String()},
		{"App2" + testId.String(), "App2 Description" + testId.String()},
	}

	// set up the user that will create the application
	user, err := userFactory(authUser.firstName, authUser.lastName, authUser.email, authUser.password)
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// set up a user that will have nothing to do with the application
	_, err = userFactory(nonAuthUser.firstName, nonAuthUser.lastName, nonAuthUser.email, nonAuthUser.password)
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// get the auth token for the auth user
	auth, err := provide.Authenticate(authUser.email, authUser.password)
	if err != nil {
		t.Errorf("user authentication failed for user %s. error: %s", authUser.email, err.Error())
	}

	// get the auth token for the non application user
	nonAuth, err := provide.Authenticate(nonAuthUser.email, nonAuthUser.password)
	if err != nil {
		t.Errorf("user authentication failed for user %s. error: %s", nonAuthUser.email, err.Error())
	}

	for _, tc := range tt {

		// Create an Application for that org
		app, err := provide.CreateApplication(string(*auth.Token.Token), map[string]interface{}{
			"name":        tc.name,
			"description": tc.description,
			"user_id":     user.ID,
		})
		if err != nil {
			t.Errorf("error creation application for user id %s", user.ID)
		}

		if app == nil {
			t.Errorf("no application created")
			return
		}

		_, err = provide.GetApplicationDetails(*nonAuth.Token.Token, app.ID.String(), map[string]interface{}{})
		if err == nil {
			t.Errorf("expected error getting application details by a user not associated with the application")
			return
		}
	}
}

// CHECKME this test will check if I can update the application details
// by a user who has nothing to do with the application
// assumption is that they shouldn't be able to update the application details
func TestUserUpdateAppDetailsAccess(t *testing.T) {

	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	authUser := User{
		"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password",
	}

	nonAuthUser := User{
		"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password",
	}

	tt := []struct {
		name        string
		description string
	}{
		{"App1" + testId.String(), "App1 Description" + testId.String()},
		{"App2" + testId.String(), "App2 Description" + testId.String()},
	}

	// set up the user that will create the application
	user, err := userFactory(authUser.firstName, authUser.lastName, authUser.email, authUser.password)
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// set up a user that will have nothing to do with the application
	nonUser, err := userFactory(nonAuthUser.firstName, nonAuthUser.lastName, nonAuthUser.email, nonAuthUser.password)
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// get the auth token for the auth user
	auth, err := provide.Authenticate(authUser.email, authUser.password)
	if err != nil {
		t.Errorf("user authentication failed for user %s. error: %s", authUser.email, err.Error())
	}

	// get the auth token for the non application user
	nonAuth, err := provide.Authenticate(nonAuthUser.email, nonAuthUser.password)
	if err != nil {
		t.Errorf("user authentication failed for user %s. error: %s", nonAuthUser.email, err.Error())
	}

	for _, tc := range tt {

		// Create an Application for that org
		app, err := provide.CreateApplication(string(*auth.Token.Token), map[string]interface{}{
			"name":        tc.name,
			"description": tc.description,
			"user_id":     user.ID,
		})
		if err != nil {
			t.Errorf("error creation application for user id %s", user.ID)
		}

		if app == nil {
			t.Errorf("no application created")
			return
		}

		updatedName := tc.name + testId.String()
		updatedDescription := tc.description + testId.String()

		err = provide.UpdateApplication(*nonAuth.Token.Token, app.ID.String(), map[string]interface{}{
			"name":        updatedName,
			"description": updatedDescription,
			"user_id":     nonUser.ID,
		})
		if err == nil {
			t.Errorf("expected error updating application details by a user not associated with the application")
		}

		deets, err := provide.GetApplicationDetails(*auth.Token.Token, app.ID.String(), map[string]interface{}{})
		if err != nil {
			t.Errorf("error getting application details. Error: %s", err.Error())
			return
		}

		// double check if they're updated (no return on UpdateApplication error above so we get to run this code)
		if *deets.Name == updatedName {
			t.Errorf("Name updated by non-Application user!. Expected %s, got %s", *app.Name, *deets.Name)
			return
		}

		if *deets.Description == updatedDescription {
			t.Errorf("Description updated by non-Application user! Expected %s, got %s", *app.Description, *deets.Description)
			return
		}

		if deets.UserID.String() != app.UserID.String() {
			t.Errorf("UserID updated by non-Application user! Expected %s, got %s", app.UserID.String(), deets.UserID.String())
			return
		}
	}
}

func TestDeleteApplication(t *testing.T) {
	// FIXME if the magic elves can add a DeleteApplication to provide-go, I will put out a saucer of milk tonight
	t.Errorf("provide-go method missing")
}

func testAddAppOrgHandler(t *testing.T) {
	t.Errorf("missing method in provide-go to add organization to application")
}
func TestListApplicationTokens(t *testing.T) {
	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	authUser := User{"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password"}

	testApp := Application{"App1" + testId.String(), "App1 Description" + testId.String()}

	// set up the user that will create the application
	_, err = userFactory(authUser.firstName, authUser.lastName, authUser.email, authUser.password)
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// get the auth token for the auth user
	auth, err := provide.Authenticate(authUser.email, authUser.password)
	if err != nil {
		t.Errorf("user authentication failed for user %s. error: %s", authUser.email, err.Error())
	}

	app, err := provide.CreateApplication(*auth.Token.Token, map[string]interface{}{
		"name":        testApp.name,
		"description": testApp.description,
	})
	if err != nil {
		t.Errorf("error creating application. Error: %s", err.Error())
		return
	}

	const tokenCount = 5
	var createdTokens [tokenCount]provide.Token

	for looper := 0; looper < tokenCount; looper++ {
		token, err := appTokenFactory(*auth.Token.Token, app.ID)
		if err != nil {
			t.Errorf("error creating app token")
			return
		}
		createdTokens[looper] = *token
	}

	listOfTokens, err := provide.ListApplicationTokens(*auth.Token.Token, app.ID.String(), map[string]interface{}{})
	if err != nil {
		t.Errorf("error getting list of application tokens. Error: %s", err.Error())
		return
	}

	if len(listOfTokens) != tokenCount {
		t.Errorf("incorrect number of application tokens returned.  Expected %d, got %d", tokenCount, len(listOfTokens))
		return
	}
	// hard to check these without a bunch of code to iterate through everything. I'm looking at
	// writing something, but this will do for now.
}
