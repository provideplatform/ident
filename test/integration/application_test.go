// +build integration ident

package integration

import (
	"fmt"
	"testing"

	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideplatform/provide-go/api/ident"
)

func TestCreateApplication(t *testing.T) {
	t.Parallel()
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
		app, err := provide.CreateApplication(string(*auth.Token.AccessToken), map[string]interface{}{
			"name":        userApp.name,
			"description": userApp.description,
			"user_id":     *user.ID,
		})
		if err != nil {
			t.Errorf("error creation application for user id %s", *user.ID)
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
	t.Parallel()
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
			app, err = provide.CreateApplication(string(*auth.Token.AccessToken), map[string]interface{}{
				"name":        userApp.name,
				"description": userApp.description,
			})
			if err != nil {
				t.Errorf("error creation application for user id %s", *user.ID)
				return
			}

			if appToken == nil {
				// create a token for the application
				apptkn, err := appTokenFactory(*auth.Token.AccessToken, app.ID)
				if err != nil {
					t.Errorf("token creation failed for application id %s. error: %s", app.ID, err.Error())
					return
				}
				appToken = apptkn
			}
		} else {
			// let's add this user to the application as the creating user is automatically added...
			err := provide.CreateApplicationUser(*appToken.Token, app.ID.String(), map[string]interface{}{
				"user_id": *user.ID,
			})
			if err != nil {
				t.Errorf("failed to add user %s to application %s; %s", *user.ID, app.ID.String(), err.Error())
				return
			}
		}
	}

	users, err := provide.ListApplicationUsers(string(*userToken.AccessToken), app.ID.String(), map[string]interface{}{})
	if err != nil { // the user who created the application is *currently* allowed to operate on the application. probably needs a permissions update.
		t.Errorf("error getting users list %s", err.Error())
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
	t.Parallel()
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
		app, err := provide.CreateApplication(string(*auth.Token.AccessToken), map[string]interface{}{
			"name":        tc.name,
			"description": tc.description,
			"user_id":     *user.ID,
		})
		if err != nil {
			t.Errorf("error creation application for user id %s", *user.ID)
		}

		if app == nil {
			t.Errorf("no application created")
			return
		}

		deets, err := provide.GetApplicationDetails(*auth.Token.AccessToken, app.ID.String(), map[string]interface{}{})
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

		if *app.UserID != *deets.UserID {
			t.Errorf("UserID mismatch. Expected %s, got %s", *app.UserID, *deets.UserID)
			return
		}
	}
}

func TestUpdateApplicationDetails(t *testing.T) {
	t.Parallel()
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
		app, err := provide.CreateApplication(string(*auth.Token.AccessToken), map[string]interface{}{
			"name":        tc.name,
			"description": tc.description,
			"user_id":     *user.ID,
		})
		if err != nil {
			t.Errorf("error creation application for user id %s", *user.ID)
		}

		if app == nil {
			t.Errorf("no application created")
			return
		}

		updatedName := tc.name + testId.String()
		updatedDescription := tc.description + testId.String()

		err = provide.UpdateApplication(string(*auth.Token.AccessToken), app.ID.String(), map[string]interface{}{
			"name":        updatedName,
			"description": updatedDescription,
		})
		if err != nil {
			t.Errorf("error updating application details. Error: %s", err.Error())
		}

		deets, err := provide.GetApplicationDetails(*auth.Token.AccessToken, app.ID.String(), map[string]interface{}{})
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

		if *app.UserID != *deets.UserID {
			t.Errorf("UserID mismatch. Expected %s, got %s", *app.UserID, *deets.UserID)
			return
		}
	}
}

// CHECKME this test will check if I can view the application details
// by a user who has nothing to do with the application
// assumption is that they shouldn't be able to read the application details
// QUESTION: is this the case?
func TestFetchAppDetailsFailsWithUnauthorizedUser(t *testing.T) {
	t.Parallel()
	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	authUser := User{
		"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password",
	}

	nonAuthUser := User{
		"first", "last.notauth", "first.last.notauth" + testId.String() + "@email.com", "secrit_password",
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
	notAuthorizedUser, err := userFactory(nonAuthUser.firstName, nonAuthUser.lastName, nonAuthUser.email, nonAuthUser.password)
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

		// Create an Application for that user
		app, err := provide.CreateApplication(string(*auth.Token.AccessToken), map[string]interface{}{
			"name":        tc.name,
			"description": tc.description,
		})
		if err != nil {
			t.Errorf("error creation application for user id %s", *user.ID)
		}

		if app == nil {
			t.Errorf("no application created")
			return
		}

		t.Logf("about to check app details with unauthorized user")
		t.Logf("app id: %s", app.ID)
		t.Logf("user id: %+v", notAuthorizedUser)
		_, err = provide.GetApplicationDetails(*nonAuth.Token.AccessToken, app.ID.String(), map[string]interface{}{})
		if err == nil {
			t.Errorf("expected error getting application details by a user not associated with the application")
			return
		}
	}
}

// CHECKME this test will check if I can update the application details
// by a user who has nothing to do with the application
// assumption is that they shouldn't be able to update the application details
// QUESTION: is this the case?
func TestUserUpdateAppDetailsAccess(t *testing.T) {
	t.Parallel()
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
		app, err := provide.CreateApplication(string(*auth.Token.AccessToken), map[string]interface{}{
			"name":        tc.name,
			"description": tc.description,
			"user_id":     *user.ID,
		})
		if err != nil {
			t.Errorf("error creation application for user id %s", *user.ID)
		}

		if app == nil {
			t.Errorf("no application created")
			return
		}

		updatedName := tc.name + testId.String()
		updatedDescription := tc.description + testId.String()

		err = provide.UpdateApplication(*nonAuth.Token.AccessToken, app.ID.String(), map[string]interface{}{
			"name":        updatedName,
			"description": updatedDescription,
			"user_id":     *nonUser.ID,
		})
		if err == nil {
			t.Errorf("expected error updating application details by a user not associated with the application")
		}

		deets, err := provide.GetApplicationDetails(*auth.Token.AccessToken, app.ID.String(), map[string]interface{}{})
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

		if *deets.UserID != *app.UserID {
			t.Errorf("UserID updated by non-Application user! Expected %s, got %s", *app.UserID, *deets.UserID)
			return
		}
	}
}

func TestDeleteApplication(t *testing.T) {
	t.Parallel()
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
		app, err := provide.CreateApplication(string(*auth.Token.AccessToken), map[string]interface{}{
			"name":        userApp.name,
			"description": userApp.description,
			"user_id":     *user.ID,
		})
		if err != nil {
			t.Errorf("error creation application for user id %s", *user.ID)
		}

		if app == nil {
			t.Errorf("no application created")
			return
		}

		// start the actual tests... lol... we gotta hire someone to DRY up this suite someday :D
		err = provide.DeleteApplication(string(*auth.Token.AccessToken), app.ID.String())
		if err != nil {
			t.Errorf("error soft-deleting application %s", app.ID)
			return
		}
		deets, err := provide.GetApplicationDetails(*auth.Token.AccessToken, app.ID.String(), map[string]interface{}{})
		if err != nil {
			t.Errorf("failed retrieving application details for soft-deleted app %s", app.ID)
			return
		}

		if !deets.Hidden {
			t.Errorf("failed soft-deleting application app %s; app was not marked 'hidden'", app.ID)
			return
		}
	}
}

func testAddAppOrgHandler(t *testing.T) {
	t.Parallel()
	t.Logf("missing method in provide-go to add organization to application")
}

func TestListApplicationTokens(t *testing.T) {
	t.Parallel()
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

	app, err := provide.CreateApplication(*auth.Token.AccessToken, map[string]interface{}{
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
		token, err := appTokenFactory(*auth.Token.AccessToken, app.ID)
		if err != nil {
			t.Errorf("error creating app token")
			return
		}
		createdTokens[looper] = *token
	}

	listOfTokens, err := provide.ListApplicationTokens(*auth.Token.AccessToken, app.ID.String(), map[string]interface{}{})
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

func TestApplicationOrganizationList(t *testing.T) {
	t.Parallel()
	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	// set up the user
	authUser := User{
		"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password",
	}

	user, err := userFactory(authUser.firstName, authUser.lastName, authUser.email, authUser.password)
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// get the auth token for the user
	auth, err := provide.Authenticate(authUser.email, authUser.password)
	if err != nil {
		t.Errorf("user authentication failed for user %s. error: %s", authUser.email, err.Error())
	}

	userApp := Application{
		"testApp1" + testId.String(), "testApp1Desc" + testId.String(),
	}

	app, err := provide.CreateApplication(string(*auth.Token.AccessToken), map[string]interface{}{
		"name":        userApp.name,
		"description": userApp.description,
		"user_id":     *user.ID,
	})
	if err != nil {
		t.Errorf("error creation application for user id %s", *user.ID)
	}

	if app == nil {
		t.Errorf("no application created")
		return
	}

	tt := []struct {
		name        string
		description string
	}{
		{"Org1" + testId.String(), "Org1 Description" + testId.String()},
		{"Org2" + testId.String(), "Org2 Description" + testId.String()},
	}

	for _, tc := range tt {

		did, err := didFactory()
		if err != nil {
			t.Errorf("did creation failed. error: %s", err.Error())
		}
		org, err := provide.CreateOrganization(string(*auth.Token.AccessToken), map[string]interface{}{
			"id":          did,
			"name":        tc.name,
			"description": tc.description,
			"user_id":     *user.ID,
		})
		if err != nil {
			t.Errorf("error creating organisation for user id %s", *user.ID)
		}

		if org == nil {
			t.Errorf("no org created")
			return
		}

		appToken, err := appTokenFactory(string(*auth.Token.AccessToken), app.ID)
		if err != nil {
			t.Errorf("error getting app token. Error: %s", err.Error())
		}

		path := fmt.Sprintf("applications/%s/organizations", app.ID)
		status, _, err := provide.InitIdentService(appToken.Token).Post(path, map[string]interface{}{
			"organization_id": *org.ID,
		})
		if err != nil {
			t.Errorf("failed to create application organization; status: %v; %s", status, err.Error())
			return
		}
		if status != 204 {
			t.Errorf("invalid status returned from add org to app. expected 204, got %d", status)
		}

		listAppOrgs, err := provide.ListApplicationOrganizations(*appToken.Token, app.ID.String(), map[string]interface{}{})
		if err != nil {
			t.Errorf("error getting application organizations. Error: %s", err.Error())
		}

		orgFound := false
		for _, apporg := range listAppOrgs {
			if *apporg.Name == *org.Name {
				orgFound = true
			}
		}
		if orgFound == false {
			t.Errorf("application organization not found in list")
			return
		}
	}
}

func TestCreateApplicationOrganization(t *testing.T) {
	t.Parallel()
	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	// set up the user
	authUser := User{
		"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password",
	}

	user, err := userFactory(authUser.firstName, authUser.lastName, authUser.email, authUser.password)
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// get the auth token for the user
	auth, err := provide.Authenticate(authUser.email, authUser.password)
	if err != nil {
		t.Errorf("user authentication failed for user %s. error: %s", authUser.email, err.Error())
	}

	userApp := Application{
		"testApp1" + testId.String(), "testApp1Desc" + testId.String(),
	}

	app, err := provide.CreateApplication(string(*auth.Token.AccessToken), map[string]interface{}{
		"name":        userApp.name,
		"description": userApp.description,
		"user_id":     *user.ID,
	})
	if err != nil {
		t.Errorf("error creation application for user id %s", *user.ID)
	}

	if app == nil {
		t.Errorf("no application created")
		return
	}

	tt := []struct {
		name        string
		description string
	}{
		{"Org1" + testId.String(), "Org1 Description" + testId.String()},
		{"Org2" + testId.String(), "Org2 Description" + testId.String()},
	}

	for _, tc := range tt {

		did, err := didFactory()
		if err != nil {
			t.Errorf("did creation failed. error: %s", err.Error())
		}
		org, err := provide.CreateOrganization(string(*auth.Token.AccessToken), map[string]interface{}{
			"id":          did,
			"name":        tc.name,
			"description": tc.description,
			"user_id":     *user.ID,
		})
		if err != nil {
			t.Errorf("error creating organisation for user id %s", *user.ID)
		}

		if org == nil {
			t.Errorf("no org created")
			return
		}

		appToken, err := appTokenFactory(string(*auth.Token.AccessToken), app.ID)
		if err != nil {
			t.Errorf("error getting app token. Error: %s", err.Error())
		}

		path := fmt.Sprintf("applications/%s/organizations", app.ID)
		status, _, err := provide.InitIdentService(appToken.Token).Post(path, map[string]interface{}{
			"organization_id": *org.ID,
		})
		if err != nil {
			t.Errorf("failed to create application organization; status: %v; %s", status, err.Error())
			return
		}
		if status != 204 {
			t.Errorf("invalid status returned from add org to app. expected 204, got %d", status)
		}
	}
}

func UpdateApplicationOrganization(t *testing.T) {
	t.Parallel()
	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	// set up the user
	authUser := User{
		"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password",
	}

	user, err := userFactory(authUser.firstName, authUser.lastName, authUser.email, authUser.password)
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// get the auth token for the user
	auth, err := provide.Authenticate(authUser.email, authUser.password)
	if err != nil {
		t.Errorf("user authentication failed for user %s. error: %s", authUser.email, err.Error())
	}

	userApp := Application{
		"testApp1" + testId.String(), "testApp1Desc" + testId.String(),
	}

	app, err := provide.CreateApplication(string(*auth.Token.AccessToken), map[string]interface{}{
		"name":        userApp.name,
		"description": userApp.description,
		"user_id":     *user.ID,
	})
	if err != nil {
		t.Errorf("error creation application for user id %s", *user.ID)
	}

	if app == nil {
		t.Errorf("no application created")
		return
	}

	tt := []struct {
		name        string
		description string
	}{
		{"Org1" + testId.String(), "Org1 Description" + testId.String()},
		{"Org2" + testId.String(), "Org2 Description" + testId.String()},
	}

	for _, tc := range tt {

		did, err := didFactory()
		if err != nil {
			t.Errorf("did creation failed. error: %s", err.Error())
		}
		org, err := provide.CreateOrganization(string(*auth.Token.AccessToken), map[string]interface{}{
			"id":          did,
			"name":        tc.name,
			"description": tc.description,
			"user_id":     *user.ID,
		})
		if err != nil {
			t.Errorf("error creating organisation for user id %s", *user.ID)
		}

		if org == nil {
			t.Errorf("no org created")
			return
		}

		appToken, err := appTokenFactory(string(*auth.Token.AccessToken), app.ID)
		if err != nil {
			t.Errorf("error getting app token. Error: %s", err.Error())
		}

		path := fmt.Sprintf("applications/%s/organizations", app.ID)
		status, _, err := provide.InitIdentService(appToken.Token).Post(path, map[string]interface{}{
			"organization_id": *org.ID,
		})
		if err != nil {
			t.Errorf("failed to create application organization; status: %v; %s", status, err.Error())
			return
		}
		if status != 204 {
			t.Errorf("invalid status returned from add org to app. expected 204, got %d", status)
		}

		//update application organization
		path = fmt.Sprintf("applications/%s/organizations/%s", app.ID, *org.ID)
		status, _, err = provide.InitIdentService(appToken.Token).Put(path, map[string]interface{}{
			"organization_id": *org.ID,
		})
		if err != nil {
			t.Errorf("failed to update application organization; status: %v; %s", status, err.Error())
			return
		}
		if status != 501 {
			t.Errorf("invalid status returned from update org from app. expected 501 (not implemented), got %d", status)
		}
	}
}

func TestDeleteApplicationOrganizationWithApplicationAPIToken(t *testing.T) {
	t.Parallel()
	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	// set up the user
	authUser := User{
		"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password",
	}

	user, err := userFactory(authUser.firstName, authUser.lastName, authUser.email, authUser.password)
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// get the auth token for the user
	auth, err := provide.Authenticate(authUser.email, authUser.password)
	if err != nil {
		t.Errorf("user authentication failed for user %s. error: %s", authUser.email, err.Error())
	}

	userApp := Application{
		"testApp1" + testId.String(), "testApp1Desc" + testId.String(),
	}

	app, err := provide.CreateApplication(string(*auth.Token.AccessToken), map[string]interface{}{
		"name":        userApp.name,
		"description": userApp.description,
		"user_id":     *user.ID,
	})
	if err != nil {
		t.Errorf("error creation application for user id %s", *user.ID)
	}

	if app == nil {
		t.Errorf("no application created")
		return
	}

	tt := []struct {
		name        string
		description string
	}{
		{"Org1" + testId.String(), "Org1 Description" + testId.String()},
		{"Org2" + testId.String(), "Org2 Description" + testId.String()},
	}

	for _, tc := range tt {

		did, err := didFactory()
		if err != nil {
			t.Errorf("did creation failed. error: %s", err.Error())
		}
		org, err := provide.CreateOrganization(string(*auth.Token.AccessToken), map[string]interface{}{
			"id":          did,
			"name":        tc.name,
			"description": tc.description,
			"user_id":     *user.ID,
		})
		if err != nil {
			t.Errorf("error creating organisation for user id %s", *user.ID)
		}

		if org == nil {
			t.Errorf("no org created")
			return
		}

		appToken, err := appTokenFactory(string(*auth.Token.AccessToken), app.ID)
		if err != nil {
			t.Errorf("error getting app token. Error: %s", err.Error())
		}

		path := fmt.Sprintf("applications/%s/organizations", app.ID)
		status, _, err := provide.InitIdentService(appToken.Token).Post(path, map[string]interface{}{
			"organization_id": *org.ID,
		})
		if err != nil {
			t.Errorf("failed to create application organization; status: %v; %s", status, err.Error())
			return
		}
		if status != 204 {
			t.Errorf("invalid status returned from add org to app. expected 204, got %d", status)
		}

		err = provide.DeleteApplicationOrganization(*appToken.Token, app.ID.String(), *org.ID)
		if err != nil {
			t.Errorf("failed to delete application organization; status: %v; %s", status, err.Error())
			return
		}
	}
}

func TestCreateApplicationUser(t *testing.T) {
	t.Parallel()
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
			app, err = provide.CreateApplication(string(*auth.Token.AccessToken), map[string]interface{}{
				"name":        userApp.name,
				"description": userApp.description,
			})
			if err != nil {
				t.Errorf("error creation application for user id %s", *user.ID)
				return
			}

			if appToken == nil {
				// create a token for the application
				apptkn, err := appTokenFactory(*auth.Token.AccessToken, app.ID)
				if err != nil {
					t.Errorf("token creation failed for application id %s. error: %s", app.ID, err.Error())
					return
				}
				appToken = apptkn
			}
		} else {
			// let's add this user to the application as the creating user is automatically added...
			err := provide.CreateApplicationUser(*appToken.Token, app.ID.String(), map[string]interface{}{
				"user_id": *user.ID,
			})
			if err != nil {
				t.Errorf("failed to add user %s to application %s; %s", *user.ID, app.ID.String(), err.Error())
				return
			}
		}
	}
}

func TestUpdateApplicationUser(t *testing.T) {
	t.Parallel()
	t.Logf("not yet implemented")
}

func TestDeleteApplicationUserWithApplicationAPIToken(t *testing.T) {
	t.Parallel()
	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	userApp := Application{
		"App " + testId.String(),
		"App " + testId.String() + " Decription",
	}

	organizingUserEmail := "organizer" + testId.String() + "@email.com"
	organizingUser, err := userFactory("O", "User", organizingUserEmail, "testzxcv")
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// get the auth token
	auth, err := provide.Authenticate(organizingUserEmail, "testzxcv")
	if err != nil {
		t.Errorf("user authentication failed for user %s. error: %s", "o", err.Error())
		return
	}

	app, err := provide.CreateApplication(string(*auth.Token.AccessToken), map[string]interface{}{
		"name":        userApp.name,
		"description": userApp.description,
	})
	if err != nil {
		t.Errorf("error creation application for user id %s", *organizingUser.ID)
		return
	}

	// create a token for the application
	apptkn, err := appTokenFactory(*auth.Token.AccessToken, app.ID)
	if err != nil {
		t.Errorf("token creation failed for application id %s. error: %s", app.ID, err.Error())
		return
	}

	// create the user
	user, err := userFactory("App", "User", "appuser"+testId.String()+"@email.com", "asdf1234")
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// let's add this user to the application as the creating user is automatically added...
	err = provide.CreateApplicationUser(*apptkn.Token, app.ID.String(), map[string]interface{}{
		"user_id": *user.ID,
	})
	if err != nil {
		t.Errorf("failed to add user %s to application %s; %s", *user.ID, app.ID.String(), err.Error())
		return
	}

	//now we'll delete the user
	err = provide.DeleteApplicationUser(*apptkn.Token, app.ID.String(), *user.ID)
	if err != nil {
		t.Errorf("failed to delete user %s from application %s; %s", *user.ID, app.ID.String(), err.Error())
		return
	}

	users, err := provide.ListApplicationUsers(string(*apptkn.Token), app.ID.String(), map[string]interface{}{})
	if err != nil {
		t.Errorf("error getting users list %s", err.Error())
		return
	}
	if len(users) != 1 {
		t.Errorf("incorrect number of application users returned, expected 1, got %d", len(users))
	}
}
