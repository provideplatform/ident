// +build integration

package integration

import (
	"testing"

	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideservices/provide-go/api/ident"
)

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

// users must have sufficient permission on the organization to create and list users...
// an org token does not current grant access to the list of users-- it is more intended
// to be a programmatic api token for interacting with organization-owned resources *without*
// undermining the privacy of users who may be part of the organization...
func TestListOrganizationUsers(t *testing.T) {

	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	// t.Logf("*** test list users *** using testid %s", testId)

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

	var org *provide.Organization
	var organizingUserToken *provide.Token

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

		if organizingUserToken == nil {
			organizingUserToken = auth.Token
		}

		// Create an Organization if it doesn't exist
		if org == nil {
			org, err = provide.CreateOrganization(string(*auth.Token.Token), map[string]interface{}{
				"name":        userOrg.name,
				"description": userOrg.description,
			})
			if err != nil {
				t.Errorf("error creation organization for user id %s", user.ID)
				return
			}
		} else {
			// let's add this user to the organization as the creating user is automatically added...
			err := provide.CreateOrganizationUser(*organizingUserToken.Token, org.ID.String(), map[string]interface{}{
				"user_id": user.ID.String(),
			})
			if err != nil {
				t.Errorf("failed to add user %s to organization %s; %s", user.ID, org.ID.String(), err.Error())
				return
			}
		}
	}

	users, err := provide.ListOrganizationUsers(string(*organizingUserToken.Token), org.ID.String(), map[string]interface{}{})
	if err != nil {
		t.Errorf("error getting organization users list %s", err.Error())
	}
	if len(users) != len(tt) {
		t.Errorf("incorrect number of organization users returned, expected %d, got %d", len(tt), len(users))
	}
	t.Logf("got correct number of organization users back %d", len(users))
}

func TestListOrganizationTokens(t *testing.T) {
	t.Errorf("no method in provide-go to list organization tokens")
}

func TestGetOrganizationDetails(t *testing.T) {

	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	type User struct {
		firstName string
		lastName  string
		email     string
		password  string
	}

	authUser := User{
		"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password",
	}

	tt := []struct {
		name        string
		description string
	}{
		{"Org1" + testId.String(), "Org1 Description" + testId.String()},
		{"Org2" + testId.String(), "Org2 Description" + testId.String()},
	}

	// set up the user that will create the organization
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

		// Create an Organization for that org
		org, err := provide.CreateOrganization(string(*auth.Token.Token), map[string]interface{}{
			"name":        tc.name,
			"description": tc.description,
		})
		if err != nil {
			t.Errorf("error creation organization for user id %s", user.ID)
		}

		if org == nil {
			t.Errorf("no organization created")
			return
		}

		deets, err := provide.GetOrganizationDetails(*auth.Token.Token, org.ID.String(), map[string]interface{}{})
		if err != nil {
			t.Errorf("error getting organization details. Error: %s", err.Error())
			return
		}

		if *org.Name != *deets.Name {
			t.Errorf("Name mismatch. Expected %s, got %s", *org.Name, *deets.Name)
			return
		}

		if *org.Description != *deets.Description {
			t.Errorf("Description mismatch. Expected %s, got %s", *org.Description, *deets.Description)
			return
		}

		if org.UserID.String() != deets.UserID.String() {
			t.Errorf("UserID mismatch. Expected %s, got %s", org.UserID.String(), deets.UserID.String())
			return
		}
	}
}

func TestUpdateOrganizationDetails(t *testing.T) {

	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	type User struct {
		firstName string
		lastName  string
		email     string
		password  string
	}

	authUser := User{
		"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password",
	}

	tt := []struct {
		name        string
		description string
	}{
		{"Org1" + testId.String(), "Org1 Description" + testId.String()},
		{"Org2" + testId.String(), "Org2 Description" + testId.String()},
	}

	// set up the user that will create the organization
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

	// loop through orgs and create, and update them
	for _, tc := range tt {

		// Create an Organization for that org
		org, err := provide.CreateOrganization(string(*auth.Token.Token), map[string]interface{}{
			"name":        tc.name,
			"description": tc.description,
			"user_id":     user.ID,
		})
		if err != nil {
			t.Errorf("error creation organization for user id %s", user.ID)
		}

		if org == nil {
			t.Errorf("no organization created")
			return
		}

		updatedName := tc.name + testId.String()
		updatedDescription := tc.description + testId.String()

		err = provide.UpdateOrganization(string(*auth.Token.Token), org.ID.String(), map[string]interface{}{
			"name":        updatedName,
			"description": updatedDescription,
		})
		if err != nil {
			t.Errorf("error updating organization details. Error: %s", err.Error())
		}

		deets, err := provide.GetOrganizationDetails(*auth.Token.Token, org.ID.String(), map[string]interface{}{})
		if err != nil {
			t.Errorf("error getting organization details. Error: %s", err.Error())
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

		if org.UserID.String() != deets.UserID.String() {
			t.Errorf("UserID mismatch. Expected %s, got %s", org.UserID.String(), deets.UserID.String())
			return
		}
	}
}

// CHECKME this test will check if I can view the organization details
// by a user who has nothing to do with the organization
// assumption is that they shouldn't be able to read the organization details
func TestFetchOrgDetailsFailsWithUnauthorizedUser(t *testing.T) {

	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	type User struct {
		firstName string
		lastName  string
		email     string
		password  string
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
		{"Org1" + testId.String(), "Org1 Description" + testId.String()},
		{"Org2" + testId.String(), "Org2 Description" + testId.String()},
	}

	// set up the user that will create the organization
	user, err := userFactory(authUser.firstName, authUser.lastName, authUser.email, authUser.password)
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// set up a user that will have nothing to do with the organization
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

	// get the auth token for the non organization user
	nonAuth, err := provide.Authenticate(nonAuthUser.email, nonAuthUser.password)
	if err != nil {
		t.Errorf("user authentication failed for user %s. error: %s", nonAuthUser.email, err.Error())
	}

	for _, tc := range tt {

		// Create an Organization for that org
		org, err := provide.CreateOrganization(string(*auth.Token.Token), map[string]interface{}{
			"name":        tc.name,
			"description": tc.description,
			"user_id":     user.ID,
		})
		if err != nil {
			t.Errorf("error creation organization for user id %s", user.ID)
		}

		if org == nil {
			t.Errorf("no organization created")
			return
		}

		_, err = provide.GetOrganizationDetails(*nonAuth.Token.Token, org.ID.String(), map[string]interface{}{})
		if err == nil {
			t.Errorf("expected error getting organization details by a user not associated with the organization")
			return
		}
	}
}

func TestUserUpdateOrgDetailsAccess(t *testing.T) {
	t.Logf("update org details not yet implemented")
}

// CHECKME this test will check if I can update the organization details
// by a user who has nothing to do with the organization
// assumption is that they shouldn't be able to update the organization details
// UPDATE: also returns 501, so not yet implemented,
// func TestUserUpdateOrgDetailsAccess(t *testing.T) {

// 	testId, err := uuid.NewV4()
// 	if err != nil {
// 		t.Logf("error creating new UUID")
// 	}

// 	type User struct {
// 		firstName string
// 		lastName  string
// 		email     string
// 		password  string
// 	}

// 	authUser := User{
// 		"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password",
// 	}

// 	nonAuthUser := User{
// 		"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password",
// 	}

// 	tt := []struct {
// 		name        string
// 		description string
// 	}{
// 		{"Org1" + testId.String(), "Org1 Description" + testId.String()},
// 		{"Org2" + testId.String(), "Org2 Description" + testId.String()},
// 	}

// 	// set up the user that will create the organization
// 	user, err := userFactory(authUser.firstName, authUser.lastName, authUser.email, authUser.password)
// 	if err != nil {
// 		t.Errorf("user creation failed. Error: %s", err.Error())
// 		return
// 	}

// 	// set up a user that will have nothing to do with the organization
// 	nonUser, err := userFactory(nonAuthUser.firstName, nonAuthUser.lastName, nonAuthUser.email, nonAuthUser.password)
// 	if err != nil {
// 		t.Errorf("user creation failed. Error: %s", err.Error())
// 		return
// 	}

// 	// get the auth token for the auth user
// 	auth, err := provide.Authenticate(authUser.email, authUser.password)
// 	if err != nil {
// 		t.Errorf("user authentication failed for user %s. error: %s", authUser.email, err.Error())
// 	}

// 	// get the auth token for the non organization user
// 	nonAuth, err := provide.Authenticate(nonAuthUser.email, nonAuthUser.password)
// 	if err != nil {
// 		t.Errorf("user authentication failed for user %s. error: %s", nonAuthUser.email, err.Error())
// 	}

// 	for _, tc := range tt {

// 		// Create an Organization for that org
// 		org, err := provide.CreateOrganization(string(*auth.Token.Token), map[string]interface{}{
// 			"name":        tc.name,
// 			"description": tc.description,
// 			"user_id":     user.ID,
// 		})
// 		if err != nil {
// 			t.Errorf("error creation organization for user id %s", user.ID)
// 		}

// 		if org == nil {
// 			t.Errorf("no organization created")
// 			return
// 		}

// 		updatedName := tc.name + testId.String()
// 		updatedDescription := tc.description + testId.String()

// 		err = provide.UpdateOrganization(*nonAuth.Token.Token, org.ID.String(), map[string]interface{}{
// 			"name":        updatedName,
// 			"description": updatedDescription,
// 			"user_id":     nonUser.ID,
// 		})
// 		if err == nil {
// 			t.Errorf("expected error updating organization details by a user not associated with the organization")
// 		}

// 		deets, err := provide.GetOrganizationDetails(*auth.Token.Token, org.ID.String(), map[string]interface{}{})
// 		if err != nil {
// 			t.Errorf("error getting organization details. Error: %s", err.Error())
// 			return
// 		}

// 		// double check if they're updated (no return on UpdateApplication error above so we get to run this code)
// 		if *deets.Name == updatedName {
// 			t.Errorf("Name updated by non-Organization user!. Expected %s, got %s", *org.Name, *deets.Name)
// 			return
// 		}

// 		if *deets.Description == updatedDescription {
// 			t.Errorf("Description updated by non-Organization user! Expected %s, got %s", *org.Description, *deets.Description)
// 			return
// 		}

// 		if deets.UserID.String() != org.UserID.String() {
// 			t.Errorf("UserID updated by non-Organization user! Expected %s, got %s", org.UserID.String(), deets.UserID.String())
// 			return
// 		}
// 	}
// }

func TestDeleteOrganization(t *testing.T) {
	// FIXME if the magic elves can add a DeleteOrganization to provide-go, I will put out a saucer of milk tonight
	// note the saucer of milk still applies, even if it's a soft delete behind the scenes in the handlers, although
	// then a recover method might also be needed (unless this is all the same as updating with Hidden set to true/false)
	t.Errorf("provide-go method missing")
}

// func TestListOrganizationTokens(t *testing.T) {
// 	testId, err := uuid.NewV4()
// 	if err != nil {
// 		t.Logf("error creating new UUID")
// 	}

// 	authUser := User{"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password"}

// 	testOrg := Organization{"Org1" + testId.String(), "Org1 Description" + testId.String()}

// 	// set up the user that will create the application
// 	_, err = userFactory(authUser.firstName, authUser.lastName, authUser.email, authUser.password)
// 	if err != nil {
// 		t.Errorf("user creation failed. Error: %s", err.Error())
// 		return
// 	}

// 	// get the auth token for the auth user
// 	auth, err := provide.Authenticate(authUser.email, authUser.password)
// 	if err != nil {
// 		t.Errorf("user authentication failed for user %s. error: %s", authUser.email, err.Error())
// 	}

// 	org, err := provide.CreateOrganization(*auth.Token.Token, map[string]interface{}{
// 		"name":        testOrg.name,
// 		"description": testOrg.description,
// 	})
// 	if err != nil {
// 		t.Errorf("error creating organization. Error: %s", err.Error())
// 		return
// 	}

// 	const tokenCount = 5
// 	var createdTokens [tokenCount]provide.Token

// 	for looper := 0; looper < tokenCount; looper++ {
// 		token, err := orgTokenFactory(*auth.Token.Token, org.ID)
// 		if err != nil {
// 			t.Errorf("error creating org token")
// 			return
// 		}
// 		createdTokens[looper] = *token
// 	}

// 	listOfTokens, err := provide.ListOrganizationTokens(*auth.Token.Token, org.ID.String(), map[string]interface{}{})
// 	if err != nil {
// 		t.Errorf("error getting list of organization tokens. Error: %s", err.Error())
// 		return
// 	}

// 	if len(listOfTokens) != tokenCount {
// 		t.Errorf("incorrect number of application tokens returned.  Expected %d, got %d", tokenCount, len(listOfTokens))
// 		return
// 	}
// 	// hard to check these without a bunch of code to iterate through everything. I'm looking at
// 	// writing something, but this will do for now.
// }

func TestCreateOrganizationUser(t *testing.T) {

	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	// t.Logf("*** test list users *** using testid %s", testId)

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

	var org *provide.Organization
	var organizingUserToken *provide.Token

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

		if organizingUserToken == nil {
			organizingUserToken = auth.Token
		}

		// Create an Organization if it doesn't exist
		if org == nil {
			org, err = provide.CreateOrganization(string(*auth.Token.Token), map[string]interface{}{
				"name":        userOrg.name,
				"description": userOrg.description,
			})
			if err != nil {
				t.Errorf("error creation organization for user id %s", user.ID)
				return
			}
		} else {
			// let's add this user to the organization as the creating user is automatically added...
			err := provide.CreateOrganizationUser(*organizingUserToken.Token, org.ID.String(), map[string]interface{}{
				"user_id": user.ID.String(),
			})
			if err != nil {
				t.Errorf("failed to add user %s to organization %s; %s", user.ID, org.ID.String(), err.Error())
				return
			}

			listOrgUsers, err := provide.ListOrganizationUsers(string(*organizingUserToken.Token), org.ID.String(), map[string]interface{}{})
			if err != nil {
				t.Errorf("error getting organization users list %s", err.Error())
			}

			userFound := false
			for _, orguser := range listOrgUsers {
				if orguser.Name == user.Name {
					userFound = true
				}
			}
			if userFound == false {
				t.Errorf("organization user not found in list")
				return
			}
		}
	}
}

func TestUpdateOrganizationUser(t *testing.T) {

	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	// t.Logf("*** test list users *** using testid %s", testId)

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

	var org *provide.Organization
	var organizingUserToken *provide.Token

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

		if organizingUserToken == nil {
			organizingUserToken = auth.Token
		}

		// Create an Organization if it doesn't exist
		if org == nil {
			org, err = provide.CreateOrganization(string(*auth.Token.Token), map[string]interface{}{
				"name":        userOrg.name,
				"description": userOrg.description,
			})
			if err != nil {
				t.Errorf("error creation organization for user id %s", user.ID)
				return
			}
		} else {
			// let's add this user to the organization as the creating user is automatically added...
			err := provide.CreateOrganizationUser(*organizingUserToken.Token, org.ID.String(), map[string]interface{}{
				"user_id": user.ID.String(),
			})
			if err != nil {
				t.Errorf("failed to add user %s to organization %s; %s", user.ID, org.ID.String(), err.Error())
				return
			}

			err = provide.UpdateOrganizationUser(*organizingUserToken.Token, org.ID.String(), map[string]interface{}{
				"user_id": user.ID.String(),
			})
			if err != nil {
				t.Errorf("error updating org user. Error: %s", err.Error())
			}
		}
	}
}

func TestDeleteOrganizationUser(t *testing.T) {

	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	// t.Logf("*** test list users *** using testid %s", testId)

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

	var org *provide.Organization
	var organizingUserToken *provide.Token

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

		if organizingUserToken == nil {
			organizingUserToken = auth.Token
		}

		// Create an Organization if it doesn't exist
		if org == nil {
			org, err = provide.CreateOrganization(string(*auth.Token.Token), map[string]interface{}{
				"name":        userOrg.name,
				"description": userOrg.description,
			})
			if err != nil {
				t.Errorf("error creation organization for user id %s", user.ID)
				return
			}
		} else {
			// let's add this user to the organization as the creating user is automatically added...
			err := provide.CreateOrganizationUser(*organizingUserToken.Token, org.ID.String(), map[string]interface{}{
				"user_id": user.ID.String(),
			})
			if err != nil {
				t.Errorf("failed to add user %s to organization %s; %s", user.ID, org.ID.String(), err.Error())
				return
			}

			err = provide.DeleteOrganizationUser(*organizingUserToken.Token, org.ID.String(), user.ID.String())
			if err != nil {
				t.Errorf("error deleting organization user; %s", err.Error())
				return
			}
		}

		orgUsers, err := provide.ListOrganizationUsers(*organizingUserToken.Token, org.ID.String(), map[string]interface{}{})
		if err != nil {
			t.Errorf("error listing organization users; %s", err.Error())
			return
		}

		if len(orgUsers) != 1 {
			// the original user still exists...
			t.Errorf("deleting organization users failed; expected 1, got %d", len(orgUsers))
			return
		}
	}
}

func TestListApplicationOrganizationUsers(t *testing.T) {
	t.Errorf("test not implemented yet")
}

func TestListOrganizationUsersByOrgUser(t *testing.T) {

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
		{"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password"},
		{"joey", "joe joe", "j.j" + testId.String() + "@email.com", "joeyjoejoe"},
		{"joey2", "joe joe2", "j.j2" + testId.String() + "@email.com", "joeyjoejoe2"},
	}

	var org *provide.Organization
	var organizingUserToken *provide.Token
	var organizationUserToken *provide.Token

	for _, tc := range tt {
		// create the organizing user
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

		if organizingUserToken != nil {
			organizationUserToken = auth.Token
		}
		// we want to set this up for the first user only
		if organizingUserToken == nil {
			organizingUserToken = auth.Token
		}

		// Create an Organization if it doesn't exist
		if org == nil {
			org, err = provide.CreateOrganization(string(*auth.Token.Token), map[string]interface{}{
				"name":        userOrg.name,
				"description": userOrg.description,
			})
			if err != nil {
				t.Errorf("error creation organization for user id %s", user.ID)
				return
			}
			t.Logf("*** created org %s with organizing user %s", org.ID.String(), user.ID.String())
		} else {
			// let's add this user to the organization as the creating user is automatically added...
			err := provide.CreateOrganizationUser(*organizingUserToken.Token, org.ID.String(), map[string]interface{}{
				"user_id": user.ID.String(),
			})
			if err != nil {
				t.Errorf("failed to add user %s to organization %s; %s", user.ID, org.ID.String(), err.Error())
				return
			}
			t.Logf("*** created user %s for org %s", user.ID.String(), org.ID.String())
		}
	}

	// CHECKME - so according to the rules in the comment above,
	// the organizing user
	users, err := provide.ListOrganizationUsers(string(*organizingUserToken.Token), org.ID.String(), map[string]interface{}{})
	if err != nil {
		t.Errorf("error getting organization users list %s", err.Error())
		return
	}
	if len(users) != len(tt) {
		t.Errorf("incorrect number of organization users returned, expected %d, got %d", len(tt), len(users))
		return
	}
	t.Logf("got correct number of organization users back %d using organizing user", len(users))

	// now we will try and list the users with a regular user token
	users, err = provide.ListOrganizationUsers(string(*organizationUserToken.Token), org.ID.String(), map[string]interface{}{})
	if err != nil {
		t.Errorf("error getting organization users list %s", err.Error())
		return
	}
	if len(users) == len(tt) {
		t.Errorf("got list of organization users by regular organization user, expected 0")
		return
	}
	t.Logf("got empty list of organization users back using organization user")
}

func TestListOrganizationUsersWithNoUsersInOrg(t *testing.T) {

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
		{"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password"},
		{"joey", "joe joe", "j.j" + testId.String() + "@email.com", "joeyjoejoe"},
		{"joey2", "joe joe2", "j.j2" + testId.String() + "@email.com", "joeyjoejoe2"},
	}

	var org *provide.Organization
	var organizingUserToken *provide.Token

	for _, tc := range tt {
		// create the organizing user
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

		if organizingUserToken == nil {
			organizingUserToken = auth.Token
		}

		// Create an Organization if it doesn't exist
		if org == nil {
			org, err = provide.CreateOrganization(string(*auth.Token.Token), map[string]interface{}{
				"name":        userOrg.name,
				"description": userOrg.description,
			})
			if err != nil {
				t.Errorf("error creation organization for user id %s", user.ID)
				return
			}
			t.Logf("*** created org %s with organizing user %s", org.ID.String(), user.ID.String())
		} else {
			// do nothing, we don't want to create any organization users
		}
	}

	// CHECKME - so according to the rules in the comment above,
	// the organizing user doesn't necessarily have list user rights, so they shouldn't even see themselves...
	users, err := provide.ListOrganizationUsers(string(*organizingUserToken.Token), org.ID.String(), map[string]interface{}{})
	if err != nil {
		t.Errorf("error getting organization users list %s", err.Error())
		return
	}
	if len(users) != 0 {
		t.Errorf("incorrect number of organization users returned, expected 0, got %d", len(users))
		return
	}
	t.Logf("got correct number of organization users back %d using organizing user", len(users))
}

func TestListOrganizationUsersWithNoUsers(t *testing.T) {

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
		{"first", "last", "first.last." + testId.String() + "@email.com", "secrit_password"},
	}

	var org *provide.Organization
	var organizingUserToken *provide.Token

	for _, tc := range tt {
		// create the organizing user
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

		// we want to set this up for the first user only
		if organizingUserToken == nil {
			organizingUserToken = auth.Token
		}

		// Create an Organization if it doesn't exist
		if org == nil {
			org, err = provide.CreateOrganization(string(*organizingUserToken.Token), map[string]interface{}{
				"name":        userOrg.name,
				"description": userOrg.description,
			})
			if err != nil {
				t.Errorf("error creation organization for user id %s", user.ID)
				return
			}
			t.Logf("*** created org %s with organizing user %s", org.ID.String(), user.ID.String())
		} else {
			// do nothing
		}

		// now we'll delete the organization user
		// and try to list users
		err = provide.DeleteOrganizationUser(*organizingUserToken.Token, org.ID.String(), user.ID.String())
		if err != nil {
			t.Errorf("error deleting organization user. Error: %s", err.Error())
		}

		// CHECKME - damn, still getting a panic here
		//
		users, err := provide.ListOrganizationUsers(string(*organizingUserToken.Token), org.ID.String(), map[string]interface{}{})
		if err != nil {
			t.Errorf("error getting organization users list %s", err.Error())
			return
		}
		if len(users) != 0 {
			t.Errorf("incorrect number of organization users returned, expected 0, got %d", len(users))
			return
		}
		t.Logf("got correct number of organization users back (0) using removedorganizing user")
	}
}
