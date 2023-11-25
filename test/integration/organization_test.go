//go:build integration || ident
// +build integration ident

/*
 * Copyright 2017-2022 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package integration

import (
	"testing"

	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideplatform/provide-go/api/ident"
)

func TestCreateOrganization(t *testing.T) {
	t.Parallel()
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
		org, err := provide.CreateOrganization(string(*auth.Token.AccessToken), map[string]interface{}{
			"name":        userOrg.name,
			"description": userOrg.description,
			"user_id":     user.ID,
		})
		if err != nil {
			t.Errorf("error creating organisation for user id %s", *user.ID)
		}

		if org == nil {
			t.Errorf("no org created")
			return
		}
	}
}

func TestListOrganizationTokens(t *testing.T) {
	t.Parallel()
	t.Logf("TBD no method in provide-go to list organization tokens")
}

func TestGetOrganizationDetailsWithAuthorizedUserToken(t *testing.T) {

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

	t.Logf("auth response: %+v", auth)
	// create an org...
	provide.CreateOrganization(string(*auth.Token.AccessToken), map[string]interface{}{
		"name":        "organiation name 1",
		"description": "organization description 1",
	})
	if err != nil {
		t.Errorf("error creation organization for user id %s", *user.ID)
	}

	// Create an organization we will fetch
	org, err := provide.CreateOrganization(string(*auth.Token.AccessToken), map[string]interface{}{
		"name":        "organiation name",
		"description": "organization description",
	})
	if err != nil {
		t.Errorf("error creation organization for user id %s", *user.ID)
		return
	}

	// create another org...
	provide.CreateOrganization(string(*auth.Token.AccessToken), map[string]interface{}{
		"name":        "organiation name 2",
		"description": "organization description 2",
	})
	if err != nil {
		t.Errorf("error creation organization for user id %s", *user.ID)
	}

	t.Logf("getting organisation details for org %s", *org.ID)
	deets, err := provide.GetOrganizationDetails(*auth.Token.AccessToken, *org.ID, map[string]interface{}{})
	if err != nil {
		t.Errorf("error getting organization details. Error: %s", err.Error())
		return
	}

	if deets.Name != nil {
		if *org.Name != *deets.Name {
			t.Errorf("Name mismatch. Expected %s, got %s", *org.Name, *deets.Name)
			return
		}

		if *org.Description != *deets.Description {
			t.Errorf("Description mismatch. Expected %s, got %s", *org.Description, *deets.Description)
			return
		}

		if *org.UserID != *deets.UserID {
			t.Errorf("UserID mismatch. Expected %s, got %s", *org.UserID, *deets.UserID)
			return
		}
	} else {
		t.Errorf("could not get organization details - org not returned")
	}
}

func TestOrganizationDetailsWithOrgToken(t *testing.T) {

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

	tt := []struct {
		name        string
		description string
		identifier  string
	}{
		{"org1" + testId.String(), "org1 desc" + testId.String(), ""},
		{"org2" + testId.String(), "org1 desc" + testId.String(), ""},
		{"org3" + testId.String(), "org1 desc" + testId.String(), ""},
		{"org4" + testId.String(), "org1 desc" + testId.String(), ""},
	}

	t.Logf("authy auth: %+v", auth)

	for counter, tc := range tt {
		// create the orgs all at once, because if we create them one at a time, we might not catch the bug (always returning latest org, maybe)
		org, err := provide.CreateOrganization(string(*auth.Token.AccessToken), map[string]interface{}{
			"name":        tc.name,
			"description": tc.description,
		})
		if err != nil {
			t.Errorf("error creation organization for user id %s", *user.ID)
		}
		t.Logf("orgy orgy: %+v", org)

		//assign the returned identifier to the test table
		tt[counter].identifier = *org.ID
	}

	for _, tc_deets := range tt {
		// get the org details
		t.Logf("getting organisation details for org %s", tc_deets.identifier)

		orgToken, err := orgTokenFactory(*auth.Token.AccessToken, tc_deets.identifier)
		if err != nil {
			t.Errorf("error generating org token for org %s", tc_deets.identifier)
		}

		deets, err := provide.GetOrganizationDetails(*orgToken.AccessToken, tc_deets.identifier, map[string]interface{}{})
		if err != nil {
			t.Errorf("error getting organization details. Error: %s", err.Error())
			return
		}

		if deets.Name != nil {
			if tc_deets.name != *deets.Name {
				t.Errorf("Name mismatch for org %s. Expected %s, got %s", tc_deets.identifier, tc_deets.name, *deets.Name)
				return
			}

			if tc_deets.description != *deets.Description {
				t.Errorf("Description mismatch for org %s. Expected %s, got %s", tc_deets.identifier, tc_deets.description, *deets.Description)
				return
			}
		} else {
			t.Errorf("could not get organization details for org %s - org not returned", tc_deets.identifier)
			return
		}
		t.Logf("org %s details ok", tc_deets.identifier)
	}
}

func TestOrganizationDetailsWithUserToken(t *testing.T) {

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

	tt := []struct {
		name        string
		description string
		identifier  string
	}{
		{"org1" + testId.String(), "org1 desc" + testId.String(), ""},
		{"org2" + testId.String(), "org1 desc" + testId.String(), ""},
		{"org3" + testId.String(), "org1 desc" + testId.String(), ""},
		{"org4" + testId.String(), "org1 desc" + testId.String(), ""},
	}

	for counter, tc := range tt {
		// create the orgs all at once, because if we create them one at a time, we might not catch the bug (always returning latest org, maybe)
		org, err := provide.CreateOrganization(string(*auth.Token.AccessToken), map[string]interface{}{
			"name":        tc.name,
			"description": tc.description,
		})
		if err != nil {
			t.Errorf("error creation organization for user id %s", *user.ID)
		}
		//assign the returned identifier to the test table
		tt[counter].identifier = *org.ID
	}

	for _, tc_deets := range tt {
		// get the org details
		t.Logf("getting organisation details for org %s", tc_deets.identifier)

		deets, err := provide.GetOrganizationDetails(*auth.Token.AccessToken, tc_deets.identifier, map[string]interface{}{})
		if err != nil {
			t.Errorf("error getting organization details. Error: %s", err.Error())
			return
		}

		if deets.Name != nil {
			if tc_deets.name != *deets.Name {
				t.Errorf("Name mismatch for org %s. Expected %s, got %s", tc_deets.identifier, tc_deets.name, *deets.Name)
				return
			}

			if tc_deets.description != *deets.Description {
				t.Errorf("Description mismatch for org %s. Expected %s, got %s", tc_deets.identifier, tc_deets.description, *deets.Description)
				return
			}
		} else {
			t.Errorf("could not get organization details for org %s - org not returned", tc_deets.identifier)
			return
		}
		t.Logf("org %s details ok", tc_deets.identifier)
	}
}

func TestUpdateOrganizationDetails(t *testing.T) {
	t.Parallel()
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

	// Create an Organization for that org
	org, err := provide.CreateOrganization(string(*auth.Token.AccessToken), map[string]interface{}{
		"name":        "org name",
		"description": "org description",
	})
	if err != nil {
		t.Errorf("error creation organization for user id %s", *user.ID)
	}

	if org == nil {
		t.Errorf("no organization created")
		return
	}

	updatedName := "org nane " + testId.String()
	updatedDescription := "org description " + testId.String()

	err = provide.UpdateOrganization(string(*auth.Token.AccessToken), *org.ID, map[string]interface{}{
		"name":        updatedName,
		"description": updatedDescription,
	})
	if err != nil {
		t.Errorf("error updating organization details. Error: %s", err.Error())
	}

	// FIXME, or rather when the code is updated to enable user org tokens, this will return the right org
	deets, err := provide.GetOrganizationDetails(*auth.Token.AccessToken, *org.ID, map[string]interface{}{})
	if err != nil {
		t.Errorf("error getting organization details. Error: %s", err.Error())
		return
	}

	if deets.Name == nil {
		t.Errorf("no org returned")
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

	if *org.UserID != *deets.UserID {
		t.Errorf("UserID mismatch. Expected %s, got %s", *org.UserID, *deets.UserID)
		return
	}
}

// CHECKME this test will check if I can view the organization details
// by a user who has nothing to do with the organization
// assumption is that they shouldn't be able to read the organization details
func TestFetchOrgDetailsFailsWithUnauthorizedUser(t *testing.T) {
	t.Parallel()
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
		"first", "last.notauth", "first.last.notauth" + testId.String() + "@email.com", "secrit_password",
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
		org, err := provide.CreateOrganization(string(*auth.Token.AccessToken), map[string]interface{}{
			"name":        tc.name,
			"description": tc.description,
			"user_id":     user.ID,
		})
		if err != nil {
			t.Errorf("error creation organization for user id %s", *user.ID)
		}

		if org == nil {
			t.Errorf("no organization created")
			return
		}

		_, err = provide.GetOrganizationDetails(*nonAuth.Token.AccessToken, *org.ID, map[string]interface{}{})
		if err == nil {
			t.Errorf("expected error getting organization details by a user not associated with the organization")
			return
		}
	}
}

// TODO-- TestUserUpdateOrgDetailsAccess
// func TestUserUpdateOrgDetailsAccess(t *testing.T) {}

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
// 			t.Errorf("error creation organization for user id %s", *user.ID)
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

// TODO-- TestDeleteOrganization
// func TestDeleteOrganization(t *testing.T) {}

//CHECKME - need to add to provide-go
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
// 		token, err := orgTokenFactory(*auth.Token.Token, org.ID.String())
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
	t.Parallel()
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
			org, err = provide.CreateOrganization(string(*auth.Token.AccessToken), map[string]interface{}{
				"name":        userOrg.name,
				"description": userOrg.description,
			})
			if err != nil {
				t.Errorf("error creation organization for user id %s", *user.ID)
				return
			}
		} else {
			// let's add this user to the organization as the creating user is automatically added...
			err := provide.CreateOrganizationUser(*organizingUserToken.AccessToken, *org.ID, map[string]interface{}{
				"user_id": user.ID,
			})
			if err != nil {
				t.Errorf("failed to add user %s to organization %s; %s", *user.ID, *org.ID, err.Error())
				return
			}

			listOrgUsers, err := provide.ListOrganizationUsers(string(*organizingUserToken.AccessToken), *org.ID, map[string]interface{}{})
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
	t.Parallel()
	t.Logf("TBD not yet implemented in code")
}

func TestListApplicationOrganizationUsers(t *testing.T) {
	t.Parallel()
	t.Logf("test not implemented yet")
}
