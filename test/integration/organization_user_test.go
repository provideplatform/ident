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

func TestDeleteOrganizationUser(t *testing.T) {
	t.Parallel()
	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	ou := User{
		"org (setup) " + testId.String(),
		"user " + testId.String(),
		"o.u." + testId.String() + "@email.com",
		"secrit_password",
	}

	app := Application{
		"App " + testId.String(),
		"App " + testId.String() + " Decription",
	}

	org := Organization{
		"Org " + testId.String(),
		"Org " + testId.String() + " Decription",
	}

	users := []struct {
		firstName string
		lastName  string
		email     string
		password  string
		userID    string
	}{
		{"joey", "joe joe", "j.j" + testId.String() + "@email.com", "secrit_password", ""},
		{"joey2", "joe joe2", "j.j2" + testId.String() + "@email.com", "secrit_password", ""},
		{"joey3", "joe joe3", "j.j3" + testId.String() + "@email.com", "secrit_password", ""},
		{"joey4", "joe joe4", "j.j4" + testId.String() + "@email.com", "secrit_password", ""},
		{"joey5", "joe joe5", "j.j5" + testId.String() + "@email.com", "secrit_password", ""},
		{"joey6", "joe joe6", "j.j6" + testId.String() + "@email.com", "secrit_password", ""},
		{"joey6", "joe joe7", "j.j7" + testId.String() + "@email.com", "secrit_password", ""},
		{"joey8", "joe joe8", "j.j8" + testId.String() + "@email.com", "secrit_password", ""},
		{"joey9", "joe joe9", "j.j9" + testId.String() + "@email.com", "secrit_password", ""},
		{"joey10", "joe joe10", "j.j10" + testId.String() + "@email.com", "secrit_password", ""},
	}

	// create organizing user
	_, err = userFactory(ou.firstName, ou.lastName, ou.email, ou.password)
	if err != nil {
		t.Errorf("organizing user %s creation failed. Error: %s", ou.email, err.Error())
		return
	}
	//t.Logf("created organizing user %s with email %s", organizingUser.ID.String(), ou.email)

	// authenticate organizing user
	ouAuth, err := provide.Authenticate(ou.email, ou.password)
	if err != nil {
		t.Errorf("authentication failed for organizing user %s. error: %s", ou.email, err.Error())
		return
	}
	//t.Logf("authenticated organizing user %s", organizingUser.ID.String())
	ouToken := ouAuth.Token.AccessToken

	// create application
	Application, err := appFactory(*ouToken, app.name, app.description)
	if err != nil {
		t.Errorf("error creating application %s. Error: %s", app.name, err.Error())
		return
	}
	//t.Logf("created application %s", Application.ID.String())

	// create organization
	Organization, err := orgFactory(*ouToken, org.name, org.description)
	if err != nil {
		t.Errorf("error creating organization %s. Error: %s", org.name, err.Error())
		return
	}
	//t.Logf("created organization %s", *Organization.ID)

	// get an app token
	appToken, err := appTokenFactory(*ouToken, Application.ID.String())
	if err != nil {
		t.Errorf("error getting app token for application %s. Error: %s", Application.ID, err.Error())
		return
	}

	orgToken, err := orgTokenFactory(*ouToken, *Organization.ID)
	if err != nil {
		t.Errorf("error getting org token for organization %s. Error: %s", *Organization.ID, err.Error())
		return
	}
	// associate org to app, using the app token
	err = apporgFactory(*appToken.AccessToken, Application.ID.String(), *Organization.ID)
	if err != nil {
		t.Errorf("error associating org %s to app %s", *Organization.ID, Application.ID)
		return
	}
	//t.Logf("associated org %s to app %s", Organization.ID, Application.ID)

	// now we'll set up the org users
	for counter, tc := range users {
		// add the users to the organization
		organizationUser, err := userFactory(tc.firstName, tc.lastName, tc.email, tc.password)
		if err != nil {
			t.Errorf("user creation failed. Error: %s", err.Error())
			return
		}
		//t.Logf("created user %s", *organizationUser.ID)

		err = provide.CreateOrganizationUser(*ouToken, *Organization.ID, map[string]interface{}{
			"user_id": *organizationUser.ID,
		})
		if err != nil {
			t.Errorf("failed to add user %s to organization %s; %s", *organizationUser.ID, *Organization.ID, err.Error())
			return
		}
		//t.Logf("created user %s for org %s", *organizationUser.ID, *Organization.ID)
		users[counter].userID = *organizationUser.ID
	}

	// now we'll do stuff and stuff with them...

	//1. let's try deleting an app org user with an app token
	err = provide.DeleteOrganizationUser(*appToken.AccessToken, *Organization.ID, users[0].userID)
	if err != nil {
		t.Errorf("error deleting organization user %s with app token. Error: %s", users[0].userID, err.Error())
		return
	}

	//2. let's try deleting an app org user with an org token
	err = provide.DeleteOrganizationUser(*orgToken.AccessToken, *Organization.ID, users[1].userID)
	if err != nil {
		t.Errorf("error deleting organization user %s with org token. Error: %s", users[1].userID, err.Error())
		return
	}

	//3 let's try a user deleting themselves from the org using their own token
	delAuth, err := provide.Authenticate(users[2].email, users[2].password)
	if err != nil {
		t.Errorf("authentication failed for organizing user %s. error: %s", users[2].email, err.Error())
		return
	}

	err = provide.DeleteOrganizationUser(*delAuth.Token.AccessToken, *Organization.ID, users[2].userID)
	if err != nil {
		t.Errorf("error deleting organization user %s with org token. Error: %s", users[2].userID, err.Error())
		return
	}
}

func TestListOrganizationUsersWithNoUsersInOrg(t *testing.T) {
	t.Parallel()
	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	ou := User{
		"org (setup) " + testId.String(),
		"user " + testId.String(),
		"o.u." + testId.String() + "@email.com",
		"secrit_password",
	}

	org := Organization{
		"Org " + testId.String(),
		"Org " + testId.String() + " Decription",
	}

	// create organizing user
	orgUser, err := userFactory(ou.firstName, ou.lastName, ou.email, ou.password)
	if err != nil {
		t.Errorf("organizing user %s creation failed. Error: %s", ou.email, err.Error())
		return
	}
	//t.Logf("created organizing user %s with email %s", organizingUser.ID.String(), ou.email)

	// authenticate organizing user
	ouAuth, err := provide.Authenticate(ou.email, ou.password)
	if err != nil {
		t.Errorf("authentication failed for organizing user %s. error: %s", ou.email, err.Error())
		return
	}
	//t.Logf("authenticated organizing user %s", organizingUser.ID.String())
	ouToken := ouAuth.Token.AccessToken

	// create organization
	Organization, err := orgFactory(*ouToken, org.name, org.description)
	if err != nil {
		t.Errorf("error creating organization %s. Error: %s", org.name, err.Error())
		return
	}
	//t.Logf("created organization %s", *Organization.ID)

	orgToken, err := orgTokenFactory(*ouToken, *Organization.ID)
	if err != nil {
		t.Errorf("error getting org token for organization %s. Error: %s", *Organization.ID, err.Error())
		return
	}

	//now let's remove the setup user
	err = provide.DeleteOrganizationUser(*ouToken, *Organization.ID, *orgUser.ID)
	if err != nil {
		t.Errorf("Error deleting user %s for org %s", *orgUser.ID, *Organization.ID)
	}

	users, err := provide.ListOrganizationUsers(*orgToken.AccessToken, *Organization.ID, map[string]interface{}{})
	if err != nil {
		t.Errorf("error getting organization users list %s", err.Error())
		return
	}

	// we should only get no users back.
	if len(users) != 0 {
		t.Errorf("incorrect number of organization users returned, expected 0, got %d", len(users))
		return
	}
	t.Logf("got correct number of organization users back %d using org token", len(users))
}

func TestListOrganizationUsersUsingOrganizingUser(t *testing.T) {
	t.Parallel()
	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	ou := User{
		"org (setup) " + testId.String(),
		"user " + testId.String(),
		"o.u." + testId.String() + "@email.com",
		"secrit_password",
	}

	org := Organization{
		"Org " + testId.String(),
		"Org " + testId.String() + " Decription",
	}

	// create organizing user
	_, err = userFactory(ou.firstName, ou.lastName, ou.email, ou.password)
	if err != nil {
		t.Errorf("organizing user %s creation failed. Error: %s", ou.email, err.Error())
		return
	}
	//t.Logf("created organizing user %s with email %s", organizingUser.ID.String(), ou.email)

	// authenticate organizing user
	ouAuth, err := provide.Authenticate(ou.email, ou.password)
	if err != nil {
		t.Errorf("authentication failed for organizing user %s. error: %s", ou.email, err.Error())
		return
	}
	//t.Logf("authenticated organizing user %s", organizingUser.ID.String())
	ouToken := ouAuth.Token.AccessToken

	// create organization
	Organization, err := orgFactory(*ouToken, org.name, org.description)
	if err != nil {
		t.Errorf("error creating organization %s. Error: %s", org.name, err.Error())
		return
	}
	//t.Logf("created organization %s", *Organization.ID)

	users, err := provide.ListOrganizationUsers(*ouToken, *Organization.ID, map[string]interface{}{})
	if err != nil {
		t.Errorf("error getting organization users list %s", err.Error())
		return
	}

	// we should only get the organizing user back.
	if len(users) != 1 {
		t.Errorf("incorrect number of organization users returned, expected 1, got %d", len(users))
		return
	}
	t.Logf("got correct number of organization users back %d using organizing user token", len(users))
}

// users must have sufficient permission on the organization to create and list users...
// an org token does not current grant access to the list of users-- it is more intended
// to be a programmatic api token for interacting with organization-owned resources *without*
// undermining the privacy of users who may be part of the organization...
func TestListOrganizationUsers(t *testing.T) {
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

		// create an Organization if it doesn't exist
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
		}
	}

	users, err := provide.ListOrganizationUsers(string(*organizingUserToken.AccessToken), *org.ID, map[string]interface{}{})
	if err != nil {
		t.Errorf("error getting organization users list %s", err.Error())
		return
	}
	if len(users) != len(tt) {
		t.Errorf("incorrect number of organization users returned, expected %d, got %d", len(tt), len(users))
	}
	t.Logf("got correct number of organization users back %d", len(users))
}
