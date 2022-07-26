//go:build failing || ident
// +build failing ident

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

func TestOrganizationDetailsWithOrgToken(t *testing.T) {

	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	t.Logf("using test ID: %s", testId)
	type User struct {
		firstName string
		lastName  string
		email     string
		password  string
	}

	authUser := User{
		"first" + testId.String(), "last" + testId.String(), "first.last." + testId.String() + "@email.com", "secrit_password",
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
		identifier  *uuid.UUID
	}{
		{"org1" + testId.String(), "org1 desc" + testId.String(), nil},
		// {"org2" + testId.String(), "org2 desc" + testId.String(), nil},
		// {"org3" + testId.String(), "org3 desc" + testId.String(), nil},
		// {"org4" + testId.String(), "org4 desc" + testId.String(), nil},
	}

	t.Logf("user id: %s", user.ID)
	t.Logf("authy auth: %s", *auth.Token.AccessToken)

	for counter, tc := range tt {
		// create the orgs all at once, because if we create them one at a time, we might not catch the bug (always returning latest org, maybe)
		org, err := provide.CreateOrganization(string(*auth.Token.AccessToken), map[string]interface{}{
			"name":        tc.name,
			"description": tc.description,
		})
		t.Logf("orgy orgy: %+v", org)
		if err != nil {
			t.Errorf("error creating organization for user id %s. error: %s", user.ID, err.Error())
			return

		}

		//assign the returned identifier to the test table
		tt[counter].identifier = &org.ID
	}

	for _, tc_deets := range tt {
		// get the org details
		t.Logf("getting organisation details for org %s", tc_deets.identifier.String())

		orgToken, err := orgTokenFactory(*auth.Token.AccessToken, *tc_deets.identifier)
		if err != nil {
			t.Errorf("error generating org token for org %s", tc_deets.identifier.String())
		}

		deets, err := provide.GetOrganizationDetails(*orgToken.AccessToken, tc_deets.identifier.String(), map[string]interface{}{})
		if err != nil {
			t.Errorf("error getting organization details. Error: %s", err.Error())
			return
		}

		if deets.Name != nil {
			if tc_deets.name != *deets.Name {
				t.Errorf("Name mismatch for org %s. Expected %s, got %s", tc_deets.identifier.String(), tc_deets.name, *deets.Name)
				return
			}

			if tc_deets.description != *deets.Description {
				t.Errorf("Description mismatch for org %s. Expected %s, got %s", tc_deets.identifier.String(), tc_deets.description, *deets.Description)
				return
			}
		} else {
			t.Errorf("could not get organization details for org %s - org not returned", tc_deets.identifier.String())
			return
		}
		t.Logf("org %s details ok", tc_deets.identifier.String())
	}
}
