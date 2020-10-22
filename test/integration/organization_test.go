// +build integration

package integration

import (
	"fmt"
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

func TestListOrganisationUsers(t *testing.T) {

	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	//t.Logf("*** test list users *** using testid %s", testId)

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

	appToken := &provide.Token{}
	userOrganization := &provide.Organization{}

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

		// Create an Organization if it doesn't exist
		if userOrganization.Name == nil {

			userOrganization, err = provide.CreateOrganization(string(*auth.Token.Token), map[string]interface{}{
				"name":        userOrg.name,
				"description": userOrg.description,
				"user_id":     user.ID,
			})
			if err != nil {
				t.Errorf("error creation organization for user id %s", user.ID)
				return
			}

			// create a token for that organization
			appToken, err = orgTokenFactory(*auth.Token.Token, userOrganization.ID)
			if err != nil {
				t.Errorf("token creation failed for organization id %s. error: %s", userOrganization.ID, err.Error())
				return
			}

		} else {
			//let's add this user to the organization as the creating user is automatically added...

			// access the add user path through the hackyhack
			//FIXME should be available in provide-go
			path := fmt.Sprintf("organizations/%s/users/", userOrganization.ID.String())

			status, resp, err := provide.InitIdentService(appToken.Token).Post(path, map[string]interface{}{
				"user_id": user.ID,
			})
			if err != nil {
				t.Errorf("failed to add user %s to organization %s; status: %v; %s", userOrganization.ID.String(), user.ID, status, err.Error())
				return
			}

			if status != 204 {
				t.Errorf("failed to add user to organization; status: %v; resp: %v", status, resp)
				return
			}
		}
	}

	if appToken != nil {
		users, err := provide.ListUsers(string(*appToken.Token), map[string]interface{}{})
		if err != nil {
			t.Errorf("error getting users list %s", err.Error())
		}
		if len(users) != len(tt) {
			t.Errorf("incorrect number of users returned, expected %d, got %d", len(tt), len(users))
		}
		t.Logf("got correct number of organization users back %d", len(users))
	}
}
