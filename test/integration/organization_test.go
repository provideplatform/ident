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
