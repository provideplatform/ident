// +build integration

package test

import (
	"testing"

	provide "github.com/provideservices/provide-go/api/ident"
)

func userFactory(firstName, lastName, email, password string) (*provide.User, error) {
	user, err := provide.CreateUser("", map[string]interface{}{
		"first_name": firstName,
		"last_name":  lastName,
		"email":      email,
		"password":   password,
	})

	return user, err
}

func TestCreateUser(t *testing.T) {
	tt := []struct {
		firstName string
		lastName  string
		email     string
		password  string
	}{
		{"first", "last", "first.last@email.com", "secrit_password"},
		{"joey", "joe joe", "j.j.j@email.com", "joeyjoejoe"},
	}

	for _, tc := range tt {
		user, err := userFactory(tc.firstName, tc.lastName, tc.email, tc.password)
		if err != nil {
			t.Errorf("user creation failed. Error: %s", err.Error())
			return
		}
		t.Logf("user returned: %+v", user)
	}
}

func TestAuthenticateUser(t *testing.T) {
	tt := []struct {
		firstName string
		lastName  string
		email     string
		password  string
	}{
		{"first", "last", "first.last.auth@email.com", "secrit_password"},
		{"joey", "joe joe", "j.j.j.auth@email.com", "joeyjoejoe"},
	}

	for _, tc := range tt {
		_, err := userFactory(tc.firstName, tc.lastName, tc.email, tc.password)
		if err != nil {
			t.Errorf("user creation failed. Error: %s", err.Error())
			return
		}

		auth, err := provide.Authenticate(tc.email, tc.password)
		if err != nil {
			t.Errorf("user authentication failed. Error: %s", err.Error())
		}
		t.Logf("user authenticated: %+v", auth)
		t.Logf("user returned from auth: %+v", *auth.User)
		t.Logf("token returned from auth: %s", *auth.Token.Token)
	}
}
func TestCreateOrganization(t *testing.T) {

	type organization struct {
		name        string
		description string
	}
	userOrg := organization{"Org 01", "Desc01"}

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

		//orgSample := provide.Organization{}

		// create the org with that user (for the moment...)
		org, err := provide.CreateOrganization(string(*auth.Token.Token), map[string]interface{}{
			"name":        userOrg.name,
			"description": userOrg.description,
			"user_id":     user.ID,
		})
		t.Logf("org: %+v", org)
	}
}
