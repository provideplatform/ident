// +build integration

package integration

import (
	"testing"

	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideservices/provide-go/api/ident"
)

func TestDeleteOrganizationUser_NEW_AND_IMPROVED(t *testing.T) {

	testId, err := uuid.NewV4()
	if err != nil {
		t.Logf("error creating new UUID")
	}

	ou := User{
		"organizing " + testId.String(),
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
		userID    *uuid.UUID
	}{
		{"joey", "joe joe", "j.j" + testId.String() + "@email.com", "secrit_password", nil},
		{"joey2", "joe joe2", "j.j2" + testId.String() + "@email.com", "secrit_password", nil},
		{"joey3", "joe joe3", "j.j3" + testId.String() + "@email.com", "secrit_password", nil},
		{"joey4", "joe joe4", "j.j4" + testId.String() + "@email.com", "secrit_password", nil},
		{"joey5", "joe joe5", "j.j5" + testId.String() + "@email.com", "secrit_password", nil},
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
	ouToken := ouAuth.Token.Token

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
	//t.Logf("created organization %s", Organization.ID.String())

	// get an app token
	appToken, err := appTokenFactory(*ouToken, Application.ID)
	if err != nil {
		t.Errorf("error getting app token for application %s. Error: %s", Application.ID, err.Error())
		return
	}

	orgToken, err := orgTokenFactory(*ouToken, Organization.ID)
	if err != nil {
		t.Errorf("error getting org token for organization %s. Error: %s", Organization.ID, err.Error())
		return
	}
	// associate org to app, using the app token
	err = apporgFactory(*appToken.Token, Application.ID.String(), Organization.ID.String())
	if err != nil {
		t.Errorf("error associating org %s to app %s", Organization.ID, Application.ID)
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
		//t.Logf("created user %s", organizationUser.ID.String())

		err = provide.CreateOrganizationUser(*ouToken, Organization.ID.String(), map[string]interface{}{
			"user_id": organizationUser.ID.String(),
		})
		if err != nil {
			t.Errorf("failed to add user %s to organization %s; %s", organizationUser.ID, Organization.ID.String(), err.Error())
			return
		}
		//t.Logf("created user %s for org %s", organizationUser.ID.String(), Organization.ID.String())
		users[counter].userID = &organizationUser.ID
	}

	// now we'll do stuff and stuff with them...

	//1. let's try deleting an app org user with an app token
	err = provide.DeleteOrganizationUser(*appToken.Token, Organization.ID.String(), users[0].userID.String())
	if err != nil {
		t.Errorf("error deleting organization user %s with app token. Error: %s", users[0].userID.String(), err.Error())
		return
	}

	//2. let's try deleting an app org user with an org token
	err = provide.DeleteOrganizationUser(*orgToken.Token, Organization.ID.String(), users[1].userID.String())
	if err != nil {
		t.Errorf("error deleting organization user %s with org token. Error: %s", users[1].userID.String(), err.Error())
		return
	}

	//3 let's try a user deleting themselves from the org using their own token
	delAuth, err := provide.Authenticate(users[2].email, users[2].password)
	if err != nil {
		t.Errorf("authentication failed for organizing user %s. error: %s", users[2].email, err.Error())
		return
	}

	err = provide.DeleteOrganizationUser(*delAuth.Token.Token, Organization.ID.String(), users[2].userID.String())
	if err != nil {
		t.Errorf("error deleting organization user %s with org token. Error: %s", users[2].userID.String(), err.Error())
		return
	}

	//4. let's try deleting an app org user with the organizing user's token
	// Note, not yet implemented, so returns 501
	// err = provide.DeleteOrganizationUser(*ouToken, Organization.ID.String(), users[3].userID.String())
	// if err != nil {
	// 	t.Errorf("error deleting organization user %s with org user token. Error: %s", users[3].userID.String(), err.Error())
	// 	return
	// }
}
