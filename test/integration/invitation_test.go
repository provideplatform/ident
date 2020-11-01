// +build integration

package integration

import (
	"fmt"
	"testing"

	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideservices/provide-go/api/ident"
)

func TestInviteUserFailsWithoutEmail(t *testing.T) {
	testId, _ := uuid.NewV4()
	email := fmt.Sprintf("%s@prvd.local", testId.String())

	// create the user
	_, err := userFactory("a", "user", email, "passw0rd")
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// get the auth token
	auth, err := provide.Authenticate(email, "passw0rd")
	if err != nil {
		t.Errorf("user authentication failed for user %s. error: %s", email, err.Error())
		return
	}

	// create an invite
	_, err = provide.CreateInvitation(*auth.Token.Token, map[string]interface{}{})
	if err == nil {
		t.Error("creating invitation should fail without an email address")
		return
	}
}

func TestInviteUserFailsWithInvalidEmail(t *testing.T) {
	testId, _ := uuid.NewV4()
	email := fmt.Sprintf("%s@prvd.local", testId.String())

	// create the user
	_, err := userFactory("a", "user", email, "passw0rd")
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// get the auth token
	auth, err := provide.Authenticate(email, "passw0rd")
	if err != nil {
		t.Errorf("user authentication failed for user %s. error: %s", email, err.Error())
		return
	}

	// create an invite
	_, err = provide.CreateInvitation(*auth.Token.Token, map[string]interface{}{
		"email": "not.a.valid.email.addr",
	})
	if err == nil {
		t.Error("creating invitation should fail with an invalid email address")
		return
	}
}

func TestInviteUserFailsWithoutFirstName(t *testing.T) {
	testId, _ := uuid.NewV4()
	email := fmt.Sprintf("%s@prvd.local", testId.String())

	// create the user
	_, err := userFactory("a", "user", email, "passw0rd")
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// get the auth token
	auth, err := provide.Authenticate(email, "passw0rd")
	if err != nil {
		t.Errorf("user authentication failed for user %s. error: %s", email, err.Error())
		return
	}

	inviteTestId, _ := uuid.NewV4()
	inviteEmail := fmt.Sprintf("%s@example.local", inviteTestId.String())

	// create an invite
	_, err = provide.CreateInvitation(*auth.Token.Token, map[string]interface{}{
		"email":     inviteEmail,
		"last_name": "User",
	})
	if err == nil {
		t.Error("creating invitation should fail without a first name")
		return
	}
}

func TestInviteUserFailsWithoutLastName(t *testing.T) {
	testId, _ := uuid.NewV4()
	email := fmt.Sprintf("%s@prvd.local", testId.String())

	// create the user
	_, err := userFactory("a", "user", email, "passw0rd")
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// get the auth token
	auth, err := provide.Authenticate(email, "passw0rd")
	if err != nil {
		t.Errorf("user authentication failed for user %s. error: %s", email, err.Error())
		return
	}

	inviteTestId, _ := uuid.NewV4()
	inviteEmail := fmt.Sprintf("%s@example.local", inviteTestId.String())

	// create an invite
	_, err = provide.CreateInvitation(*auth.Token.Token, map[string]interface{}{
		"email":      inviteEmail,
		"first_name": "A",
	})
	if err == nil {
		t.Error("creating invitation should fail without a last name")
		return
	}
}

func TestInviteUserByUserWithoutSudoFailsWithArbitraryPermission(t *testing.T) {
	testId, _ := uuid.NewV4()
	email := fmt.Sprintf("%s@prvd.local", testId.String())

	// create the user
	_, err := userFactory("a", "user", email, "passw0rd")
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// get the auth token
	auth, err := provide.Authenticate(email, "passw0rd")
	if err != nil {
		t.Errorf("user authentication failed for user %s. error: %s", email, err.Error())
		return
	}

	inviteTestId, _ := uuid.NewV4()
	inviteEmail := fmt.Sprintf("%s@example.local", inviteTestId.String())

	// create an invite
	_, err = provide.CreateInvitation(*auth.Token.Token, map[string]interface{}{
		"email":       inviteEmail,
		"first_name":  "A",
		"last_name":   "User",
		"permissions": 1024, // arbitrary... should fail unless user has `Sudo` permission
	})
	if err == nil {
		t.Error("creating invitation with non-sudoer should fail with arbitrary user permissions")
		return
	}
}

func TestInviteUserWithUserAPIToken(t *testing.T) {
	testId, _ := uuid.NewV4()
	email := fmt.Sprintf("%s@prvd.local", testId.String())

	// create the user
	user, err := userFactory("a", "user", email, "passw0rd")
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// get the auth token
	auth, err := provide.Authenticate(email, "passw0rd")
	if err != nil {
		t.Errorf("user authentication failed for user %s. error: %s", email, err.Error())
		return
	}

	inviteTestId, _ := uuid.NewV4()
	inviteEmail := fmt.Sprintf("%s@example.local", inviteTestId.String())

	// create an invite
	invite, err := provide.CreateInvitation(*auth.Token.Token, map[string]interface{}{
		"email":      inviteEmail,
		"first_name": "A",
		"last_name":  "User",
	})
	if err != nil {
		t.Errorf("creating invitation failed by user with id %s; %s", user.ID, err.Error())
		return
	}
	t.Logf("invite: %s", invite.ID)
}

func TestInviteApplicationUserWithApplicationAPIToken(t *testing.T) {
	testId, _ := uuid.NewV4()
	email := fmt.Sprintf("%s@prvd.local", testId.String())

	// create the user
	_, err := userFactory("a", "user", email, "passw0rd")
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// get the auth token
	auth, err := provide.Authenticate(email, "passw0rd")
	if err != nil {
		t.Errorf("user authentication failed for user %s; %s", email, err.Error())
		return
	}

	// create the app
	app, err := appFactory(*auth.Token.Token, "test app", "baseline workgroup")
	if err != nil {
		t.Errorf("app creaton failed; %s", err.Error())
		return
	}

	// create a token for the application
	apptkn, err := appTokenFactory(*auth.Token.Token, app.ID)
	if err != nil {
		t.Errorf("token creation failed for application id %s; %s", app.ID, err.Error())
		return
	}

	invite, err := provide.CreateApplicationInvitation(*apptkn.Token, app.ID.String(), map[string]interface{}{})
	if err != nil {
		t.Errorf("creating app invitation failed for application id %s; %s", app.ID, err.Error())
		return
	}
	t.Logf("invite: %s", invite.ID)

	invitations, err := provide.ListApplicationInvitations(*apptkn.AccessToken, app.ID.String(), map[string]interface{}{})
	if err != nil {
		t.Errorf("listing app invitations failed for application id %s; %s", app.ID, err.Error())
		return
	}

	if len(invitations) != 1 {
		t.Errorf("listing app invitations failed for application id %s; expected 1 invitation, got %d", app.ID, len(invitations))
		return
	}
}

// func TestListApplicationInvitationsWithApplicationAPIToken(t *testing.T) {
// 	// create the user
// 	user, err := userFactory(tc.firstName, tc.lastName, tc.email, tc.password)
// 	if err != nil {
// 		t.Errorf("user creation failed. Error: %s", err.Error())
// 		return
// 	}

// 	// get the auth token
// 	auth, err := provide.Authenticate(tc.email, tc.password)
// 	if err != nil {
// 		t.Errorf("user authentication failed for user %s. error: %s", tc.email, err.Error())
// 		return
// 	}

// 	// create the app
// 	app, err := appFactory(*auth.Token.Token, "test app", "baseline workgroup")
// 	if err != nil {
// 		t.Errorf("app creaton failed; %s", err.Error())
// 		return
// 	}

// 	// create a token for the application
// 	apptkn, err := appTokenFactory(*auth.Token.Token, app.ID)
// 	if err != nil {
// 		t.Errorf("token creation failed for application id %s; %s", app.ID, err.Error())
// 		return
// 	}

// 	invitations, err := provide.ListApplicationInvitations(*apptkn.Token.Token, app.ID.String(), map[string]interface{}{})
// 	if err != nil {
// 		t.Errorf("listing app invitations failed for application id %s; %s", app.ID, err.Error())
// 		return
// 	}

// 	if len(invitations) != 1 {
// 		t.Errorf("listing app invitations failed for application id %s; expected 1 invitation, got %d", app.ID, len(invitations))
// 		return
// 	}
// }
