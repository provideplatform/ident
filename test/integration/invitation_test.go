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
	"fmt"
	"testing"

	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideplatform/provide-go/api/ident"
)

func TestInviteUserFailsWithoutEmail(t *testing.T) {
	t.Parallel()
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

	// create an invite¡
	err = provide.CreateInvitation(*auth.Token.AccessToken, map[string]interface{}{})
	if err == nil {
		t.Error("creating invitation should fail without an email address")
		return
	}
}

func TestInviteUserFailsWithInvalidEmail(t *testing.T) {
	t.Parallel()
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
	err = provide.CreateInvitation(*auth.Token.AccessToken, map[string]interface{}{
		"email": "not.a.valid.email.addr",
	})
	if err == nil {
		t.Error("creating invitation should fail with an invalid email address")
		return
	}
}

func TestInviteUserByUserWithoutSudoFailsWithArbitraryPermission(t *testing.T) {
	t.Parallel()
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
	err = provide.CreateInvitation(*auth.Token.AccessToken, map[string]interface{}{
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

func TestInviteUserFailsWithExistingUserEmail(t *testing.T) {
	t.Parallel()
	testId, _ := uuid.NewV4()
	email := fmt.Sprintf("%s@prvd.local", testId.String())

	// create the user
	_, err := userFactory("a", "user", email, "passw0rd")
	if err != nil {
		t.Errorf("user creation failed;  %s", err.Error())
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
	_, err = userFactory("joe", "user", inviteEmail, "passw0rd")
	if err != nil {
		t.Errorf("user creation failed; %s", err.Error())
		return
	}

	// create an invite for the existing user
	err = provide.CreateInvitation(*auth.Token.AccessToken, map[string]interface{}{
		"email":      inviteEmail,
		"first_name": "Joe",
		"last_name":  "User",
	})
	if err == nil {
		t.Error("creating invitation should fail with existing user email")
		return
	}
}

func TestInviteUserWithUserAPIToken(t *testing.T) {
	t.Parallel()
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
	err = provide.CreateInvitation(*auth.Token.AccessToken, map[string]interface{}{
		"email":      inviteEmail,
		"first_name": "A",
		"last_name":  "User",
	})
	if err != nil {
		t.Errorf("creating invitation failed by user with id %s; %s", user.ID, err.Error())
		return
	}

	// second invite should also work
	err = provide.CreateInvitation(*auth.Token.AccessToken, map[string]interface{}{
		"email":      inviteEmail,
		"first_name": "A",
		"last_name":  "User",
	})
	if err != nil {
		t.Errorf("creating second invitation failed by user with id %s; %s", user.ID, err.Error())
		return
	}
}

func TestInviteApplicationUserWithApplicationAPIToken(t *testing.T) {
	t.Parallel()
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
	app, err := appFactory(*auth.Token.AccessToken, "test app", "axiom workgroup")
	if err != nil {
		t.Errorf("app creaton failed; %s", err.Error())
		return
	}

	// create a token for the application
	apptkn, err := appTokenFactory(*auth.Token.AccessToken, app.ID)
	if err != nil {
		t.Errorf("token creation failed for application id %s; %s", app.ID, err.Error())
		return
	}

	inviteTestId, _ := uuid.NewV4()
	inviteEmail := fmt.Sprintf("%s@example.local", inviteTestId.String())

	err = provide.CreateInvitation(*apptkn.AccessToken, map[string]interface{}{
		"email":      inviteEmail,
		"first_name": "A",
		"last_name":  "User",
	})
	if err != nil {
		t.Errorf("creating invitation failed for authorized application context; %s", err.Error())
		return
	}

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

func TestInviteOrganizationUserWithOrganizationAPIToken(t *testing.T) {
	t.Parallel()
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

	// create the org
	org, err := orgFactory(*auth.Token.AccessToken, "test org", "ABC Corp")
	if err != nil {
		t.Errorf("org creaton failed; %s", err.Error())
		return
	}

	// create a token for the organization
	orgtkn, err := orgTokenFactory(*auth.Token.AccessToken, org.ID)
	if err != nil {
		t.Errorf("token creation failed for organization id %s; %s", org.ID, err.Error())
		return
	}

	inviteTestId, _ := uuid.NewV4()
	inviteEmail := fmt.Sprintf("%s@example.local", inviteTestId.String())

	err = provide.CreateInvitation(*orgtkn.AccessToken, map[string]interface{}{
		"email":      inviteEmail,
		"first_name": "A",
		"last_name":  "User",
	})
	if err != nil {
		t.Errorf("creating invitation failed for authorized organization context; %s", err.Error())
		return
	}

	invitations, err := provide.ListOrganizationInvitations(*orgtkn.AccessToken, org.ID.String(), map[string]interface{}{})
	if err != nil {
		t.Errorf("listing org invitations failed for organization id %s; %s", org.ID, err.Error())
		return
	}

	if len(invitations) != 1 {
		t.Errorf("listing org invitations failed for organization id %s; expected 1 invitation, got %d", org.ID, len(invitations))
		return
	}
}
