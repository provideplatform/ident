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
	"encoding/json"
	"fmt"
	"testing"

	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideplatform/provide-go/api/ident"
)

func TestUserAccessRefreshToken(t *testing.T) {
	t.Parallel()
	testId, err := uuid.NewV4()
	if err != nil {
		t.Errorf("error creating uuid; %s", err.Error())
		return
	}

	email := fmt.Sprintf("%s@prvd.local", testId.String())
	passwd := "passw0rd"

	user, err := userFactory("joe", "user", email, passwd)
	if err != nil {
		t.Errorf("user creation failed. Error: %s", err.Error())
		return
	}

	// get the auth token
	// FIXME should be available in provide-go (offline_access param)
	status, resp, err := provide.InitIdentService(nil).Post("authenticate", map[string]interface{}{
		"email":    email,
		"password": passwd,
		"scope":    "offline_access",
	})
	if err != nil {
		t.Errorf("failed to authenticate user; status: %v; %s", status, err.Error())
		return
	}
	auth := &provide.AuthenticationResponse{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &auth)
	if err != nil {
		t.Errorf("failed to authenticate user; status: %v; %s", status, err.Error())
	}

	accessRefreshToken := auth.Token
	if accessRefreshToken == nil {
		t.Error("user authenticate request with offline_access token scope failed to return access_token/refresh_token")
		return
	}

	// this authenticate response returns an access token
	if accessRefreshToken.Token != nil {
		t.Errorf("token returned for offline_access token scope; should only contain access_token and refresh_token. token present: %+v", accessRefreshToken)
		return
	}

	if accessRefreshToken.AccessToken == nil {
		t.Error("access token not returned for offline_access token scope")
		return
	}

	if accessRefreshToken.RefreshToken == nil {
		t.Error("refresh token not returned for offline_access token scope")
		return
	}

	if accessRefreshToken.ExpiresIn == nil {
		t.Error("expires_in not returned for offline_access token scope")
		return
	}

	// use the refresh token to vend a new access token
	accessToken, err := provide.CreateToken(string(*accessRefreshToken.RefreshToken), map[string]interface{}{
		"grant_type": "refresh_token",
	})
	if err != nil {
		t.Errorf("error refreshing token for user %s", *user.ID)
		return
	}

	if accessToken.Token != nil {
		t.Error("token returned for access token authorized by refresh_token token grant; should only contain access_token and optional refresh_token")
		return
	}

	if accessToken.AccessToken == nil {
		t.Error("access token not returned for access token authorized by refresh_token token grant")
		return
	}

	if accessToken.RefreshToken != nil {
		t.Error("refresh token returned for access token authorized by refresh_token token grant")
		return
	}

	if accessToken.ExpiresIn == nil {
		t.Error("expires_in not returned for access token authorized by refresh_token token grant")
		return
	}
}

func TestAppRevocableToken(t *testing.T) {
	t.Parallel()
	testId, err := uuid.NewV4()
	if err != nil {
		t.Errorf("error creating uuid; %s", err.Error())
		return
	}

	email := fmt.Sprintf("%s@prvd.local", testId.String())
	user, err := userFactory("joe", "user", email, "passw0rd")
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

	// create an app
	app, err := provide.CreateApplication(string(*auth.Token.AccessToken), map[string]interface{}{
		"name": "DeFi Unicornz",
	})
	if err != nil {
		t.Errorf("error creating application for user id %s", *user.ID)
		return
	}

	// create a revocable api token
	token, err := provide.CreateToken(string(*auth.Token.AccessToken), map[string]interface{}{
		"application_id": app.ID.String(),
	})
	if err != nil {
		t.Errorf("error creating token for app id %s", app.ID.String())
		return
	}

	if token.AccessToken == nil {
		t.Error("token not returned for revocable application api token")
		return
	}

	if token.RefreshToken != nil {
		t.Error("refresh token returned for revocable application api token")
		return
	}

	if token.ExpiresIn != nil {
		t.Error("expires_in returned for revocable application api token")
		return
	}
}

func TestAppAccessRefreshToken(t *testing.T) {
	t.Parallel()
	testId, err := uuid.NewV4()
	if err != nil {
		t.Errorf("error creating uuid; %s", err.Error())
		return
	}

	email := fmt.Sprintf("%s@prvd.local", testId.String())
	user, err := userFactory("joe", "user", email, "passw0rd")
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

	// create an app
	app, err := provide.CreateApplication(string(*auth.Token.AccessToken), map[string]interface{}{
		"name": "DeFi Unicornz",
	})
	if err != nil {
		t.Errorf("error creating application for user id %s", *user.ID)
		return
	}

	// create an access/refresh token
	accessRefreshToken, err := provide.CreateToken(string(*auth.Token.AccessToken), map[string]interface{}{
		"application_id": app.ID.String(),
		"scope":          "offline_access",
	})
	if err != nil {
		t.Errorf("error creating token for app id %s", app.ID.String())
		return
	}

	if accessRefreshToken.Token != nil {
		t.Error("token returned for offline_access token scope; should only contain access_token and refresh_token")
		return
	}

	if accessRefreshToken.AccessToken == nil {
		t.Error("access token not returned for offline_access token scope")
		return
	}

	if accessRefreshToken.RefreshToken == nil {
		t.Error("refresh token not returned for offline_access token scope")
		return
	}

	if accessRefreshToken.ExpiresIn == nil {
		t.Error("expires_in not returned for offline_access token scope")
		return
	}

	// use the refresh token to vend a new access token
	accessToken, err := provide.CreateToken(string(*accessRefreshToken.RefreshToken), map[string]interface{}{
		"grant_type": "refresh_token",
	})
	if err != nil {
		t.Errorf("error refreshing token for app %s", app.ID)
		return
	}

	if accessToken.Token != nil {
		t.Error("token returned for refresh_token token grant; should only contain access_token and optional refresh_token")
		return
	}

	if accessToken.AccessToken == nil {
		t.Error("access token not returned for refresh_token token grant")
		return
	}

	if accessToken.RefreshToken != nil {
		t.Error("refresh token returned for refresh_token token grant")
		return
	}

	if accessToken.ExpiresIn == nil {
		t.Error("expires_in not returned for refresh_token token grant")
		return
	}
}

func TestOrgAccessRefreshToken(t *testing.T) {
	t.Parallel()
	testId, err := uuid.NewV4()
	if err != nil {
		t.Errorf("error creating uuid; %s", err.Error())
		return
	}

	email := fmt.Sprintf("%s@prvd.local", testId.String())
	user, err := userFactory("joe", "user", email, "passw0rd")
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

	// create an org
	org, err := provide.CreateOrganization(string(*auth.Token.AccessToken), map[string]interface{}{
		"name": "ABC Corp",
	})
	if err != nil {
		t.Errorf("error creating organization for user id %s", *user.ID)
		return
	}

	// create an access/refresh token
	accessRefreshToken, err := provide.CreateToken(string(*auth.Token.AccessToken), map[string]interface{}{
		"organization_id": org.ID,
		"scope":           "offline_access",
	})
	if err != nil {
		t.Errorf("error creating token for org id %s", *org.ID)
		return
	}

	if accessRefreshToken.Token != nil {
		t.Error("token returned for offline_access token scope; should only contain access_token and refresh_token")
		return
	}

	if accessRefreshToken.AccessToken == nil {
		t.Error("access token not returned for offline_access token scope")
		return
	}

	if accessRefreshToken.RefreshToken == nil {
		t.Error("refresh token not returned for offline_access token scope")
		return
	}

	if accessRefreshToken.ExpiresIn == nil {
		t.Error("expires_in not returned for offline_access token scope")
		return
	}

	// use the refresh token to vend a new access token
	accessToken, err := provide.CreateToken(string(*accessRefreshToken.RefreshToken), map[string]interface{}{
		"grant_type": "refresh_token",
	})
	if err != nil {
		t.Errorf("error refreshing token for org %s", *org.ID)
		return
	}

	if accessToken.Token != nil {
		t.Error("token returned for refresh_token token grant; should only contain access_token and optional refresh_token")
		return
	}

	if accessToken.AccessToken == nil {
		t.Error("access token not returned for refresh_token token grant")
		return
	}

	if accessToken.RefreshToken != nil {
		t.Error("refresh token returned for refresh_token token grant")
		return
	}

	if accessToken.ExpiresIn == nil {
		t.Error("expires_in not returned for refresh_token token grant")
		return
	}
}
