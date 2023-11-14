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

package token

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	dbconf "github.com/kthomas/go-db-config"
	"github.com/kthomas/go-redisutil"
	"github.com/provideplatform/ident/common"
	provide "github.com/provideplatform/provide-go/common"
)

// const oauthAuthorizationGrantResponseTypeCode = "code"
// const oauthAuthorizationGrantResponseTypeToken = "token"
// const oauthAuthorizationGrantCodeChallengeMethodS256 = "S256"
const oauthAuthorizationGrantDefaultTokenType = "bearer"

// OAuthAuthorizationGrantParams for various OAuth authorization grant requests
//
// `CodeVerifier`, when non-nil, should be a cryptographically random string using
// the characters A-Z, a-z, 0-9, and the punctuation characters -._~ (hyphen, period,
// underscore, and tilde), between 43 and 128 characters long
type OAuthAuthorizationGrantParams struct {
	AccessToken         *string `json:"access_token,omitempty"`
	AuthorizeURI        *string `json:"authorize_uri,omitempty"`
	CallbackURI         *string `json:"callback_uri,omitempty"`
	ClientID            *string `json:"client_id,omitempty"`
	ClientSecret        *string `json:"client_secret,omitempty"`
	Code                *string `json:"code,omitempty"`
	CodeChallenge       *string `json:"code_challenge,omitempty"`
	CodeChallengeMethod *string `json:"code_challenge_method,omitempty"`
	CodeVerifier        *string `json:"code_verifier,omitempty"`
	ExpiresIn           *int64  `json:"expires_in,omitempty"`
	RedirectURI         *string `json:"redirect_uri,omitempty"`
	RefreshToken        *string `json:"refresh_token,omitempty"`
	ResponseType        *string `json:"response_type,omitempty"`
	Scope               *string `json:"scope,omitempty"`
	State               *string `json:"state,omitempty"`
	TokenType           *string `json:"token_type,omitempty"`
}

// authorizeCode attempts to exchange a short-lived OAuth `authorization_code`
// code for newly-authorized access/refresh tokens
//
// PKCE is required such that the state parameter can be used for application
// state (i.e., instead of CSRF protection)
//
// The given code_verifier should be verified against the associated code_challenge
func authorizeCode(c *gin.Context) {
	params, err := parseOAuthAuthorizationGrantRequest(c)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if params.ClientID == nil {
		provide.RenderError("client_id is required", 400, c)
		return
	}

	if params.ClientSecret == nil {
		provide.RenderError("client_secret is required", 400, c)
		return
	}

	if params.Code == nil {
		provide.RenderError("code is required", 400, c)
		return
	}

	if params.CodeVerifier == nil {
		provide.RenderError("code_verifier is required", 400, c)
		return
	}

	code, err := Parse(*params.Code)
	if err != nil {
		provide.RenderError("invalid code", 401, c)
		return
	}

	if code.ExpiresAt != nil {
		if !time.Now().Before(*code.ExpiresAt) {
			provide.RenderError("expired code", 401, c)
			return
		}
	}

	err = verifyOAuthClient(*params.ClientID, *params.ClientSecret, params.RedirectURI)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	challengeRaw, err := redisutil.Get(fmt.Sprintf("oauth.%s", common.SHA256(*params.Code))) // FIXME
	if challengeRaw == nil || err != nil {
		provide.RenderError("invalid code", 401, c)
		return
	}

	var challenge *OAuthAuthorizationGrantParams
	err = json.Unmarshal([]byte(*challengeRaw), &challenge)
	if err != nil {
		provide.RenderError("invalid code", 401, c)
		return
	}

	if strings.EqualFold(*challenge.CodeChallengeMethod, "S256") && !strings.EqualFold(common.SHA256(*params.CodeVerifier), *challenge.CodeChallenge) {
		provide.RenderError("PKCE verifier code failed validation", 401, c)
		return
	} else if strings.EqualFold(*challenge.CodeChallengeMethod, "plain") && !strings.EqualFold(*params.CodeVerifier, *challenge.CodeChallenge) {
		provide.RenderError("PKCE verifier code failed validation", 401, c)
		return
	}

	// var expiresIn *int64
	// ttl := code.ExpiresAt.Unix() - time.Now().Unix()
	// expiresIn = &ttl

	var scope string
	if code.Scope != nil {
		if !strings.Contains(*code.Scope, authorizationScopeOfflineAccess) {
			scope = authorizationScopeOfflineAccess
		}
		scope = fmt.Sprintf("%s %s", scope, *code.Scope)
	} else {
		scope = authorizationScopeOfflineAccess
	}

	token := &Token{
		ApplicationID:  code.ApplicationID,
		OrganizationID: code.OrganizationID,
		UserID:         code.UserID,
		Scope:          common.StringOrNil(strings.Trim(scope, " ")),
		State:          code.State,
		// TTL:            expiresIn,
	}

	if !token.Vend() {
		provide.RenderError(*token.Errors[0].Message, 401, c)
		return
	}

	provide.Render(token, 201, c)
}

// authorizeClientCredentials attempts to authorize a `client_credentials` OAuth grant type
func authorizeClientCredentials(c *gin.Context) {
	params, err := parseOAuthAuthorizationGrantRequest(c)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if params.ClientID == nil {
		provide.RenderError("client_id is required", 400, c)
		return
	}

	provide.RenderError("not implemented", 501, c)
}

func oauthAuthorizationGrantRedirectLocationFactory(params *OAuthAuthorizationGrantParams) *string {
	if params.ClientID == nil {
		return nil
	}

	location := fmt.Sprintf("%s?client_id=%s", *params.RedirectURI, *params.ClientID)

	if params.ResponseType != nil {
		location = fmt.Sprintf("%s&response_type=%s", location, *params.ResponseType)
	}

	if params.Code != nil {
		location = fmt.Sprintf("%s&code=%s", location, *params.Code)
	}

	if params.CodeChallenge != nil {
		location = fmt.Sprintf("%s&code_challenge=%s", location, *params.CodeChallenge)
	}

	if params.CodeChallengeMethod != nil {
		location = fmt.Sprintf("%s&code_challenge_method=%s", location, *params.CodeChallengeMethod)
	}

	if params.RedirectURI != nil {
		location = fmt.Sprintf("%s&redirect_uri=%s", location, *params.RedirectURI)
	}

	if params.Scope != nil {
		location = fmt.Sprintf("%s&scope=%s", location, *params.Scope)
	}

	if params.State != nil {
		location = fmt.Sprintf("%s&state=%s", location, *params.State)
	}

	return common.StringOrNil(location)
}

func parseOAuthAuthorizationGrantRequest(c *gin.Context) (*OAuthAuthorizationGrantParams, error) {
	buf, err := c.GetRawData()
	if err != nil {
		return nil, err
	}

	var params *OAuthAuthorizationGrantParams
	err = json.Unmarshal(buf, &params)
	if err != nil {
		return nil, err
	}

	return params, nil
}

// refreshAccessToken authorizes a new access token using the authorized refresh token
// provided in the given gin context; the subject of a refresh token is `token:<jti>`;
// if a non-nil scope parameter is provided, the authorized access token is constrained
// to these requested scopes, provided the refresh token authorizes such scopes
func refreshAccessToken(c *gin.Context, scope *string) {
	refreshToken := authorize(c)
	if refreshToken != nil {
		ttl := int(defaultAccessTokenTTL.Seconds())
		accessToken := &Token{
			ApplicationID:       refreshToken.ApplicationID,
			UserID:              refreshToken.UserID,
			OrganizationID:      refreshToken.OrganizationID,
			Scope:               refreshToken.Scope,
			Permissions:         refreshToken.Permissions,
			ExtendedPermissions: refreshToken.ExtendedPermissions,
			TTL:                 &ttl,
		}

		var err error

		if scope != nil {
			for _, scp := range strings.Split(*scope, " ") {
				forbiddenScopes := make([]string, 0)
				if !refreshToken.HasScope(scp) {
					forbiddenScopes = append(forbiddenScopes, scp)
				}

				if len(forbiddenScopes) > 0 {
					forbiddenScopesRaw, _ := json.Marshal(forbiddenScopes)
					err = fmt.Errorf("failed to authorize access token; refresh token does not authorize requested scope: %s", string(forbiddenScopesRaw))
					common.Log.Tracef(err.Error())
					provide.RenderError(err.Error(), 403, c)
					return
				}
			}
		}

		if accessToken.Vend() {
			accessToken.Token = nil
			provide.Render(accessToken.AsResponse(), 201, c)
			return
		}

		if len(accessToken.Errors) > 0 {
			err = fmt.Errorf("failed to authorize access token using refresh token on behalf of subject: %s; %s", *accessToken.Subject, *accessToken.Errors[0].Message)
			common.Log.Tracef(err.Error())
			provide.RenderError(err.Error(), 401, c)
			return
		}
	}

	provide.RenderError("unauthorized", 401, c)
}

// verifyOAuthClientParams ensures the given client secret and redirect uri match the application
func verifyOAuthClient(clientID, clientSecret string, redirectURI *string) error {
	db := dbconf.DatabaseConnection()

	out := []string{}
	db.Table("applications").Select("config").Where("applications.id = ?", clientID).Pluck("config", &out)
	if len(out) == 0 {
		return fmt.Errorf("application lookup failed for OAuth client_id: %s", clientID)
	}

	config := map[string]interface{}{}
	err := json.Unmarshal([]byte(out[0]), &config)
	if err != nil {
		return err
	}

	if oauth, oauthOk := config["oauth"].(map[string]interface{}); oauthOk {
		oauthRaw, _ := json.Marshal(oauth)

		var params *OAuthAuthorizationGrantParams
		err := json.Unmarshal(oauthRaw, &params)
		if err != nil {
			return err
		}

		if params.ClientSecret == nil {
			return errors.New("no client_secret configured for OAuth application")
		}

		if !strings.EqualFold(*params.ClientSecret, clientSecret) {
			return errors.New("client_secret mismatch")
		}

		if params.CallbackURI == nil {
			return errors.New("no callback_uri configured for OAuth application")
		}

		if redirectURI != nil {
			if !strings.EqualFold(*params.CallbackURI, *redirectURI) {
				return errors.New("redirect_uri mismatch")
			}
		}

		return nil
	}

	return fmt.Errorf("no oauth config resolved for client_id: %s", clientID)
}
