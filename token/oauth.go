package token

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/provideplatform/ident/common"
	provide "github.com/provideplatform/provide-go/common"
)

const oauthAuthorizationGrantResponseTypeCode = "code"
const oauthAuthorizationGrantResponseTypeToken = "token"

// OAuthAuthorizationGrantParams for various OAuth authorization grant requests
type OAuthAuthorizationGrantParams struct {
	ClientID            *string `json:"client_id,omitempty"`
	ClientSecret        *string `json:"client_secret,omitempty"`
	Code                *string `json:"code,omitempty"`
	CodeChallenge       *string `json:"code_challenge,omitempty"`
	CodeChallengeMethod *string `json:"code_challenge_method,omitempty"`
	CodeVerifier        *string `json:"code_verifier,omitempty"`
	RedirectURI         *string `json:"redirect_uri,omitempty"`
	ResponseType        *string `json:"response_type,omitempty"`
	Scope               *string `json:"scope,omitempty"`
	State               *string `json:"state,omitempty"`
}

// authorizeAuthorizationCode attempts to authorize an `authorization_code` OAuth grant_type
func authorizeAuthorizationCode(c *gin.Context, bearer *Token) {
	params, err := parseOAuthAuthorizationGrantRequest(c)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if params.ResponseType == nil || !strings.EqualFold(*params.ResponseType, oauthAuthorizationGrantResponseTypeCode) {
		provide.RenderError("response_type parameter must be set to 'code' for authorization_code grant request", 422, c)
		return
	}

	if params.ClientID == nil {
		provide.RenderError("client_id is required", 400, c)
		return
	}

	if params.RedirectURI == nil {
		provide.RenderError("failed to resolve redirect uri", 500, c)
		return
	}

	params.Code = bearer.AccessToken // FIXME

	// FIXME!! verify client_id redirect_uri matches

	location := oauthAuthorizationGrantRedirectLocationFactory(params)
	if location == nil {
		provide.RenderError("failed to resolve redirect uri", 500, c)
		return
	}

	c.Redirect(302, *location)
}

func oauthAuthorizationGrantRedirectLocationFactory(params *OAuthAuthorizationGrantParams) *string {
	if params.ResponseType == nil {
		return nil
	}

	location := fmt.Sprintf("%s?response_type=%s", *params.RedirectURI, *params.ResponseType)

	if params.Code != nil {
		location = fmt.Sprintf("%s&code=%s", location, *params.ResponseType)
	}

	if params.Scope != nil {
		location = fmt.Sprintf("%s&scope=%s", location, *params.Scope)
	}

	if params.State != nil {
		location = fmt.Sprintf("%s&state=%s", location, *params.State)
	}

	return common.StringOrNil(location)
}

// authorizeClientCredentials attempts to authorize a `client_credentials` OAuth grant_type
func authorizeClientCredentials(c *gin.Context) {
	// params, err := parseOAuthAuthorizationGrantRequest(c)

	// TODO-- read and handle required and optional params: client_id, client_secret, state, scope and redirect_uri from given context

	// if params.ClientID == nil {
	// 	provide.RenderError("client_id is required", 400, c)
	// 	return
	// }

	// if params.Scope != nil {
	// 	// FIXME!! handle state
	// }

	// if params.State != nil {
	// 	// FIXME!! handle state
	// }

	// if params.RedirectURI != nil {
	// 	// FIXME!! handle redirect
	// }

	provide.RenderError("not implemented", 501, c)
}

// authorizeImplicit attempts to authorize an `implicit` OAuth grant_type
func authorizeImplicit(c *gin.Context) {
	params, err := parseOAuthAuthorizationGrantRequest(c)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if params.ResponseType == nil || !strings.EqualFold(*params.ResponseType, oauthAuthorizationGrantResponseTypeToken) {
		provide.RenderError("response_type parameter must be set to 'token' for implicit authorization grant request", 422, c)
		return
	}

	// TODO-- read and handle required and optional params: client_id, state, scope and redirect_uri from given context

	// if params.ClientID == nil {
	// 	provide.RenderError("client_id is required", 400, c)
	// 	return
	// }

	// if params.Scope != nil {
	// 	// FIXME!! handle state
	// }

	// if params.State != nil {
	// 	// FIXME!! handle state
	// }

	// if params.RedirectURI != nil {
	// 	// FIXME!! handle redirect
	// }

	provide.RenderError("not implemented", 501, c)
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
