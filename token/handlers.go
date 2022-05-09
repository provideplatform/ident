package token

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"

	// "github.com/provideplatform/ident/application"
	"github.com/provideplatform/ident/common"
	provide "github.com/provideplatform/provide-go/common"
	util "github.com/provideplatform/provide-go/common/util"
)

// InstallPublicOAuthAPI installs unauthenticated API handlers using the given gin Engine
func InstallPublicOAuthAPI(r *gin.Engine) {
	r.GET("/api/v1/oauth/authorize", oauthAuthorizeHandler)
}

// InstallTokenAPI installs the handlers using the given gin Engine
func InstallTokenAPI(r *gin.Engine) {
	r.GET("/api/v1/tokens", tokensListHandler)
	r.POST("/api/v1/tokens", createTokenHandler)
	r.DELETE("/api/v1/tokens/:id", deleteTokenHandler)

	// r.GET("/api/v1/applications/:id/tokens", applicationTokensListHandler)
}

// FetchJWKsHandler returns a list of JWKs suitable for public consumption under a well-known path
func FetchJWKsHandler(c *gin.Context) {
	jwks, _ := common.ResolveJWKs()
	provide.Render(jwks, 200, c)
}

func tokensListHandler(c *gin.Context) {
	bearer := InContext(c)

	var tokens []*Token
	query := dbconf.DatabaseConnection()

	if bearer.HasAnyPermission(common.ListTokens, common.Sudo) && c.Query("user_id") != "" {
		// sudo arbitrary filtering by user_id
		query = query.Where("user_id = ?", c.Query("user_id"))
	} else if bearer.ApplicationID != nil && *bearer.ApplicationID != uuid.Nil {
		query = query.Where("application_id = ?", bearer.ApplicationID)
	} else if bearer.UserID != nil && *bearer.UserID != uuid.Nil {
		query = query.Where("user_id = ?", bearer.UserID)
	} else {
		provide.RenderError("forbidden", 403, c)
		return
	}

	provide.Paginate(c, query, &Token{}).Find(&tokens)
	provide.Render(tokens, 200, c)
}

func createTokenHandler(c *gin.Context) {
	bearer := InContext(c)

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	params := map[string]interface{}{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	var scope *string
	if reqScope, reqScopeOk := params["scope"].(string); reqScopeOk {
		scope = &reqScope
	}

	var grantType *string
	if reqGrantType, reqGrantTypeOk := params["grant_type"].(string); reqGrantTypeOk {
		grantType = &reqGrantType
	}

	if grantType != nil && (*grantType != authorizationGrantAuthorizationCode && *grantType != authorizationGrantClientCredentials && *grantType != authorizationGrantRefreshToken) {
		provide.RenderError(fmt.Sprintf("invalid grant_type: %s", *grantType), 422, c)
		return
	} else if grantType != nil && strings.EqualFold(*grantType, authorizationGrantRefreshToken) {
		refreshAccessToken(c, scope)
		return
	}

	var appID *uuid.UUID
	if applicationID, ok := params["application_id"].(string); ok {
		appUUID, err := uuid.FromString(applicationID)
		if err == nil {
			appID = &appUUID
		}
	} else if bearer.ApplicationID != nil && *bearer.ApplicationID != uuid.Nil {
		appID = bearer.ApplicationID
	}

	var orgID *uuid.UUID
	if organizationID, ok := params["organization_id"].(string); ok {
		orgUUID, err := uuid.FromString(organizationID)
		if err == nil {
			orgID = &orgUUID
		}
	} else if bearer.OrganizationID != nil && *bearer.OrganizationID != uuid.Nil {
		orgID = bearer.OrganizationID
	}

	var userID *uuid.UUID
	if usrID, ok := params["user_id"].(string); ok {
		userUUID, err := uuid.FromString(usrID)
		if err == nil {
			userID = &userUUID
		}
	} else if bearer.UserID != nil && *bearer.UserID != uuid.Nil {
		userID = bearer.UserID
	}

	var audience *string
	if aud, audOk := params["aud"].(string); audOk {
		altAudience, altAudienceOk := util.JWTAlternativeAuthorizationAudiences[aud].(string)
		if !altAudienceOk {
			provide.RenderError(fmt.Sprintf("invalid aud: %s", aud), 400, c)
			return
		}
		audience = &altAudience
	}

	var permissions common.Permission

	if userID != nil {
		db := dbconf.DatabaseConnection()
		var out []int64

		if orgID != nil {
			db.Table("organizations_users").Select("permissions").Where("organizations_users.organization_id = ? AND organizations_users.user_id = ?", orgID.String(), userID.String()).Pluck("permissions", &out)
			if len(out) == 0 {
				msg := fmt.Sprintf("permissions lookup failed for organization: %s", userID)
				common.Log.Warning(msg)
				provide.RenderError(msg, 500, c)
				return
			}

			permissions = common.Permission(out[0])
		} else {
			db.Table("users").Select("permissions").Where("users.id = ?", userID.String()).Pluck("permissions", &out)
			if len(out) == 0 {
				msg := fmt.Sprintf("permissions lookup failed for user: %s", userID)
				common.Log.Warning(msg)
				provide.RenderError(msg, 500, c)
				return
			}

			permissions = common.Permission(out[0])
		}
	}

	tkn := &Token{
		Audience:       audience,
		ApplicationID:  appID,
		OrganizationID: orgID,
		Permissions:    permissions,
		UserID:         userID,
		Scope:          scope,
	}

	if appID != nil && !tkn.HasScope(authorizationScopeOfflineAccess) {
		// overwrite tkn
		db := dbconf.DatabaseConnection()
		tkn, err = VendApplicationToken(db, appID, orgID, userID, nil, audience, scope)
		if err != nil {
			provide.RenderError(err.Error(), 401, c)
			return
		}
		provide.Render(tkn.AsResponse(), 201, c)
		return
	}

	if !tkn.Vend() {
		if len(tkn.Errors) > 0 {
			provide.RenderError(*tkn.Errors[0].Message, 401, c)
		} else {
			provide.RenderError("failed to vend token", 401, c)
		}
		return
	}

	if grantType != nil {
		switch *grantType {
		case authorizationGrantAuthorizationCode:
			authorizeCode(c, tkn)
		case authorizationGrantClientCredentials:
			authorizeClientCredentials(c)
		case authorizationGrantRefreshToken:
			refreshAccessToken(c, scope)
		default:
			// no-op -- unreachable
		}

		return
	}

	provide.Render(tkn.AsResponse(), 201, c)
}

func deleteTokenHandler(c *gin.Context) {
	bearer := InContext(c)
	var userID *uuid.UUID
	var appID *uuid.UUID

	if bearer != nil {
		userID = bearer.UserID
		appID = bearer.ApplicationID
	}

	if bearer == nil || ((userID == nil || *userID == uuid.Nil) && (appID == nil || *appID == uuid.Nil) && !bearer.HasAnyPermission(common.DeleteToken, common.Sudo)) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	db := dbconf.DatabaseConnection()
	tx := db.Begin()
	defer tx.RollbackUnlessCommitted()

	var token = &Token{}

	if bearer.HasAnyPermission(common.DeleteToken, common.Sudo) {
		tx.Where("id = ?", c.Param("id")).Find(&token)
	} else {
		tx = tx.Where("id = ?", c.Param("id"))
		if bearer.UserID != nil {
			tx = tx.Where("user_id = ?", bearer.UserID)
		}
		if bearer.ApplicationID != nil {
			tx = tx.Where("application_id = ?", bearer.ApplicationID)
		}
		tx.Find(&token)
	}

	if token.ID == uuid.Nil {
		provide.RenderError("token not found", 404, c)
		return
	}
	if userID != nil && token.UserID != nil && *userID != *token.UserID {
		provide.RenderError("forbidden", 403, c)
		return
	}
	if appID != nil && token.ApplicationID != nil && *appID != *token.ApplicationID {
		provide.RenderError("forbidden", 403, c)
		return
	}
	if !token.Delete(tx) {
		provide.RenderError("token not deleted", 500, c)
		return
	}

	tx.Commit()
	provide.Render(nil, 204, c)
}

func oauthAuthorizeHandler(c *gin.Context) {
	clientID := c.Query("client_id")
	appID, err := uuid.FromString(clientID)
	if err != nil {
		provide.RenderError("failed to parse client_id as valid application id", 422, c)
		return
	}

	responseType := common.StringOrNil(c.Query("response_type"))
	if responseType == nil || *responseType != authorizationGrantResponseTypeCode {
		provide.RenderError("response_type must be set to 'code'", 422, c)
		return
	}

	scope := common.StringOrNil(c.Query("scope"))
	ttl := int(defaultOAuthCodeTTL.Seconds())

	code := &Token{
		ApplicationID: &appID,
		OAuthAuthorizationGrant: &OAuthAuthorizationGrantParams{
			CodeChallenge:       common.StringOrNil(c.Query("code_challenge")),
			CodeChallengeMethod: common.StringOrNil(c.Query("code_challenge_method")),
			RedirectURI:         common.StringOrNil(c.Query("redirect_uri")),
			Scope:               scope,
			State:               common.StringOrNil(c.Query("state")),
			TokenType:           common.StringOrNil(oauthAuthorizationGrantDefaultTokenType),
		},
		Scope: scope,
		TTL:   &ttl,
	}

	db := dbconf.DatabaseConnection()
	code, err = VendApplicationToken(db, &appID, nil, nil, nil, nil, scope)
	if err != nil {
		provide.RenderError(err.Error(), 401, c)
		return
	}

	location := oauthAuthorizationGrantRedirectLocationFactory(&OAuthAuthorizationGrantParams{
		Code:  code.AccessToken,
		State: common.StringOrNil(c.Query("state")),
	})
	if location == nil {
		provide.RenderError("failed to authorize short-lived authorization code; failed to build redirect uri", 500, c)
		return
	}

	c.Redirect(302, *location)
}
