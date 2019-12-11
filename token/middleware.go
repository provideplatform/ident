package token

import (
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/ident/common"
	provide "github.com/provideservices/provide-go"
)

const authorizationHeader = "authorization"

const contextApplicationIDKey = "application_id"
const contextPermissionsKey = "permissions"
const contextSubjectKey = "sub"
const contextTokenKey = "token"
const contextUserIDKey = "user_id"

// AuthMiddleware returns gin middleware for API call authentication and authorization
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := authorize(c)
		if common.IsAuth0(c) {
			common.Log.Debugf("authorizing whitelisted auth0 IP address request with CreateUser permission")
			c.Set(contextTokenKey, &Token{
				Permissions: common.DefaultAuth0RequestPermission,
			})
			c.Set(contextPermissionsKey, common.DefaultAuth0RequestPermission)
		} else if common.IsBanned(c) {
			provide.RenderError(common.BannedErrorMessage, 429, c)
			return
		} else if token != nil && (token.UserID != nil || token.ApplicationID != nil) {
			c.Set(contextSubjectKey, token.Subject)
			c.Set(contextTokenKey, token)
			c.Set(contextPermissionsKey, token.Permissions)

			if token.ApplicationID != nil {
				c.Set(contextApplicationIDKey, token.ApplicationID.String())
			}
			if token.UserID != nil {
				c.Set(contextUserIDKey, token.UserID.String())
			}
		} else {
			provide.RenderError("unauthorized", 401, c)
			c.Abort()
			return
		}
		c.Next()
	}
}

// authorize is a convenience method to parse the presented bearer authorization
// header from the provided context and resolve it to a token instance; if the
// given bearer token is a valid, non-expired JWT, the returned Token instance
// is ephemeral. If the authorization attempt fails, nil is returned.
func authorize(c *gin.Context) *Token {
	jwtToken, err := common.ParseAuthorizationHeader(c, nil)
	if err != nil {
		authorization := strings.Split(c.GetHeader("authorization"), "bearer ")
		token := FindLegacyToken(authorization[len(authorization)-1])
		if token != nil {
			common.Log.Debugf("legacy API token authorized: %s", token.ID) // this is the id in the DB, not the token itself so it's safe to log
			return token
		}
		common.Log.Debugf("failed to parse bearer authorization header; %s", err.Error()) // this is the id in the DB, not the token itself so it's safe to log
		return nil
	}

	var token *Token
	if claims, ok := jwtToken.Claims.(jwt.MapClaims); ok {
		appclaims, appclaimsOk := claims[common.JWTApplicationClaimsKey].(map[string]interface{})

		var appID *uuid.UUID
		var userID *uuid.UUID

		var sub string
		if subclaim, subclaimOk := claims["sub"].(string); subclaimOk {
			sub = subclaim
		}

		subprts := strings.Split(sub, ":")
		if len(subprts) != 2 {
			common.Log.Warningf("valid bearer authorization contained invalid sub claim: %s", sub)
			return nil
		}
		subUUID, err := uuid.FromString(subprts[1])
		if err != nil {
			common.Log.Warningf("valid bearer authorization contained invalid sub claim: %s; %s", sub, err.Error())
			return nil
		}

		switch subprts[0] {
		case "application":
			appID = &subUUID
		case "token":
			// this is a refresh token and can only authorize new access tokens on behalf of a user_id specified in the application claims
			if appclaimsOk {
				if claimedUserID, claimedUserIDOk := appclaims["user_id"].(string); claimedUserIDOk {
					subUUID, err := uuid.FromString(claimedUserID)
					if err != nil {
						common.Log.Warningf("valid bearer authorization contained invalid sub claim: %s; %s", sub, err.Error())
						return nil
					}

					userID = &subUUID
					common.Log.Debugf("authorized refresh token for creation of new access token on behalf of user: %s", userID)
				}
			}
		case "user":
			userID = &subUUID
		}

		var iat *time.Time
		if claims["iat"] != nil {
			iat = parseJWTTimestampClaim(claims, "iat")
		}

		var exp *time.Time
		if claims["exp"] != nil {
			exp = parseJWTTimestampClaim(claims, "exp")
		}

		var nbf *time.Time
		if claims["nbf"] != nil {
			nbf = parseJWTTimestampClaim(claims, "nbf")
		}

		token = &Token{
			Token:         &jwtToken.Raw,
			IssuedAt:      iat,
			ExpiresAt:     exp,
			NotBefore:     nbf,
			Subject:       common.StringOrNil(sub),
			UserID:        userID,
			ApplicationID: appID,
		}

		if aud, audOk := claims["aud"].(string); audOk {
			token.Audience = &aud
		}

		if iss, issOk := claims["iss"].(string); issOk {
			token.Issuer = &iss
		}

		if appclaimsOk {
			if permissions, permissionsOk := appclaims["permissions"].(float64); permissionsOk {
				token.Permissions = common.Permission(permissions)
			} else {
				common.Log.Warningf("valid bearer authorization was permissionless")
			}
		}
	}

	return token
}
