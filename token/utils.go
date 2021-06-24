package token

import (
	"encoding/json"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/provideplatform/ident/common"
	provide "github.com/provideplatform/provide-go/common"
)

// InContext returns the previously authorized token instance in
// the given gin context, if one exists; this me`thod does not
// attempt to re-authorize the context
func InContext(c *gin.Context) *Token {
	if tok, exists := c.Get(contextTokenKey); exists {
		if token, tokenOk := tok.(*Token); tokenOk {
			return token
		}
	}
	return nil
}

func parseJWTTimestampClaim(claims jwt.MapClaims, claim string) *time.Time {
	var retval *time.Time
	switch timeclaim := claims[claim].(type) {
	case float64:
		timeval := time.Unix(int64(timeclaim), 0)
		retval = &timeval
	case json.Number:
		val, _ := timeclaim.Int64()
		timeval := time.Unix(val, 0)
		retval = &timeval
	default:
		common.Log.Warningf("failed to parse bearer authorization timestamp claim: %s", claim)
		return nil
	}
	return retval
}

// refreshAccessToken authorizes a new access token using the refresh token
// provided as authorization in the given gin context; the subject of a refresh
// token is `token:<jti>`
func refreshAccessToken(c *gin.Context) {
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

		if accessToken.Vend() {
			accessToken.Token = nil
			provide.Render(accessToken.AsResponse(), 201, c)
			return
		}

		var err error
		if len(accessToken.Errors) > 0 {
			err = fmt.Errorf("failed to authorize access token using refresh token on behalf of subject: %s; %s", *accessToken.Subject, *accessToken.Errors[0].Message)
			common.Log.Warningf(err.Error())
			provide.RenderError(err.Error(), 401, c)
			return
		}
	}

	provide.RenderError("unauthorized", 401, c)
}
