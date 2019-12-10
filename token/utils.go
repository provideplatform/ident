package token

import (
	"encoding/json"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/provideapp/ident/common"
)

// InContext returns the previously authorized token instance in
// the given gin context, if one exists; this me`thod does not
// attempt to re-authorize the context
func InContext(c *gin.Context) *Token {
	if tok, exists := c.Get("token"); exists {
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
