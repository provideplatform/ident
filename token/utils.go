package token

import (
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideservices/provide-go"
)

// ParseBearerAuthToken is a convenience method to parse the presented
// bearer authorization header and resolve it to a token instance
func ParseBearerAuthToken(c *gin.Context) *Token {
	jwtToken, err := provide.ParseBearerAuthorizationHeader(c, nil)
	if err != nil {
		return nil
	}
	var token *Token
	if claims, ok := jwtToken.Claims.(jwt.MapClaims); ok {
		if jti, jtiok := claims["jti"]; jtiok {
			token = &Token{}
			dbconf.DatabaseConnection().Where("id = ?", jti).Find(&token)
			if token == nil || token.ID == uuid.Nil {
				return nil
			}
		}
	}
	return token
}
