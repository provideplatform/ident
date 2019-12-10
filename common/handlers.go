package common

import (
	"errors"
	"fmt"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

const authorizationHeader = "authorization"
const defaultResponseContentType = "application/json; charset=UTF-8"
const defaultResultsPerPage = 25
const errorStatus = "error"

// ParseAuthorizationHeader parses a bearer authorization header expecting to find a valid JWT issued and signed by us;
// in the event no valid JWT is found, this method is currently backward compatible with "older" (non-JWT) API tokens.
func ParseAuthorizationHeader(c *gin.Context, keyfunc *func(_jwtToken *jwt.Token) (interface{}, error)) (*jwt.Token, error) {
	authorization := c.GetHeader(authorizationHeader)
	if authorization == "" {
		return nil, errors.New("no authorization header provided")
	}
	hdrprts := strings.Split(authorization, "bearer ")
	if len(hdrprts) != 2 {
		return nil, fmt.Errorf("failed to parse authorization header: %s", authorization)
	}
	authorization = hdrprts[1]
	jwtToken, err := jwt.Parse(authorization, func(_jwtToken *jwt.Token) (interface{}, error) {
		if keyfunc != nil {
			fn := *keyfunc
			return fn(_jwtToken)
		}
		if _, ok := _jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("failed to parse bearer authorization header; unexpected JWT signing algo: %s", _jwtToken.Method.Alg())
		}
		if JWTPublicKey != nil {
			return JWTPublicKey, nil
		}
		return nil, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse bearer authorization header as valid JWT; %s", err.Error())
	}
	return jwtToken, err
}
