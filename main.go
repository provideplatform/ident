package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideservices/provide-go"
)

const defaultResultsPerPage = 25
const privacyPolicyUpdatedAt = "2018-10-19T00:00:00.000000"
const termsOfServiceUpdatedAt = "2018-10-19T00:00:00.000000"

func main() {
	migrateSchema()
	subscribeNatsStreaming()
	runAPIUsageDaemon()

	r := gin.Default()
	r.Use(gin.Recovery())
	r.Use(provide.CORSMiddleware())
	r.Use(provide.TrackAPICalls())

	InstallApplicationAPI(r)
	InstallTokenAPI(r)
	InstallUserAPI(r)
	InstallKYCAPI(r)

	r.GET("/status", statusHandler)

	if shouldServeTLS() {
		r.RunTLS(listenAddr, certificatePath, privateKeyPath)
	} else {
		r.Run(listenAddr)
	}
}

func bearerAuthToken(c *gin.Context) *Token {
	var token *Token
	keyfn := func(jwtToken *jwt.Token) (interface{}, error) {
		if claims, ok := jwtToken.Claims.(jwt.MapClaims); ok {
			if jti, jtiok := claims["jti"]; jtiok {
				token = &Token{}
				DatabaseConnection().Where("id = ?", jti).Find(&token)
				if token.ID != uuid.Nil {
					return []byte(*token.Secret), nil
				}
			}
		}
		return nil, nil
	}
	provide.ParseBearerAuthorizationHeader(c, &keyfn)
	return token
}

func getAuthorizedApplication(c *gin.Context) *Application {
	token := bearerAuthToken(c)
	if token == nil || token.ApplicationID == nil || *token.ApplicationID == uuid.Nil {
		return nil
	}
	return token.GetApplication()
}

func getAuthorizedUser(c *gin.Context) *User {
	token := bearerAuthToken(c)
	if token == nil || token.UserID == nil || *token.UserID == uuid.Nil {
		return nil
	}
	return token.GetUser()
}

func render(obj interface{}, status int, c *gin.Context) {
	c.Header("content-type", "application/json; charset=UTF-8")
	c.Writer.WriteHeader(status)
	if &obj != nil && status != http.StatusNoContent {
		encoder := json.NewEncoder(c.Writer)
		encoder.SetIndent("", "    ")
		if err := encoder.Encode(obj); err != nil {
			panic(err)
		}
	} else {
		c.Header("content-length", "0")
	}
}

func renderError(message string, status int, c *gin.Context) {
	err := map[string]*string{}
	err["message"] = &message
	render(err, status, c)
}

func requireParams(requiredParams []string, c *gin.Context) error {
	var errs []string
	for _, param := range requiredParams {
		if c.Query(param) == "" {
			errs = append(errs, param)
		}
	}
	if len(errs) > 0 {
		msg := strings.Trim(fmt.Sprintf("missing required parameters: %s", strings.Join(errs, ", ")), " ")
		renderError(msg, 400, c)
		return errors.New(msg)
	}
	return nil
}

func statusHandler(c *gin.Context) {
	status := map[string]interface{}{
		"privacy_policy_updated_at":   privacyPolicyUpdatedAt,
		"terms_of_service_updated_at": termsOfServiceUpdatedAt,
	}
	render(status, 200, c)
}
