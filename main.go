package main

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideservices/provide-go"
)

const defaultResultsPerPage = 25
const privacyPolicyUpdatedAt = "2018-10-19T00:00:00.000000"
const termsOfServiceUpdatedAt = "2018-10-19T00:00:00.000000"

func main() {
	migrateSchema()
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
	jwtToken, err := provide.ParseBearerAuthorizationHeader(c, nil)
	if err != nil {
		return nil
	}
	var token *Token
	if claims, ok := jwtToken.Claims.(jwt.MapClaims); ok {
		if jti, jtiok := claims["jti"]; jtiok {
			token = &Token{}
			DatabaseConnection().Where("id = ?", jti).Find(&token)
			if token == nil || token.ID == uuid.Nil {
				return nil
			}
		}
	}
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

func statusHandler(c *gin.Context) {
	status := map[string]interface{}{
		"privacy_policy_updated_at":   privacyPolicyUpdatedAt,
		"terms_of_service_updated_at": termsOfServiceUpdatedAt,
	}
	provide.Render(status, 200, c)
}
