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
	bootstrap()
	migrateSchema()

	r := gin.Default()
	r.Use(gin.Recovery())
	r.Use(provide.CORSMiddleware())

	r.GET("/api/v1/applications", applicationsListHandler)
	r.POST("/api/v1/applications", createApplicationHandler)
	r.GET("/api/v1/applications/:id", applicationDetailsHandler)
	r.GET("/api/v1/applications/:id/tokens", applicationTokensListHandler)
	r.PUT("/api/v1/applications/:id", updateApplicationHandler)
	r.DELETE("/api/v1/applications/:id", deleteApplicationHandler)

	r.POST("/api/v1/authenticate", authenticationHandler)

	r.GET("/api/v1/tokens", tokensListHandler)
	r.POST("/api/v1/tokens", createTokenHandler)
	r.DELETE("/api/v1/tokens/:id", deleteTokenHandler)

	r.GET("/api/v1/users", usersListHandler)
	r.GET("/api/v1/users/:id", userDetailsHandler)
	r.POST("/api/v1/users", createUserHandler)
	r.PUT("/api/v1/users/:id", updateUserHandler)
	r.DELETE("/api/v1/users/:id", deleteUserHandler)

	r.GET("/status", statusHandler)

	if shouldServeTLS() {
		r.RunTLS(ListenAddr, CertificatePath, PrivateKeyPath)
	} else {
		r.Run(ListenAddr)
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

func authenticationHandler(c *gin.Context) {
	bearer := bearerAuthToken(c)

	buf, err := c.GetRawData()
	if err != nil {
		renderError(err.Error(), 400, c)
		return
	}

	params := map[string]interface{}{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		renderError(err.Error(), 400, c)
		return
	}

	if bearer == nil || bearer.UserID == nil {
		if email, ok := params["email"].(string); ok {
			if pw, pwok := params["password"].(string); pwok {
				var appID *uuid.UUID
				if bearer != nil {
					appID = bearer.ApplicationID
				}
				resp, err := AuthenticateUser(email, pw, appID)
				if err != nil {
					renderError(err.Error(), 401, c)
					return
				}
				render(resp, 201, c)
				return
			}
			msg := fmt.Sprintf("password required to attempt user authentication; email address: %s", email)
			renderError(msg, 422, c)
			return
		}
	}

	renderError("unauthorized", 401, c)
}

// applications

func applicationsListHandler(c *gin.Context) {
	user := getAuthorizedUser(c)
	if user == nil || user.ID == uuid.Nil {
		renderError("unauthorized", 401, c)
		return
	}

	var hidden = false
	if c.Query("hidden") == "true" {
		hidden = true
	}

	query := DatabaseConnection()

	var apps []Application
	query = query.Where("user_id = ? AND hidden = ?", user.ID, hidden)

	if c.Query("network_id") != "" {
		query = query.Where("network_id = ?", c.Query("network_id"))
	}

	provide.Paginate(c, query, &Application{}).Find(&apps)
	render(apps, 200, c)
}

func createApplicationHandler(c *gin.Context) {
	user := getAuthorizedUser(c)
	if user == nil {
		renderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		renderError(err.Error(), 400, c)
		return
	}

	app := &Application{}
	err = json.Unmarshal(buf, app)
	if err != nil {
		renderError(err.Error(), 422, c)
		return
	}
	app.UserID = user.ID

	if app.NetworkID == uuid.Nil {
		cfg := app.ParseConfig()
		if networkID, ok := cfg["network_id"].(string); ok {
			networkUUID, err := uuid.FromString(networkID)
			if err != nil {
				renderError(err.Error(), 422, c)
				return
			}
			app.NetworkID = networkUUID
		}
	}

	if app.Create() {
		render(app, 201, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = app.Errors
		render(obj, 422, c)
	}
}

func applicationDetailsHandler(c *gin.Context) {
	bearer := bearerAuthToken(c)
	if bearer == nil {
		renderError("unauthorized", 401, c)
		return
	}
	if bearer.ApplicationID != nil && bearer.ApplicationID.String() != c.Param("id") {
		renderError("forbidden", 403, c)
		return
	}

	var app = &Application{}
	DatabaseConnection().Where("id = ?", c.Param("id")).Find(&app)
	if app.ID == uuid.Nil {
		renderError("application not found", 404, c)
		return
	}
	if bearer.UserID != nil && *bearer.UserID != app.UserID {
		renderError("forbidden", 403, c)
		return
	}
	render(app, 200, c)
}

func updateApplicationHandler(c *gin.Context) {
	bearer := bearerAuthToken(c)
	if bearer != nil && bearer.UserID == nil {
		renderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		renderError(err.Error(), 400, c)
		return
	}

	app := &Application{}
	DatabaseConnection().Where("id = ?", c.Param("id")).Find(&app)
	if app.ID == uuid.Nil {
		renderError("app not found", 404, c)
		return
	}

	if bearer.UserID != nil && *bearer.UserID != app.UserID {
		renderError("forbidden", 403, c)
		return
	}

	err = json.Unmarshal(buf, app)
	if err != nil {
		renderError(err.Error(), 422, c)
		return
	}

	if app.Update() {
		render(nil, 204, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = app.Errors
		render(obj, 422, c)
	}
}

func deleteApplicationHandler(c *gin.Context) {
	renderError("not implemented", 501, c)
}

func applicationTokensListHandler(c *gin.Context) {
	bearer := bearerAuthToken(c)
	if bearer == nil {
		renderError("unauthorized", 401, c)
		return
	}
	if bearer.ApplicationID != nil && bearer.ApplicationID.String() != c.Param("id") {
		renderError("forbidden", 403, c)
		return
	}

	var app = &Application{}
	DatabaseConnection().Where("id = ?", c.Param("id")).Find(&app)
	if app.ID == uuid.Nil {
		renderError("application not found", 404, c)
		return
	}
	if bearer.UserID != nil && *bearer.UserID != app.UserID {
		renderError("forbidden", 403, c)
		return
	}

	query := DatabaseConnection()

	var tokens []*Token
	query = query.Where("application_id = ?", app.ID)
	provide.Paginate(c, query, &Token{}).Find(&tokens)
	render(app.GetTokens(), 200, c)
}

// tokens

func tokensListHandler(c *gin.Context) {
	bearer := bearerAuthToken(c)
	if bearer == nil {
		renderError("unauthorized", 401, c)
		return
	}

	query := DatabaseConnection()

	var tokens []Token
	if bearer.ApplicationID != nil {
		query = query.Where("application_id = ?", bearer.ApplicationID)
	} else if bearer.UserID != nil {
		query = query.Where("user_id = ?", bearer.UserID)
	}
	provide.Paginate(c, query, &Token{}).Find(&tokens)
	render(tokens, 200, c)
}

func createTokenHandler(c *gin.Context) {
	bearer := bearerAuthToken(c)

	buf, err := c.GetRawData()
	if err != nil {
		renderError(err.Error(), 400, c)
		return
	}

	params := map[string]interface{}{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		renderError(err.Error(), 400, c)
		return
	}

	var appID *uuid.UUID
	if applicationID, ok := params["application_id"].(string); ok {
		appUUID, err := uuid.FromString(applicationID)
		if err == nil {
			appID = &appUUID
		}
	} else if bearer.ApplicationID != nil {
		appID = bearer.ApplicationID
	}

	if appID != nil {
		var app = &Application{}
		DatabaseConnection().Where("id = ?", appID).Find(&app)
		if app != nil && app.ID != uuid.Nil && bearer.UserID != nil && *bearer.UserID != app.UserID {
			renderError("forbidden", 403, c)
			return
		}
		resp, err := app.CreateToken()
		if err != nil {
			renderError(err.Error(), 401, c)
			return
		}
		render(resp, 201, c)
		return
	}

	renderError("unauthorized", 401, c)
}

func deleteTokenHandler(c *gin.Context) {
	bearer := bearerAuthToken(c)
	if bearer == nil {
		renderError("unauthorized", 401, c)
		return
	}

	var token = &Token{}
	DatabaseConnection().Where("id = ?", c.Param("id")).Find(&token)
	if token.ID == uuid.Nil {
		renderError("token not found", 404, c)
		return
	}
	if bearer.UserID != nil && token.UserID != nil && *bearer.UserID != *token.UserID {
		renderError("forbidden", 403, c)
		return
	}
	if bearer.ApplicationID != nil && token.ApplicationID != nil && *bearer.ApplicationID != *token.ApplicationID {
		renderError("forbidden", 403, c)
		return
	}
	if !token.Delete() {
		renderError("token not deleted", 500, c)
		return
	}
	render(nil, 204, c)
}

// users

func usersListHandler(c *gin.Context) {
	bearer := bearerAuthToken(c)
	if bearer == nil || bearer.ApplicationID == nil {
		renderError("unauthorized", 401, c)
		return
	}

	var users []User
	query := DatabaseConnection()
	query = query.Where("application_id = ?", bearer.ApplicationID.String())
	provide.Paginate(c, query, &User{}).Find(&users)
	render(users, 200, c)
}

func userDetailsHandler(c *gin.Context) {
	bearer := bearerAuthToken(c)
	if bearer == nil || (bearer != nil && bearer.ApplicationID == nil && bearer.UserID == nil) {
		renderError("unauthorized", 401, c)
		return
	}

	if bearer.UserID != nil && bearer.UserID.String() != c.Param("id") {
		renderError("forbidden", 403, c)
		return
	}

	user := &User{}
	query := DatabaseConnection().Where("id = ?", c.Param("id"))
	if bearer.ApplicationID != nil {
		query = query.Where("application_id = ?", bearer.ApplicationID)
	}

	query.Find(&user)
	if user.ID == uuid.Nil {
		renderError("user not found", 404, c)
		return
	}

	render(user, 200, c)
}

func createUserHandler(c *gin.Context) {
	bearer := bearerAuthToken(c)
	if bearer != nil && bearer.ApplicationID == nil {
		renderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		renderError(err.Error(), 400, c)
		return
	}

	user := &User{}
	err = json.Unmarshal(buf, user)
	if err != nil {
		renderError(err.Error(), 422, c)
		return
	}

	if bearer != nil {
		user.ApplicationID = bearer.ApplicationID
	}

	if user.Create() {
		render(user.AsResponse(), 201, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = user.Errors
		render(obj, 422, c)
	}
}

func updateUserHandler(c *gin.Context) {
	bearer := bearerAuthToken(c)
	if bearer == nil || (bearer != nil && bearer.ApplicationID == nil && bearer.UserID == nil) {
		renderError("unauthorized", 401, c)
		return
	}

	if bearer.UserID != nil && bearer.UserID.String() != c.Param("id") {
		renderError("forbidden", 403, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		renderError(err.Error(), 400, c)
		return
	}

	params := map[string]interface{}{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		renderError(err.Error(), 400, c)
		return
	}

	rehashPassword := false
	if _, pwok := params["password"].(string); pwok {
		rehashPassword = true
	}

	user := &User{}
	DatabaseConnection().Where("id = ?", c.Param("id")).Find(&user)
	if user.ID == uuid.Nil {
		renderError("user not found", 404, c)
		return
	}

	err = json.Unmarshal(buf, user)
	if err != nil {
		renderError(err.Error(), 422, c)
		return
	}

	if bearer != nil {
		user.ApplicationID = bearer.ApplicationID
	}

	if rehashPassword {
		user.rehashPassword()
	}

	if user.Update() {
		render(nil, 204, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = user.Errors
		render(obj, 422, c)
	}
}

func deleteUserHandler(c *gin.Context) {
	renderError("not implemented", 501, c)
}
