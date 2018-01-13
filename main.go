package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	uuid "github.com/satori/go.uuid"
)

func main() {
	bootstrap()
	migrateSchema()

	r := gin.Default()

	r.GET("/api/v1/applications", applicationsListHandler)
	r.POST("/api/v1/applications", createApplicationHandler)
	r.GET("/api/v1/applications/:id", applicationDetailsHandler)
	r.DELETE("/api/v1/applications/:id", deleteApplicationHandler)

	r.POST("/api/v1/authenticate", authenticationHandler)

	r.GET("/api/v1/tokens", tokensListHandler)
	r.POST("/api/v1/tokens", createTokenHandler)
	r.DELETE("/api/v1/tokens/:id", deleteTokenHandler)

	r.GET("/api/v1/users", usersListHandler)
	r.POST("/api/v1/users", createUserHandler)
	r.DELETE("/api/v1/users/:id", deleteUserHandler)

	r.GET("/status", statusHandler)

	if shouldServeTLS() {
		r.RunTLS(ListenAddr, CertificatePath, PrivateKeyPath)
	} else {
		r.Run(ListenAddr)
	}
}

func authorize(c *gin.Context) *Authenticable {
	var authenticable *Authenticable
	authorization := c.GetHeader("authorization")
	if authorization == "" {
		return nil
	}
	jwt.Parse(authorization, func(*jwt.Token) (interface{}, error) {
		return nil, nil
	})
	return authenticable
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
	render(nil, 204, c)
}

func authenticationHandler(c *gin.Context) {
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

	if email, ok := params["email"].(string); ok {
		if pw, pwok := params["password"].(string); pwok {
			resp, err := AuthenticateUser(email, pw)
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

	renderError("unauthorized", 401, c)
}

// applications

func applicationsListHandler(c *gin.Context) {
	var apps []Application
	DatabaseConnection().Find(&apps)
	render(apps, 200, c)
}

func createApplicationHandler(c *gin.Context) {
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

	if app.Create() {
		render(app, 201, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = app.Errors
		render(obj, 422, c)
	}
}

func applicationDetailsHandler(c *gin.Context) {
	renderError("not implemented", 501, c)
}

func deleteApplicationHandler(c *gin.Context) {
	renderError("not implemented", 501, c)
}

// tokens

func tokensListHandler(c *gin.Context) {
	var tokens []Token
	DatabaseConnection().Find(&tokens)
	render(tokens, 200, c)
}

func createTokenHandler(c *gin.Context) {
	renderError("not implemented", 501, c)
}

func deleteTokenHandler(c *gin.Context) {
	var token = &Token{}
	DatabaseConnection().Where("id = ?", c.Param("id")).Find(&token)
	if token.Id == uuid.Nil {
		renderError("token not found", 404, c)
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
	var users []User
	DatabaseConnection().Find(&users)
	render(users, 200, c)
}

func createUserHandler(c *gin.Context) {
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

	if user.Create() {
		render(user.AsResponse(), 201, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = user.Errors
		render(obj, 422, c)
	}
}

func deleteUserHandler(c *gin.Context) {
	renderError("not implemented", 501, c)
}
