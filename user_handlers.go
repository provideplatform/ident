package main

import (
	"encoding/json"
	"fmt"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideservices/provide-go"
)

// InstallUserAPI installs the handlers using the given gin Engine
func InstallUserAPI(r *gin.Engine) {
	r.POST("/api/v1/authenticate", authenticationHandler)

	r.GET("/api/v1/users", usersListHandler)
	r.GET("/api/v1/users/:id", userDetailsHandler)
	r.GET("/api/v1/users/:id/kyc_applications", userKYCApplicationsListHandler)
	r.POST("/api/v1/users/reset_password", userResetPasswordRequestHandler)
	r.POST("/api/v1/users/reset_password/:token", userResetPasswordHandler)
	r.POST("/api/v1/users", createUserHandler)
	r.PUT("/api/v1/users/:id", updateUserHandler)
	r.DELETE("/api/v1/users/:id", deleteUserHandler)
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
				if bearer != nil && bearer.ApplicationID != nil && *bearer.ApplicationID != uuid.Nil {
					appID = bearer.ApplicationID
				} else if applicationID, applicationIDOk := params["application_id"].(string); applicationIDOk {
					appUUID, err := uuid.FromString(applicationID)
					if err != nil {
						msg := fmt.Sprintf("malformed application_id provided; %s", err.Error())
						renderError(msg, 422, c)
						return
					}
					appID = &appUUID
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

func userKYCApplicationsListHandler(c *gin.Context) {
	bearer := bearerAuthToken(c)
	if bearer == nil || (bearer != nil && bearer.ApplicationID == nil && bearer.UserID == nil) {
		renderError("unauthorized", 401, c)
		return
	}

	if bearer.UserID == nil {
		// HACK: only support KYC for user_id
		renderError("unauthorized", 401, c)
		return
	}

	var kycApplications []KYCApplication
	query := dbconf.DatabaseConnection().Where("user_id = ?", bearer.UserID)

	if c.Query("status") != "" {
		query = query.Where("status = ?", c.Query("status"))
	}

	query = query.Order("created_at DESC")
	provide.Paginate(c, query, &KYCApplication{}).Find(&kycApplications)
	render(kycApplications, 200, c)
}

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

	params := map[string]interface{}{}
	err = json.Unmarshal(buf, &params)
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
	} else if appID, appIDOk := params["application_id"].(string); appIDOk {
		appUUID, err := uuid.FromString(appID)
		if err != nil {
			msg := fmt.Sprintf("malformed application_id provided; %s", err.Error())
			renderError(msg, 422, c)
			return
		}
		user.ApplicationID = &appUUID
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

func userResetPasswordRequestHandler(c *gin.Context) {
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

	email, emailOk := params["email"].(string)
	if !emailOk {
		renderError("email address is required", 422, c)
		return
	}

	db := DatabaseConnection()
	user := &User{}
	query := db.Where("email = ?", email)
	if bearer != nil && bearer.ApplicationID != nil {
		query = query.Where("application_id = ?", bearer.ApplicationID.String())
	}
	query.Find(&user)

	if user == nil || user.ID == uuid.Nil {
		renderError("user not found", 404, c)
		return
	}

	if user.CreateResetPasswordToken(db) {
		render(user.ResetPasswordTokenResponse(), 201, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = user.Errors
		render(obj, 422, c)
	}
}

func userResetPasswordHandler(c *gin.Context) {
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

	rawToken := c.Param("token")
	jwtToken, err := jwt.Parse(rawToken, func(_jwtToken *jwt.Token) (interface{}, error) {
		// if keyfunc != nil {
		// 	fn := *keyfunc
		// 	return fn(_jwtToken)
		// }
		return nil, nil
	})

	if err != nil {
		renderError(fmt.Sprintf("invalid jwt token; %s", err.Error()), 422, c)
		return
	}

	var userID *uuid.UUID
	if claims, ok := jwtToken.Claims.(jwt.MapClaims); ok {
		if sub, subok := claims["sub"].(string); subok {
			subprts := strings.Split(sub, ":")
			if len(subprts) != 2 {
				renderError(fmt.Sprintf("JWT subject malformed; %s", sub), 422, c)
				return
			}
			if subprts[0] != "user" {
				renderError(fmt.Sprintf("JWT claims specified non-user subject: %s", subprts[0]), 422, c)
				return
			}
			id, err := uuid.FromString(subprts[1])
			if err != nil {
				renderError(fmt.Sprintf("invalid user id; %s", err.Error()), 422, c)
				return
			}
			userID = &id
		}
	}

	if userID == nil || *userID == uuid.Nil {
		renderError("invalid user id", 422, c)
		return
	}

	password, passwordOk := params["password"].(string)
	if !passwordOk {
		renderError("password is required", 422, c)
		return
	}

	db := DatabaseConnection()
	user := &User{}
	query := db.Where("id = ?", userID.String())
	if bearer != nil && bearer.ApplicationID != nil {
		query = query.Where("application_id = ?", bearer.ApplicationID.String())
	}
	query.Find(&user)

	if user == nil || user.ID == uuid.Nil {
		renderError("user not found", 404, c)
		return
	}

	if user.ResetPasswordToken == nil || *user.ResetPasswordToken != rawToken {
		renderError("invalid reset token", 422, c)
		return
	}

	user.Password = stringOrNil(password)
	user.rehashPassword()

	if user.Update() {
		render(user.ResetPasswordTokenResponse(), 201, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = user.Errors
		render(obj, 422, c)
	}
}

func deleteUserHandler(c *gin.Context) {
	renderError("not implemented", 501, c)
}
