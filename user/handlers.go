package user

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/ident/common"
	"github.com/provideapp/ident/token"
	provide "github.com/provideservices/provide-go"
)

// InstallPublicUserAPI installs unauthenticated API handlers using the given gin Engine
func InstallPublicUserAPI(r *gin.Engine) {
	r.POST("/api/v1/authenticate", authenticationHandler)
	r.POST("/api/v1/users", createUserHandler)
	r.POST("/api/v1/users/reset_password", userResetPasswordRequestHandler)
	r.POST("/api/v1/users/reset_password/:token", userResetPasswordHandler)

	r.POST("/api/v1/oauth/callback", oauthCallbackHandler)
}

// InstallUserAPI installs handlers using the given gin Engine which require API authorization
func InstallUserAPI(r *gin.Engine) {
	r.GET("/api/v1/users", usersListHandler)
	r.GET("/api/v1/users/:id", userDetailsHandler)
	r.PUT("/api/v1/users/:id", updateUserHandler)
	r.DELETE("/api/v1/users/:id", deleteUserHandler)

	r.POST("/api/v1/invitations", vendInvitationTokenHandler)
}

func authenticationHandler(c *gin.Context) {
	bearer := token.InContext(c)

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	params := map[string]interface{}{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	var scope *string
	if reqScope, reqScopeOk := params["scope"].(string); reqScopeOk {
		scope = &reqScope
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
						provide.RenderError(msg, 422, c)
						return
					}
					appID = &appUUID
				}

				db := dbconf.DatabaseConnection()
				resp, err := AuthenticateUser(db, email, pw, appID, scope)
				if err != nil {
					provide.RenderError(err.Error(), 401, c)
					return
				}

				if invitationToken, invitationTokenOk := params["invitation_token"].(string); invitationTokenOk {
					invite, err := ParseInvite(invitationToken, false)
					if err != nil {
						provide.RenderError(err.Error(), 422, c)
						return
					}

					user := Find(&resp.User.ID)
					if user != nil && invite != nil {
						err = processUserInvite(db, *user, *invite)
						if err != nil {
							provide.RenderError(err.Error(), 422, c)
							return
						}
					}
				}

				provide.Render(resp, 201, c)
				return
			} else if bearer.ApplicationID != nil {
				resp, err := AuthenticateApplicationUser(email, *bearer.ApplicationID, scope)
				if err != nil {
					provide.RenderError(err.Error(), 401, c)
					return
				}
				provide.Render(resp, 201, c)
				return
			}

			msg := fmt.Sprintf("password required to attempt user authentication; email address: %s", email)
			provide.RenderError(msg, 422, c)
			return
		}
	}

	provide.RenderError("unauthorized", 401, c)
}

func usersListHandler(c *gin.Context) {
	bearer := token.InContext(c)
	if bearer == nil || (bearer.ApplicationID == nil && !bearer.HasAnyPermission(common.ListUsers, common.Sudo)) {
		provide.RenderError("forbidden", 403, c)
		return
	}

	users := []*User{}
	query := dbconf.DatabaseConnection()

	if c.Query("email") != "" {
		query = query.Where("email = ?", strings.ToLower(c.Query("email")))
	}

	query.Find(&users)

	if c.Query("enrich") == "true" {
		for _, usr := range users {
			usr.Enrich()
		}
	}

	provide.Render(users, 200, c)
}

func userDetailsHandler(c *gin.Context) {
	bearer := token.InContext(c)
	if bearer == nil || (!bearer.HasAnyPermission(common.ListUsers, common.Sudo) && bearer.UserID != nil && bearer.UserID.String() != c.Param("id")) {
		provide.RenderError("forbidden", 403, c)
		return
	}

	user := &User{}
	query := dbconf.DatabaseConnection().Where("id = ?", c.Param("id"))
	if bearer.ApplicationID != nil {
		query = query.Where("application_id = ?", bearer.ApplicationID)
	}

	query.Find(&user)
	if user.ID == uuid.Nil {
		provide.RenderError("user not found", 404, c)
		return
	}
	user.Enrich()

	provide.Render(user.AsResponse(), 200, c)
}

func createUserHandler(c *gin.Context) {
	// the following token.InContext method is a no-op now that createUserHandler is registered before AuthMiddleware;
	// current workaround is to use provide.AuthorizedSubjectID() to manually read an application bearer token if one exists
	var bearerApplicationID *uuid.UUID
	bearer := token.InContext(c)
	if bearer != nil && (bearer.ApplicationID == nil && !bearer.HasAnyPermission(common.CreateUser, common.Sudo)) {
		provide.RenderError("forbidden", 403, c)
		return
	} else if bearer != nil {
		bearerApplicationID = bearer.ApplicationID
	} else {
		bearerApplicationID = provide.AuthorizedSubjectID(c, "application")
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	params := map[string]interface{}{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	user := &User{}
	err = json.Unmarshal(buf, user)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	var invite *Invite

	if invitationToken, invitationTokenOk := params["invitation_token"].(string); invitationTokenOk {
		invite, err = ParseInvite(invitationToken, true)
		if err != nil {
			provide.RenderError(err.Error(), 422, c)
			return
		}

		if user.Email == nil {
			user.Email = invite.Email
		}

		if user.FirstName == nil {
			user.FirstName = invite.FirstName
		}

		if user.LastName == nil {
			user.LastName = invite.LastName
		}
	}

	if user.Email == nil {
		provide.RenderError("email address required", 422, c)
		return
	}

	if bearer != nil {
		user.ApplicationID = bearerApplicationID
	} else if appID, appIDOk := params["application_id"].(string); appIDOk {
		appUUID, err := uuid.FromString(appID)
		if err != nil {
			msg := fmt.Sprintf("malformed application_id provided; %s", err.Error())
			provide.RenderError(msg, 422, c)
			return
		}
		user.ApplicationID = &appUUID
	}

	if password, passwordOk := params["password"].(string); passwordOk {
		user.Password = common.StringOrNil(password)
	}

	if _, permissionsOk := params["permissions"]; permissionsOk && (bearer == nil || !bearer.HasAnyPermission(common.UpdateUser, common.Sudo)) {
		provide.RenderError("unable to assert arbitrary user permissions", 403, c)
		return
	}

	if Exists(*user.Email, user.ApplicationID, nil) {
		msg := fmt.Sprintf("user exists: %s", *user.Email)
		provide.RenderError(msg, 409, c)
		return
	}

	createAuth0User := !common.IsAuth0(c) && common.Auth0IntegrationEnabled

	db := dbconf.DatabaseConnection()
	tx := db.Begin()

	success := user.Create(tx, createAuth0User)
	if success && invite != nil {
		err = processUserInvite(tx, *user, *invite)
		if err != nil {
			success = false
			user.Errors = append(user.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}

	if success {
		tx.Commit()
		provide.Render(user.AsResponse(), 201, c)
	} else {
		tx.Rollback()
		obj := map[string]interface{}{}
		obj["errors"] = user.Errors
		provide.Render(obj, 422, c)
	}
}

func processUserInvite(tx *gorm.DB, user User, invite Invite) error {
	success := false

	if invite.OrganizationID != nil {
		orgPermissions := common.DefaultApplicationResourcePermission
		if invite.Permissions != nil {
			orgPermissions = *invite.Permissions
		}
		success = user.addOrganizationAssociation(tx, *invite.OrganizationID, orgPermissions)
		if !success {
			return errors.New("failed to process user invitation; organization association failed")
		}
	} else if invite.ApplicationID != nil && !invite.authorizesNewApplicationOrganization() {
		appPermissions := common.DefaultApplicationResourcePermission
		if invite.Permissions != nil {
			appPermissions = *invite.Permissions
		}
		success = user.addApplicationAssociation(tx, *invite.ApplicationID, appPermissions)
		if !success {
			return errors.New("failed to process user invitation; application association failed")
		}
	} else {
		success = invite.authorizesNewApplicationOrganization()
	}

	if success {
		if !invite.Token.IsRevoked() && !invite.Token.Revoke(tx) {
			return errors.New("failed to process user invitation; token revocation failed")
		}

		go invite.InvalidateCache()
	}

	return nil
}

func updateUserHandler(c *gin.Context) {
	bearer := token.InContext(c)
	if bearer == nil || (bearer.UserID != nil && bearer.UserID.String() != c.Param("id") && !bearer.HasAnyPermission(common.UpdateUser, common.Sudo)) {
		provide.RenderError("forbidden", 403, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	params := map[string]interface{}{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	rehashPassword := false
	if _, pwok := params["password"].(string); pwok {
		rehashPassword = true
	}

	user := &User{}
	dbconf.DatabaseConnection().Where("id = ?", c.Param("id")).Find(&user)
	if user.ID == uuid.Nil {
		provide.RenderError("user not found", 404, c)
		return
	}

	if permissions, permissionsOk := params["permissions"].(float64); permissionsOk && (!bearer.HasAnyPermission(common.UpdateUser, common.Sudo) && common.Permission(permissions) != user.Permissions) {
		provide.RenderError("insufficient permissions to modifiy user permissions", 403, c)
		return
	}

	err = json.Unmarshal(buf, user)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if bearer != nil && !bearer.HasAnyPermission(common.UpdateUser, common.Sudo) {
		user.ApplicationID = bearer.ApplicationID
	}

	if rehashPassword {
		user.Password = common.StringOrNil(params["password"].(string))
		user.rehashPassword()
	}

	if user.Update() {
		provide.Render(nil, 204, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = user.Errors
		provide.Render(obj, 422, c)
	}
}

func deleteUserHandler(c *gin.Context) {
	bearer := token.InContext(c)
	if !bearer.HasAnyPermission(common.DeleteUser, common.Sudo) {
		provide.RenderError("forbidden", 403, c)
		return
	}

	user := &User{}
	query := dbconf.DatabaseConnection().Where("id = ?", c.Param("id"))

	if bearer.ApplicationID != nil {
		query = query.Where("application_id = ?", bearer.ApplicationID.String())
	}

	query.Find(&user)
	if user.ID == uuid.Nil {
		provide.RenderError("user not found", 404, c)
		return
	}

	if user.Delete() {
		provide.Render(nil, 204, c)
	} else {
		provide.RenderError("user deletion failed", 500, c)
	}
}

func userResetPasswordRequestHandler(c *gin.Context) {
	bearer := token.InContext(c)

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	params := map[string]interface{}{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	email, emailOk := params["email"].(string)
	if !emailOk {
		provide.RenderError("email address is required", 422, c)
		return
	}

	db := dbconf.DatabaseConnection()
	user := &User{}
	query := db.Where("email = ?", email)
	if bearer != nil && bearer.ApplicationID != nil {
		query = query.Where("application_id = ?", bearer.ApplicationID.String())
	}
	query.Find(&user)

	if user == nil || user.ID == uuid.Nil {
		provide.RenderError("user not found", 404, c)
		return
	}

	if user.CreateResetPasswordToken(db) {
		provide.Render(user.ResetPasswordTokenResponse(), 201, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = user.Errors
		provide.Render(obj, 422, c)
	}
}

func userResetPasswordHandler(c *gin.Context) {
	bearer := token.InContext(c)

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	params := map[string]interface{}{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
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

	if jwtToken == nil {
		// provide.RenderError(fmt.Sprintf("invalid jwt token; %s", err.Error()), 422, c)
		provide.RenderError("invalid jwt token", 422, c)
		return
	}

	var userID *uuid.UUID
	if claims, ok := jwtToken.Claims.(jwt.MapClaims); ok {
		if sub, subok := claims["sub"].(string); subok {
			subprts := strings.Split(sub, ":")
			if len(subprts) != 2 {
				provide.RenderError(fmt.Sprintf("JWT subject malformed; %s", sub), 422, c)
				return
			}
			if subprts[0] != "user" {
				provide.RenderError(fmt.Sprintf("JWT claims specified non-user subject: %s", subprts[0]), 422, c)
				return
			}
			id, err := uuid.FromString(subprts[1])
			if err != nil {
				provide.RenderError(fmt.Sprintf("invalid user id; %s", err.Error()), 422, c)
				return
			}
			userID = &id
		}
	}

	if userID == nil || *userID == uuid.Nil {
		provide.RenderError("invalid user id", 422, c)
		return
	}

	password, passwordOk := params["password"].(string)
	if !passwordOk {
		provide.RenderError("password is required", 422, c)
		return
	}

	db := dbconf.DatabaseConnection()
	user := &User{}
	query := db.Where("id = ?", userID.String())
	if bearer != nil && bearer.ApplicationID != nil {
		query = query.Where("application_id = ?", bearer.ApplicationID.String())
	}
	query.Find(&user)

	if user == nil || user.ID == uuid.Nil {
		provide.RenderError("user not found", 404, c)
		return
	}

	if user.ResetPasswordToken == nil || *user.ResetPasswordToken != rawToken {
		provide.RenderError("invalid reset token", 422, c)
		return
	}

	user.Password = common.StringOrNil(password)
	user.rehashPassword()

	if user.Update() {
		provide.Render(nil, 204, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = user.Errors
		provide.Render(obj, 422, c)
	}
}

func vendInvitationTokenHandler(c *gin.Context) {
	bearer := token.InContext(c)
	userID := bearer.UserID

	if userID == nil || *userID == uuid.Nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	params := map[string]interface{}{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	invite := &Invite{}
	err = json.Unmarshal(buf, &invite)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if invite.Email == nil {
		provide.RenderError("email address required", 422, c)
		return
	}

	invitor := Find(userID)

	invite.InvitorID = userID
	invite.InvitorName = invitor.FullName()
	// TODO: load invitor permissions in the appropriate context; i.e., in the ApplicationID context if it is set

	_, permissionsOk := params["permissions"]

	if permissionsOk {
		if invite.ApplicationID != nil {
			common.Log.Warningf("arbitrary permissions specified for user application invitation: %s", *invite.Email)
		} else if invite.OrganizationID != nil {
			common.Log.Warningf("arbitrary permissions specified for user organization invitation: %s", *invite.Email)
		} else if !bearer.HasAnyPermission(common.UpdateUser, common.Sudo) {
			provide.RenderError("unable to assert arbitrary user permissions", 403, c)
			return
		}
	}

	if Exists(*invite.Email, invite.ApplicationID, invite.OrganizationID) {
		// FIXME-- check existing user against organization_id if one is provided alongside an application_id
		msg := fmt.Sprintf("user exists: %s", *invite.Email)
		provide.RenderError(msg, 409, c)
		return
	}

	if invite.Create() {
		provide.Render(nil, 204, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = invite.Errors
		provide.Render(obj, 422, c)
	}
}

func oauthCallbackHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}
