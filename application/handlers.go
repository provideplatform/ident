package application

import (
	"encoding/json"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/ident/common"
	"github.com/provideapp/ident/organization"
	"github.com/provideapp/ident/token"
	"github.com/provideapp/ident/user"
	provide "github.com/provideservices/provide-go/common"
)

// InstallApplicationAPI installs the handlers using the given gin Engine
func InstallApplicationAPI(r *gin.Engine) {
	r.GET("/api/v1/applications", applicationsListHandler)
	r.POST("/api/v1/applications", createApplicationHandler)
	r.GET("/api/v1/applications/:id", applicationDetailsHandler)
	r.PUT("/api/v1/applications/:id", updateApplicationHandler)
	r.DELETE("/api/v1/applications/:id", deleteApplicationHandler)

	r.GET("/api/v1/applications/:id/tokens", applicationTokensListHandler)
}

// InstallApplicationOrganizationsAPI installs the handlers using the given gin Engine
func InstallApplicationOrganizationsAPI(r *gin.Engine) {
	r.GET("/api/v1/applications/:id/organizations", applicationOrganizationsListHandler)
	r.POST("/api/v1/applications/:id/organizations", createApplicationOrganizationHandler)
	r.PUT("/api/v1/applications/:id/organizations/:orgId", updateApplicationOrganizationHandler)
	r.DELETE("/api/v1/applications/:id/organizations/:orgId", deleteApplicationOrganizationHandler)
}

// InstallApplicationUsersAPI installs the handlers using the given gin Engine
func InstallApplicationUsersAPI(r *gin.Engine) {
	r.GET("/api/v1/applications/:id/users", applicationUsersListHandler)
	r.POST("/api/v1/applications/:id/users", createApplicationUserHandler)
	r.PUT("/api/v1/applications/:id/users/:userId", updateApplicationUserHandler)
	r.DELETE("/api/v1/applications/:id/users/:userId", deleteApplicationUserHandler)

	r.GET("/api/v1/applications/:id/invitations", applicationInvitationsListHandler)
}

func resolveAppUser(db *gorm.DB, app *Application, userID *uuid.UUID) *user.User {
	if userID == nil {
		return nil
	}
	appUser := &user.User{}
	query := app.UsersListQuery(db)
	query.Where("au.user_id = ?", userID).Find(&appUser)
	if appUser == nil || appUser.ID == uuid.Nil {
		query := db.Select("users.id, users.created_at, users.first_name, users.last_name, ou.permissions as permissions")
		query = query.Joins("LEFT OUTER JOIN applications_organizations as ao ON ao.application_id = ? LEFT OUTER JOIN organizations_users as ou ON ou.organization_id = ao.organization_id", app.ID)
		query = query.Joins("LEFT OUTER JOIN applications_users as au ON au.application_id = ?", app.ID)
		query = query.Where("au.user_id = ? OR (ao.organization_id = ou.organization_id AND ou.user_id = ?)", userID, userID)
		query.Find(&appUser)

		if appUser == nil || appUser.ID == uuid.Nil {
			return nil
		}
	}
	return appUser
}

func applicationsListHandler(c *gin.Context) {
	bearer := token.InContext(c)
	userID := bearer.UserID

	if userID == nil || *userID == uuid.Nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	var apps []Application

	query := dbconf.DatabaseConnection()
	query = query.Select("applications.*")

	if c.Query("hidden") == "true" {
		query = query.Where("applications.hidden IS TRUE")
	} else if c.Query("hidden") == "false" {
		query = query.Where("applications.hidden IS FALSE")
	} else if c.Query("hidden") != "" {
		provide.RenderError("invalid value for hidden query param", 422, c)
		return
	}

	query = query.Joins("LEFT OUTER JOIN applications_organizations as ao ON ao.application_id = applications.id LEFT OUTER JOIN organizations_users as ou ON ou.organization_id = ao.organization_id")
	query = query.Joins("LEFT OUTER JOIN applications_users as au ON au.application_id = applications.id")
	query = query.Where("applications.user_id = ? OR au.user_id = ? OR (ao.organization_id = ou.organization_id AND ou.user_id = ?)", userID, userID, userID)

	if c.Query("network_id") != "" {
		query = query.Where("applications.network_id = ?", c.Query("network_id"))
	}

	if c.Query("type") != "" {
		query = query.Where("applications.type = ?", c.Query("type"))
	}

	query = query.Order("applications.created_at DESC").Group("id")

	provide.Paginate(c, query, &Application{}).Find(&apps)
	for _, app := range apps {
		var cfg map[string]interface{}
		if userID.String() == app.UserID.String() {
			cfg = app.mergedConfig()
		} else {
			cfg = app.ParseConfig()
		}

		cfgJSON, _ := json.Marshal(cfg)
		_cfgJSON := json.RawMessage(cfgJSON)
		*app.Config = _cfgJSON
	}
	provide.Render(apps, 200, c)
}

func createApplicationHandler(c *gin.Context) {
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

	app := &Application{}
	err = json.Unmarshal(buf, app)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}
	app.UserID = *userID

	if app.NetworkID == uuid.Nil {
		cfg := app.ParseConfig()
		if networkID, ok := cfg["network_id"].(string); ok {
			networkUUID, err := uuid.FromString(networkID)
			if err != nil {
				provide.RenderError(err.Error(), 422, c)
				return
			}
			app.NetworkID = networkUUID
		}
	}

	if app.Create(nil) {
		mergedConfig := app.mergedConfig()
		mergedConfigJSON, _ := json.Marshal(mergedConfig)
		_mergedConfigJSON := json.RawMessage(mergedConfigJSON)
		app.Config = &_mergedConfigJSON

		provide.Render(app, 201, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = app.Errors
		provide.Render(obj, 422, c)
	}
}

func applicationDetailsHandler(c *gin.Context) {
	bearer := token.InContext(c)
	userID := bearer.UserID
	appID := bearer.ApplicationID

	if (userID == nil || *userID == uuid.Nil) && (appID == nil || *appID == uuid.Nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	db := dbconf.DatabaseConnection()

	var app = &Application{}
	db.Where("id = ?", c.Param("id")).Find(&app)
	if app == nil || app.ID == uuid.Nil {
		provide.RenderError("application not found", 404, c)
		return
	}

	appUser := resolveAppUser(db, app, userID)
	common.Log.Debugf("APP USER : %s", appUser)

	if appID != nil && appID.String() != c.Param("id") { // FIXME -- test ListApplications permission
		provide.RenderError("forbidden", 403, c)
		return
	} else if bearer.HasAnyPermission(common.ListApplications, common.Sudo) {
		common.Log.Tracef("bearer token authorization grants arbitrary access to application: %s", c.Param("id"))
		_appID, err := uuid.FromString(c.Param("id"))
		if err != nil {
			provide.RenderError(err.Error(), 422, c)
			return
		}
		appID = &_appID
	} else if appUser == nil && userID != nil && !bearer.HasAnyPermission(common.ListApplications, common.Sudo) {
		provide.RenderError("forbidden", 403, c)
		return
	} else if appUser != nil && !appUser.Permissions.Has(common.ReadResources) {
		provide.RenderError("forbidden", 403, c)
		return
	}

	var cfg map[string]interface{}
	if userID != nil && userID.String() == app.UserID.String() {
		cfg = app.mergedConfig()
	} else {
		cfg = app.ParseConfig()
	}

	cfgJSON, _ := json.Marshal(cfg)
	_cfgJSON := json.RawMessage(cfgJSON)
	*app.Config = _cfgJSON

	provide.Render(app, 200, c)
}

func updateApplicationHandler(c *gin.Context) {
	bearer := token.InContext(c)
	if bearer == nil || (bearer.UserID == nil || *bearer.UserID == uuid.Nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	app := &Application{}
	dbconf.DatabaseConnection().Where("id = ?", c.Param("id")).Find(&app)
	if app.ID == uuid.Nil {
		provide.RenderError("app not found", 404, c)
		return
	}

	if bearer.UserID != nil && *bearer.UserID != app.UserID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	err = json.Unmarshal(buf, app)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if app.Update() {
		provide.Render(nil, 204, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = app.Errors
		provide.Render(obj, 422, c)
	}
}

func deleteApplicationHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func applicationTokensListHandler(c *gin.Context) {
	bearer := token.InContext(c)
	userID := bearer.UserID
	appID := bearer.ApplicationID

	if (userID == nil || *userID == uuid.Nil) && (appID == nil || *appID == uuid.Nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	if appID != nil && appID.String() != c.Param("id") {
		provide.RenderError("forbidden", 403, c)
		return
	}

	db := dbconf.DatabaseConnection()

	app := &Application{}
	db.Where("id = ?", c.Param("id")).Find(&app)
	if app == nil || app.ID == uuid.Nil {
		provide.RenderError("application not found", 404, c)
		return
	}

	appUser := resolveAppUser(db, app, userID)
	if appUser == nil && userID != nil && *userID != app.UserID {
		provide.RenderError("forbidden", 403, c)
		return
	} else if appUser != nil && !appUser.Permissions.Has(common.ReadResources) {
		provide.RenderError("forbidden", 403, c)
		return
	}

	var tokens []*token.Token
	query := db.Where("application_id = ?", app.ID)
	provide.Paginate(c, query, &token.Token{}).Find(&tokens)
	provide.Render(tokens, 200, c)
}

func applicationOrganizationsListHandler(c *gin.Context) {
	bearer := token.InContext(c)
	userID := bearer.UserID
	appID := bearer.ApplicationID

	if (userID == nil || *userID == uuid.Nil) && (appID == nil || *appID == uuid.Nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	if appID != nil && (*appID).String() != c.Param("id") {
		provide.RenderError("forbidden", 403, c)
		return
	}

	db := dbconf.DatabaseConnection()

	var app = &Application{}
	db.Where("id = ?", c.Param("id")).Find(&app)
	if app == nil || app.ID == uuid.Nil {
		provide.RenderError("application not found", 404, c)
		return
	}
	if userID != nil && *userID != app.UserID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	var orgs []*organization.Organization
	provide.Paginate(c, app.OrganizationsListQuery(db), &organization.Organization{}).Find(&orgs)
	for _, org := range orgs {
		org.Enrich(db, common.StringOrNil("asymmetric"))
	}
	provide.Render(orgs, 200, c)
}

func createApplicationOrganizationHandler(c *gin.Context) {
	bearer := token.InContext(c)
	appID := bearer.ApplicationID

	if appID == nil || *appID == uuid.Nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	if appID != nil && appID.String() != c.Param("id") {
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

	var organizationID *uuid.UUID
	if orgIDStr, orgIDOk := params["organization_id"].(string); orgIDOk {
		orgID, err := uuid.FromString(orgIDStr)
		if err != nil {
			provide.RenderError(err.Error(), 422, c)
			return
		}
		organizationID = &orgID
	}
	if organizationID == nil || *organizationID == uuid.Nil {
		provide.RenderError("no organization_id provided", 422, c)
		return
	}

	var permissions common.Permission
	orgPermissions, permissionsOk := params["permissions"].(common.Permission)
	if permissionsOk && !bearer.HasAnyExtendedPermission(applicationResourceKey, common.CreateResource, common.GrantResourceAuthorization) {
		provide.RenderError("unable to assert arbitrary application organization permissions", 403, c)
		return
	} else if permissionsOk {
		permissions = orgPermissions
	} else {
		permissions = common.DefaultApplicationOrganizationPermission
	}

	db := dbconf.DatabaseConnection()

	var app = &Application{}
	db.Where("id = ?", c.Param("id")).Find(&app)
	if app == nil || app.ID == uuid.Nil {
		provide.RenderError("application not found", 404, c)
		return
	}

	org := &organization.Organization{}
	db.Where("id = ?", organizationID).Find(&org)
	if org == nil || org.ID == uuid.Nil {
		provide.RenderError("organization not found", 404, c)
		return
	}

	if app.addOrganization(db, *org, permissions) {
		provide.Render(nil, 204, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = org.Errors
		provide.Render(obj, 422, c)
	}
}

func updateApplicationOrganizationHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func deleteApplicationOrganizationHandler(c *gin.Context) {
	bearer := token.InContext(c)
	appID := bearer.ApplicationID
	orgID := bearer.OrganizationID

	if (appID == nil || *appID == uuid.Nil) && (orgID == nil || *orgID == uuid.Nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	if appID != nil && appID.String() != c.Param("id") {
		provide.RenderError("forbidden", 403, c)
		return
	} else if appID == nil {
		_appID, err := uuid.FromString(c.Param("id"))
		if err != nil {
			provide.RenderError(err.Error(), 422, c)
			return
		}
		appID = &_appID
	}

	if orgID != nil && orgID.String() != c.Param("orgId") {
		provide.RenderError("no organization_id provided", 422, c)
		return
	} else if orgID == nil {
		_orgID, err := uuid.FromString(c.Param("orgId"))
		if err != nil {
			provide.RenderError(err.Error(), 422, c)
			return
		}
		orgID = &_orgID
	}

	db := dbconf.DatabaseConnection()

	var app = &Application{}
	db.Where("id = ?", c.Param("id")).Find(&app)
	if app == nil || app.ID == uuid.Nil {
		provide.RenderError("application not found", 404, c)
		return
	}

	org := &organization.Organization{}
	db.Where("id = ?", orgID).Find(&org)
	if org == nil || org.ID == uuid.Nil {
		provide.RenderError("organization not found", 404, c)
		return
	}

	if app.removeOrganization(db, *org) {
		provide.Render(nil, 204, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = org.Errors
		provide.Render(obj, 422, c)
	}
}

func applicationInvitationsListHandler(c *gin.Context) {
	bearer := token.InContext(c)
	userID := bearer.UserID
	appID := bearer.ApplicationID

	if (userID == nil || *userID == uuid.Nil) && (appID == nil || *appID == uuid.Nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	if appID != nil && (*appID).String() != c.Param("id") {
		provide.RenderError("forbidden", 403, c)
		return
	}

	db := dbconf.DatabaseConnection()

	var app = &Application{}
	db.Where("id = ?", c.Param("id")).Find(&app)
	if app == nil || app.ID == uuid.Nil {
		provide.RenderError("application not found", 404, c)
		return
	}

	if userID != nil && *userID != app.UserID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	invitations := app.pendingInvitations() // FIXME-- paginate the in-memory invitations list within redis
	invitedUsers := make([]*user.User, 0)
	for _, invite := range invitations {
		usr := &user.User{
			FirstName: invite.FirstName,
			LastName:  invite.LastName,
			Email:     invite.Email,
		}
		if invite.Permissions != nil {
			usr.Permissions = *invite.Permissions
		}
		invitedUsers = append(invitedUsers, usr)
	}
	provide.Render(invitedUsers, 200, c)
}

func applicationUsersListHandler(c *gin.Context) {
	bearer := token.InContext(c)
	userID := bearer.UserID
	appID := bearer.ApplicationID

	if (userID == nil || *userID == uuid.Nil) && (appID == nil || *appID == uuid.Nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	if appID != nil && (*appID).String() != c.Param("id") {
		provide.RenderError("forbidden", 403, c)
		return
	}

	db := dbconf.DatabaseConnection()

	var app = &Application{}
	db.Where("id = ?", c.Param("id")).Find(&app)
	if app == nil || app.ID == uuid.Nil {
		provide.RenderError("application not found", 404, c)
		return
	}

	if userID != nil && *userID != app.UserID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	var users []*user.User
	provide.Paginate(c, app.UsersListQuery(db), &user.User{}).Find(&users)
	for _, usr := range users {
		usr.Enrich()
	}
	provide.Render(users, 200, c)
}

func createApplicationUserHandler(c *gin.Context) {
	bearer := token.InContext(c)
	appID := bearer.ApplicationID

	if appID == nil || *appID == uuid.Nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	if appID != nil && appID.String() != c.Param("id") {
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

	var userID *uuid.UUID
	if userIDStr, userIDOk := params["user_id"].(string); userIDOk {
		usrID, err := uuid.FromString(userIDStr)
		if err != nil {
			provide.RenderError(err.Error(), 422, c)
			return
		}
		userID = &usrID
	}

	var permissions common.Permission
	appPermissions, permissionsOk := params["permissions"].(common.Permission)
	if permissionsOk && !bearer.HasAnyExtendedPermission(applicationResourceKey, common.CreateResource, common.GrantResourceAuthorization) {
		provide.RenderError("unable to assert arbitrary application user permissions", 403, c)
		return
	} else if permissionsOk {
		permissions = appPermissions
	} else {
		permissions = common.DefaultApplicationResourcePermission
	}

	db := dbconf.DatabaseConnection()

	var app = &Application{}
	db.Where("id = ?", c.Param("id")).Find(&app)
	if app == nil || app.ID == uuid.Nil {
		provide.RenderError("application not found", 404, c)
		return
	}

	usr := &user.User{}
	db.Where("id = ?", userID).Find(&usr)
	if usr == nil || usr.ID == uuid.Nil {
		provide.RenderError("user not found", 404, c)
		return
	}

	if app.addUser(db, *usr, permissions) {
		provide.Render(nil, 204, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = usr.Errors
		provide.Render(obj, 422, c)
	}
}

func updateApplicationUserHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func deleteApplicationUserHandler(c *gin.Context) {
	bearer := token.InContext(c)
	appID := bearer.ApplicationID
	userID := bearer.UserID

	if (appID == nil || *appID == uuid.Nil) && (userID == nil || *userID == uuid.Nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	if appID != nil && appID.String() != c.Param("id") {
		provide.RenderError("forbidden", 403, c)
		return
	} else if appID == nil {
		_appID, err := uuid.FromString(c.Param("id"))
		if err != nil {
			provide.RenderError(err.Error(), 422, c)
			return
		}
		appID = &_appID
	}

	if userID == nil {
		_userID, err := uuid.FromString(c.Param("userId"))
		if err != nil {
			provide.RenderError(err.Error(), 422, c)
			return
		}
		userID = &_userID
	}

	db := dbconf.DatabaseConnection()

	var app = &Application{}
	db.Where("id = ?", c.Param("id")).Find(&app)
	if app == nil || app.ID == uuid.Nil {
		provide.RenderError("application not found", 404, c)
		return
	}

	usr := &user.User{}
	db.Where("id = ?", userID).Find(&usr)
	if usr == nil || usr.ID == uuid.Nil {
		provide.RenderError("user not found", 404, c)
		return
	}

	if app.removeUser(db, *usr) {
		provide.Render(nil, 204, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = usr.Errors
		provide.Render(obj, 422, c)
	}
}
