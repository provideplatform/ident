package organization

import (
	"encoding/json"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/ident/token"
	"github.com/provideapp/ident/user"
	provide "github.com/provideservices/provide-go"
)

// InstallOrganizationAPI installs handlers using the given gin Engine
func InstallOrganizationAPI(r *gin.Engine) {
	r.GET("/api/v1/organizations", organizationsListHandler)
	r.GET("/api/v1/organizations/:id", organizationDetailsHandler)
	r.POST("/api/v1/organizations", createOrganizationHandler)
	r.PUT("/api/v1/organizations/:id", updateOrganizationHandler)
	r.DELETE("/api/v1/organizations/:id", deleteOrganizationHandler)
}

// InstallOrganizationUsersAPI installs the handlers using the given gin Engine
func InstallOrganizationUsersAPI(r *gin.Engine) {
	r.GET("/api/v1/organizations/:id/users", organizationUsersListHandler)
	r.POST("/api/v1/organizations/:id/users", createOrganizationUserHandler)
	r.PUT("/api/v1/organizations/:id/users/:userId", updateOrganizationUserHandler)
	r.DELETE("/api/v1/organizations/:id/users/:userId", deleteOrganizationUserHandler)
}

func resolveOrganization(db *gorm.DB, appID *uuid.UUID) *gorm.DB {
	query := db.Joins("applications_organizations as ao ON ao.organization_id = organizations.id")
	if appID != nil {
		query = query.Where("ao.application_id = ?", appID)
	}
	return query
}

func organizationsListHandler(c *gin.Context) {
	bearer := token.InContext(c)
	applicationID := bearer.ApplicationID

	if applicationID == nil || *applicationID == uuid.Nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	var orgs []*Organization

	query := dbconf.DatabaseConnection()
	query = resolveOrganization(query, applicationID)
	provide.Paginate(c, query, &Organization{}).Find(&orgs)
	provide.Render(orgs, 200, c)
}

func organizationDetailsHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func createOrganizationHandler(c *gin.Context) {
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

	org := &Organization{}
	err = json.Unmarshal(buf, &org)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}
	org.UserID = userID

	if _, permissionsOk := params["permissions"]; permissionsOk {
		provide.RenderError("unable to assert arbitrary organization permissions", 403, c)
		return
	}

	if org.Create() {
		provide.Render(org, 201, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = org.Errors
		provide.Render(obj, 422, c)
	}
}

func updateOrganizationHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func deleteOrganizationHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func organizationUsersListHandler(c *gin.Context) {
	bearer := token.InContext(c)
	applicationID := bearer.ApplicationID

	if applicationID == nil || *applicationID == uuid.Nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	org := &Organization{}
	query := dbconf.DatabaseConnection()
	query = resolveOrganization(query, applicationID).Find(&org)

	if org == nil || org.ID == uuid.Nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	var users []*user.User
	provide.Paginate(c, query.Model(&org).Related(&users, "Users"), &user.User{}).Find(&users)
	provide.Render(users, 200, c)
}

func createOrganizationUserHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func updateOrganizationUserHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func deleteOrganizationUserHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}
