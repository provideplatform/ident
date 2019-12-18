package organization

import (
	"github.com/gin-gonic/gin"
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

func organizationsListHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func organizationDetailsHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func createOrganizationHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func updateOrganizationHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func deleteOrganizationHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func organizationUsersListHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
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
