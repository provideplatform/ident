package main

import (
	"encoding/json"

	"github.com/gin-gonic/gin"
	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideservices/provide-go"
)

// InstallApplicationAPI installs the handlers using the given gin Engine
func InstallApplicationAPI(r *gin.Engine) {
	r.GET("/api/v1/applications", applicationsListHandler)
	r.POST("/api/v1/applications", createApplicationHandler)
	r.GET("/api/v1/applications/:id", applicationDetailsHandler)
	r.GET("/api/v1/applications/:id/tokens", applicationTokensListHandler)
	r.PUT("/api/v1/applications/:id", updateApplicationHandler)
	r.DELETE("/api/v1/applications/:id", deleteApplicationHandler)
}

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
