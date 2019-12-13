package application

import (
	"encoding/json"

	"github.com/gin-gonic/gin"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/ident/token"
	provide "github.com/provideservices/provide-go"
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

func applicationsListHandler(c *gin.Context) {
	bearer := token.InContext(c)
	userID := bearer.UserID

	if userID == nil || *userID == uuid.Nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	var hidden = false
	if c.Query("hidden") == "true" {
		hidden = true
	}

	query := dbconf.DatabaseConnection()

	var apps []Application
	query = query.Where("user_id = ? AND hidden = ?", userID, hidden)

	if c.Query("network_id") != "" {
		query = query.Where("network_id = ?", c.Query("network_id"))
	}

	if c.Query("type") != "" {
		query = query.Where("type = ?", c.Query("type"))
	}

	provide.Paginate(c, query, &Application{}).Find(&apps)
	for _, app := range apps {
		mergedConfig := app.mergedConfig()
		mergedConfigJSON, _ := json.Marshal(mergedConfig)
		_mergedConfigJSON := json.RawMessage(mergedConfigJSON)
		*app.Config = _mergedConfigJSON
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

	resp, err := app.Create()
	if err == nil {
		mergedConfig := resp.Application.mergedConfig()
		mergedConfigJSON, _ := json.Marshal(mergedConfig)
		_mergedConfigJSON := json.RawMessage(mergedConfigJSON)
		resp.Application.Config = &_mergedConfigJSON

		provide.Render(resp, 201, c)
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

	if appID != nil && (*appID).String() != c.Param("id") {
		provide.RenderError("forbidden", 403, c)
		return
	}

	var app = &Application{}
	dbconf.DatabaseConnection().Where("id = ?", c.Param("id")).Find(&app)
	if app == nil || app.ID == uuid.Nil {
		provide.RenderError("application not found", 404, c)
		return
	}
	if userID != nil && *userID != app.UserID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	mergedConfig := app.mergedConfig()
	mergedConfigJSON, _ := json.Marshal(mergedConfig)
	_mergedConfigJSON := json.RawMessage(mergedConfigJSON)
	app.Config = &_mergedConfigJSON

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

	if appID != nil && (*appID).String() != c.Param("id") {
		provide.RenderError("forbidden", 403, c)
		return
	}

	var app = &Application{}
	dbconf.DatabaseConnection().Where("id = ?", c.Param("id")).Find(&app)
	if app == nil || app.ID == uuid.Nil {
		provide.RenderError("application not found", 404, c)
		return
	}
	if userID != nil && *userID != app.UserID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	query := dbconf.DatabaseConnection()

	var tokens []*token.Token
	query = query.Where("application_id = ?", app.ID)
	provide.Paginate(c, query, &token.Token{}).Find(&tokens)
	provide.Render(tokens, 200, c)
}
