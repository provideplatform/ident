package token

import (
	"encoding/json"

	"github.com/gin-gonic/gin"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/ident/application"
	provide "github.com/provideservices/provide-go"
)

// InstallTokenAPI installs the handlers using the given gin Engine
func InstallTokenAPI(r *gin.Engine) {
	r.GET("/api/v1/tokens", tokensListHandler)
	r.POST("/api/v1/tokens", createTokenHandler)
	r.DELETE("/api/v1/tokens/:id", deleteTokenHandler)

	r.GET("/api/v1/applications/:id/tokens", applicationTokensListHandler)
}

func tokensListHandler(c *gin.Context) {
	bearer := ParseBearerAuthToken(c)
	if bearer == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	query := dbconf.DatabaseConnection()

	var tokens []Token
	if bearer.ApplicationID != nil && *bearer.ApplicationID != uuid.Nil {
		query = query.Where("application_id = ?", bearer.ApplicationID)
	} else if bearer.UserID != nil && *bearer.UserID != uuid.Nil {
		query = query.Where("user_id = ?", bearer.UserID)
	}
	provide.Paginate(c, query, &Token{}).Find(&tokens)
	provide.Render(tokens, 200, c)
}

func createTokenHandler(c *gin.Context) {
	bearer := ParseBearerAuthToken(c)

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

	var appID *uuid.UUID
	if applicationID, ok := params["application_id"].(string); ok {
		appUUID, err := uuid.FromString(applicationID)
		if err == nil {
			appID = &appUUID
		}
	} else if bearer.ApplicationID != nil && *bearer.ApplicationID != uuid.Nil {
		appID = bearer.ApplicationID
	}

	if appID != nil {
		var app = &application.Application{}
		dbconf.DatabaseConnection().Where("id = ?", appID).Find(&app)
		if app != nil && app.ID != uuid.Nil && bearer.UserID != nil && *bearer.UserID != app.UserID {
			provide.RenderError("forbidden", 403, c)
			return
		}
		resp, err := CreateApplicationToken(&app.ID)
		if err != nil {
			provide.RenderError(err.Error(), 401, c)
			return
		}
		provide.Render(resp, 201, c)
		return
	}

	provide.RenderError("unauthorized", 401, c)
}

func deleteTokenHandler(c *gin.Context) {
	userID := provide.AuthorizedSubjectID(c, "user")
	appID := provide.AuthorizedSubjectID(c, "application")
	if (userID == nil || *userID == uuid.Nil) && (appID == nil || *appID == uuid.Nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	var token = &Token{}
	dbconf.DatabaseConnection().Where("id = ?", c.Param("id")).Find(&token)
	if token.ID == uuid.Nil {
		provide.RenderError("token not found", 404, c)
		return
	}
	if userID != nil && token.UserID != nil && *userID != *token.UserID {
		provide.RenderError("forbidden", 403, c)
		return
	}
	if appID != nil && token.ApplicationID != nil && *appID != *token.ApplicationID {
		provide.RenderError("forbidden", 403, c)
		return
	}
	if !token.Delete() {
		provide.RenderError("token not deleted", 500, c)
		return
	}
	provide.Render(nil, 204, c)
}

func applicationTokensListHandler(c *gin.Context) {
	userID := provide.AuthorizedSubjectID(c, "user")
	appID := provide.AuthorizedSubjectID(c, "application")
	if (userID == nil || *userID == uuid.Nil) && (appID == nil || *appID == uuid.Nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	if appID != nil && (*appID).String() != c.Param("id") {
		provide.RenderError("forbidden", 403, c)
		return
	}

	var app = &application.Application{}
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

	var tokens []*Token
	query = query.Where("application_id = ?", app.ID)
	provide.Paginate(c, query, &Token{}).Find(&tokens)
	provide.Render(tokens, 200, c)
}