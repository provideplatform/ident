package main

import (
	"encoding/json"

	"github.com/gin-gonic/gin"
	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideservices/provide-go"
)

// InstallTokenAPI installs the handlers using the given gin Engine
func InstallTokenAPI(r *gin.Engine) {
	r.GET("/api/v1/tokens", tokensListHandler)
	r.POST("/api/v1/tokens", createTokenHandler)
	r.DELETE("/api/v1/tokens/:id", deleteTokenHandler)
}

func tokensListHandler(c *gin.Context) {
	bearer := bearerAuthToken(c)
	if bearer == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	query := DatabaseConnection()

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
	bearer := bearerAuthToken(c)

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
		var app = &Application{}
		DatabaseConnection().Where("id = ?", appID).Find(&app)
		if app != nil && app.ID != uuid.Nil && bearer.UserID != nil && *bearer.UserID != app.UserID {
			provide.RenderError("forbidden", 403, c)
			return
		}
		resp, err := app.CreateToken()
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
	bearer := bearerAuthToken(c)
	if bearer == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	var token = &Token{}
	DatabaseConnection().Where("id = ?", c.Param("id")).Find(&token)
	if token.ID == uuid.Nil {
		provide.RenderError("token not found", 404, c)
		return
	}
	if bearer.UserID != nil && token.UserID != nil && *bearer.UserID != *token.UserID {
		provide.RenderError("forbidden", 403, c)
		return
	}
	if bearer.ApplicationID != nil && token.ApplicationID != nil && *bearer.ApplicationID != *token.ApplicationID {
		provide.RenderError("forbidden", 403, c)
		return
	}
	if !token.Delete() {
		provide.RenderError("token not deleted", 500, c)
		return
	}
	provide.Render(nil, 204, c)
}
