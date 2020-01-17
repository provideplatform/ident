package token

import (
	"encoding/json"

	"github.com/gin-gonic/gin"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	// "github.com/provideapp/ident/application"
	"github.com/provideapp/ident/common"
	provide "github.com/provideservices/provide-go"
)

// InstallTokenAPI installs the handlers using the given gin Engine
func InstallTokenAPI(r *gin.Engine) {
	r.GET("/api/v1/tokens", tokensListHandler)
	r.POST("/api/v1/tokens", createTokenHandler)
	r.DELETE("/api/v1/tokens/:id", deleteTokenHandler)

	// r.GET("/api/v1/applications/:id/tokens", applicationTokensListHandler)
}

func tokensListHandler(c *gin.Context) {
	bearer := InContext(c)

	var tokens []*Token
	query := dbconf.DatabaseConnection()

	if bearer.HasAnyPermission(common.ListTokens, common.Sudo) && c.Query("user_id") != "" {
		// sudo arbitrary filtering by user_id
		query = query.Where("user_id = ?", c.Query("user_id"))
	} else if bearer.ApplicationID != nil && *bearer.ApplicationID != uuid.Nil {
		query = query.Where("application_id = ?", bearer.ApplicationID)
	} else if bearer.UserID != nil && *bearer.UserID != uuid.Nil {
		query = query.Where("user_id = ?", bearer.UserID)
	} else {
		provide.RenderError("forbidden", 403, c)
		return
	}

	provide.Paginate(c, query, &Token{}).Find(&tokens)
	provide.Render(tokens, 200, c)
}

func createTokenHandler(c *gin.Context) {
	bearer := InContext(c)

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

	var grantType *string
	if reqGrantType, reqGrantTypeOk := params["grant_type"].(string); reqGrantTypeOk {
		grantType = &reqGrantType
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
		var orgID *uuid.UUID
		if organizationID, ok := params["organization_id"].(string); ok {
			orgUUID, err := uuid.FromString(organizationID)
			if err == nil {
				orgID = &orgUUID
			}
		} else if bearer.OrganizationID != nil && *bearer.OrganizationID != uuid.Nil {
			orgID = bearer.OrganizationID
		}

		db := dbconf.DatabaseConnection()
		resp, err := VendApplicationToken(db, appID, orgID, nil, nil) // FIXME-- support users and extended permissions
		if err != nil {
			provide.RenderError(err.Error(), 401, c)
			return
		}
		provide.Render(resp.AsResponse(), 201, c)
		return
	} else if grantType != nil && *grantType == authorizationGrantRefreshToken {
		refreshAccessToken(c)
		return
	}

	provide.RenderError("unauthorized", 401, c)
}

func deleteTokenHandler(c *gin.Context) {
	bearer := InContext(c)
	userID := bearer.UserID
	appID := bearer.ApplicationID
	if bearer == nil || ((userID == nil || *userID == uuid.Nil) && (appID == nil || *appID == uuid.Nil) && !bearer.HasAnyPermission(common.DeleteToken, common.Sudo)) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	db := dbconf.DatabaseConnection()

	var token = &Token{}

	if bearer.HasAnyPermission(common.DeleteToken, common.Sudo) {
		db.Where("id = ?", c.Param("id")).Find(&token)
	} else {
		query := db.Where("id = ?", c.Param("id"))
		if bearer.UserID != nil {
			query = query.Where("user_id = ?", bearer.UserID)
		}
		if bearer.ApplicationID != nil {
			query = query.Where("application_id = ?", bearer.ApplicationID)
		}
		query.Find(&token)
	}

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

// func applicationTokensListHandler(c *gin.Context) {
// 	bearer := InContext(c)
// 	userID := bearer.UserID
// 	appID := bearer.ApplicationID
// 	if (userID == nil || *userID == uuid.Nil) && (appID == nil || *appID == uuid.Nil) {
// 		provide.RenderError("unauthorized", 401, c)
// 		return
// 	}

// 	if appID != nil && (*appID).String() != c.Param("id") {
// 		provide.RenderError("forbidden", 403, c)
// 		return
// 	}

// 	var app = &application.Application{}
// 	dbconf.DatabaseConnection().Where("id = ?", c.Param("id")).Find(&app)
// 	if app == nil || app.ID == uuid.Nil {
// 		provide.RenderError("application not found", 404, c)
// 		return
// 	}
// 	if userID != nil && *userID != app.UserID {
// 		provide.RenderError("forbidden", 403, c)
// 		return
// 	}

// 	query := dbconf.DatabaseConnection()

// 	var tokens []*Token
// 	query = query.Where("application_id = ?", app.ID)
// 	provide.Paginate(c, query, &Token{}).Find(&tokens)
// 	provide.Render(tokens, 200, c)
// }
