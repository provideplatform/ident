package kyc

import (
	"encoding/json"
	"fmt"

	"github.com/gin-gonic/gin"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/ident/common"
	"github.com/provideapp/ident/token"
	"github.com/provideapp/ident/user"
	provide "github.com/provideservices/provide-go"
)

// InstallKYCAPI installs the handlers using the given gin Engine
func InstallKYCAPI(r *gin.Engine) {
	r.GET("/api/v1/kyc_applications", kycApplicationListHandler)
	r.POST("/api/v1/kyc_applications", createKYCApplicationHandler)
	r.PUT("/api/v1/kyc_applications/:id", updateKYCApplicationHandler)
	r.GET("/api/v1/kyc_applications/:id", kycApplicationDetailsHandler)

	r.GET("/api/v1/kyc_applications/:id/documents", kycApplicationDocumentsListHandler)
	r.POST("/api/v1/kyc_applications/:id/documents", createKYCApplicationDocumentHandler)
	r.GET("/api/v1/kyc_applications/:id/documents/:docId", kycApplicationDocumentDownloadHandler)

	r.GET("/api/v1/users/:id/kyc_applications", userKYCApplicationsListHandler)
}

func kycApplicationListHandler(c *gin.Context) {
	bearer := token.ParseBearerAuthToken(c)
	if bearer == nil || (bearer != nil && bearer.ApplicationID == nil && bearer.UserID == nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	var kycApplications []KYCApplication
	query := dbconf.DatabaseConnection()

	if bearer.UserID != nil {
		query = query.Where("user_id = ?", bearer.UserID)
	}

	if bearer.ApplicationID != nil {
		query = query.Where("application_id = ?", bearer.ApplicationID)
	}

	if c.Query("status") != "" {
		query = query.Where("status = ?", c.Query("status"))
	}

	query = query.Order("created_at DESC")
	provide.Paginate(c, query, &KYCApplication{}).Find(&kycApplications)
	provide.Render(kycApplications, 200, c)
}

func kycApplicationDetailsHandler(c *gin.Context) {
	userID := provide.AuthorizedSubjectID(c, "user")
	appID := provide.AuthorizedSubjectID(c, "application")
	if (userID == nil || *userID == uuid.Nil) && (appID == nil || *appID == uuid.Nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	db := dbconf.DatabaseConnection()

	kycApplication := &KYCApplication{}
	query := db.Where("id = ?", c.Param("id"))
	if appID != nil {
		query = query.Where("application_id = ?", appID)
	}
	if userID != nil {
		query = query.Where("user_id = ?", userID)
	}

	query.Find(&kycApplication)
	if kycApplication.ID == uuid.Nil {
		provide.RenderError("kyc application not found", 404, c)
		return
	}

	if userID != nil && kycApplication.UserID != nil && *userID != *kycApplication.UserID {
		provide.RenderError("forbidden", 403, c)
		return
	} else if appID != nil && kycApplication.ApplicationID != nil && *appID != *kycApplication.ApplicationID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	kycApplication.enrich(db)
	provide.Render(kycApplication, 200, c)
}

func createKYCApplicationHandler(c *gin.Context) {
	userID := provide.AuthorizedSubjectID(c, "user")
	appID := provide.AuthorizedSubjectID(c, "application")
	if (userID == nil || *userID == uuid.Nil) && (appID == nil || *appID == uuid.Nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	kycApplication := &KYCApplication{}
	err = json.Unmarshal(buf, &kycApplication)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	db := dbconf.DatabaseConnection()

	if appID != nil {
		kycApplication.ApplicationID = appID
		if kycApplication.UserID != nil && *kycApplication.UserID != uuid.Nil {
			// Make sure the authorized application has permission to submit KYC application on behalf of the user
			kycApplicationUser := kycApplication.User(db)
			if kycApplicationUser == nil || kycApplicationUser.ID == uuid.Nil {
				provide.RenderError("user does not exist", 404, c)
				return
			} else if kycApplicationUser.ApplicationID != nil && *kycApplicationUser.ApplicationID != *appID {
				provide.RenderError("unauthorized user kyc application creation", 403, c)
				return
			}
		}
	} else if userID != nil {
		user := user.Find(userID)
		if user == nil || user.ID == uuid.Nil {
			provide.RenderError("user does not exist", 404, c)
			return
		}

		kycApplication.ApplicationID = user.ApplicationID
		kycApplication.UserID = userID
	}

	common.Log.Debugf("Creating new KYC application for user %s", kycApplication.UserID)
	if !kycApplication.Create(db) {
		err = fmt.Errorf("Failed to create KYC application; %s", *kycApplication.Errors[0].Message)
		common.Log.Warningf(err.Error())
		provide.RenderError(err.Error(), 422, c)
		return
	}
	provide.Render(kycApplication, 201, c)
}

func updateKYCApplicationHandler(c *gin.Context) {
	userID := provide.AuthorizedSubjectID(c, "user")
	appID := provide.AuthorizedSubjectID(c, "application")
	if (userID == nil || *userID == uuid.Nil) && (appID == nil || *appID == uuid.Nil) {
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

	db := dbconf.DatabaseConnection()

	kycApplication := &KYCApplication{}
	db.Where("id = ?", c.Param("id")).Find(&kycApplication)
	if kycApplication.ID == uuid.Nil {
		provide.RenderError("kyc application not found", 404, c)
		return
	}

	if appID != nil {
		if kycApplication.ApplicationID == nil || *appID != *kycApplication.ApplicationID {
			provide.RenderError("forbidden", 403, c)
			return
		}

		if kycApplication.UserID != nil && *kycApplication.UserID != uuid.Nil {
			// Make sure the authorized application has permission to update the KYC application on behalf of the user
			kycApplicationUser := kycApplication.User(db)
			if kycApplicationUser == nil || kycApplicationUser.ID == uuid.Nil {
				provide.RenderError("user does not exist", 404, c)
				return
			} else if kycApplicationUser.ApplicationID != nil && *kycApplicationUser.ApplicationID != *appID {
				provide.RenderError("unauthorized user kyc application creation", 403, c)
				return
			}
		}
	} else if userID != nil {
		if *userID != *kycApplication.UserID {
			provide.RenderError("forbidden", 403, c)
			return
		}

		user := user.Find(userID)
		if user == nil || user.ID == uuid.Nil {
			provide.RenderError("user does not exist", 404, c)
			return
		} else if user.ApplicationID != nil && kycApplication.ApplicationID != nil && *user.ApplicationID != *kycApplication.ApplicationID {
			provide.RenderError("unauthorized user kyc application update", 403, c)
			return
		}
	}

	if status, statusOk := params["status"].(string); statusOk {
		if appID == nil {
			provide.RenderError("unauthorized user kyc application status update", 403, c)
			return
		}

		if kycApplication.Update(common.StringOrNil(status)) {
			provide.Render(kycApplication, 202, c)
		} else {
			obj := map[string]interface{}{}
			obj["errors"] = kycApplication.Errors
			provide.Render(obj, 422, c)
		}
	} else {
		provide.RenderError("kyc application update must include status", 400, c)
	}
}

func kycApplicationDocumentsListHandler(c *gin.Context) {
	bearer := token.ParseBearerAuthToken(c)
	if bearer == nil || (bearer != nil && bearer.ApplicationID == nil && bearer.UserID == nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	var kycApplications []KYCApplication
	query := dbconf.DatabaseConnection()

	if bearer.UserID != nil {
		query = query.Where("user_id = ?", bearer.UserID)
	}

	if bearer.ApplicationID != nil {
		query = query.Where("application_id = ?", bearer.ApplicationID)
	}

	if c.Query("status") != "" {
		query = query.Where("status = ?", c.Query("status"))
	}

	query = query.Order("created_at DESC")
	provide.Paginate(c, query, &KYCApplication{}).Find(&kycApplications)
	provide.Render(kycApplications, 200, c)
}

func createKYCApplicationDocumentHandler(c *gin.Context) {
	bearer := token.ParseBearerAuthToken(c)
	if bearer == nil || (bearer != nil && bearer.ApplicationID == nil && bearer.UserID == nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	kycApplication := &KYCApplication{}
	query := dbconf.DatabaseConnection().Where("id = ?", c.Param("id"))
	if bearer.ApplicationID != nil {
		query = query.Where("application_id = ?", bearer.ApplicationID)
	}
	if bearer.UserID != nil {
		query = query.Where("user_id = ?", bearer.UserID)
	}

	query.Find(&kycApplication)
	if kycApplication.ID == uuid.Nil {
		provide.RenderError("kyc application not found", 404, c)
		return
	}

	if kycApplication.Identifier == nil {
		provide.RenderError("provider KYC application identifier not resolved for kyc application: %s", 500, c)
		return
	}

	apiClient, err := kycApplication.KYCAPIClient()
	if err != nil {
		provide.RenderError("provider not resolved for kyc application: %s", 500, c)
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

	common.Log.Debugf("Attempting to upload KYC application document for KYC application: %s", kycApplication.ID)
	resp, err := apiClient.UploadApplicationDocument(*kycApplication.Identifier, params)
	if err != nil {
		msg := fmt.Sprintf("failed to upload kyc application document; %s", err.Error())
		common.Log.Warning(msg)
		provide.RenderError(msg, 500, c)
		return
	}

	provide.Render(resp, 201, c)
}

func kycApplicationDocumentDownloadHandler(c *gin.Context) {
	bearer := token.ParseBearerAuthToken(c)
	if bearer == nil || (bearer != nil && bearer.ApplicationID == nil && bearer.UserID == nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	kycApplication := &KYCApplication{}
	query := dbconf.DatabaseConnection().Where("id = ?", c.Param("id"))
	if bearer.ApplicationID != nil {
		query = query.Where("application_id = ?", bearer.ApplicationID)
	}
	if bearer.UserID != nil {
		query = query.Where("user_id = ?", bearer.UserID)
	}

	query.Find(&kycApplication)
	if kycApplication.ID == uuid.Nil {
		provide.RenderError("kyc application not found", 404, c)
		return
	}

	if kycApplication.Identifier == nil {
		provide.RenderError("provider KYC application identifier not resolved for kyc application: %s", 500, c)
		return
	}

	apiClient, err := kycApplication.KYCAPIClient()
	if err != nil {
		provide.RenderError("provider not resolved for kyc application: %s", 500, c)
		return
	}

	docID := c.Param("docId")
	common.Log.Debugf("Attempting to stream KYC application document for KYC application: %s; document id: %s", kycApplication.ID, docID)

	resp, err := apiClient.DownloadApplicationDocument(*kycApplication.Identifier, docID)
	if err != nil {
		msg := fmt.Sprintf("failed to retrieve KYC application document; %s", err.Error())
		common.Log.Warning(msg)
		provide.RenderError(msg, 500, c)
		return
	}

	provide.Render(resp, 200, c)
}

func userKYCApplicationsListHandler(c *gin.Context) {
	bearer := token.ParseBearerAuthToken(c)
	if bearer == nil || (bearer != nil && bearer.ApplicationID == nil && bearer.UserID == nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	if bearer.UserID == nil {
		// HACK: only support KYC for user_id
		provide.RenderError("unauthorized", 401, c)
		return
	}

	var kycApplications []KYCApplication
	query := dbconf.DatabaseConnection().Where("user_id = ?", bearer.UserID)

	if c.Query("status") != "" {
		query = query.Where("status = ?", c.Query("status"))
	}

	query = query.Order("created_at DESC")
	provide.Paginate(c, query, &KYCApplication{}).Find(&kycApplications)
	provide.Render(kycApplications, 200, c)
}
