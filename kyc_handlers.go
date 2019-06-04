package main

import (
	"encoding/json"
	"fmt"

	"github.com/gin-gonic/gin"
	uuid "github.com/kthomas/go.uuid"
)

// InstallKYCAPI installs the handlers using the given gin Engine
func InstallKYCAPI(r *gin.Engine) {
	r.POST("/api/v1/kyc_applications", createKYCApplicationHandler)
	r.PUT("/api/v1/kyc_applications/:id", updateKYCApplicationHandler)
	r.GET("/api/v1/kyc_applications/:id", kycApplicationDetailsHandler)
}

func kycApplicationDetailsHandler(c *gin.Context) {
	bearer := bearerAuthToken(c)
	if bearer == nil || (bearer != nil && bearer.ApplicationID == nil && bearer.UserID == nil) {
		renderError("unauthorized", 401, c)
		return
	}

	user := getAuthorizedUser(c)
	app := getAuthorizedApplication(c)

	kycApplication := &KYCApplication{}
	query := DatabaseConnection().Where("id = ?", c.Param("id"))
	if bearer.ApplicationID != nil {
		query = query.Where("application_id = ?", bearer.ApplicationID)
	}
	if bearer.UserID != nil {
		query = query.Where("user_id = ?", bearer.UserID)
	}

	query.Find(&kycApplication)
	if kycApplication.ID == uuid.Nil {
		renderError("kyc application not found", 404, c)
		return
	}

	if user != nil && user.ID.String() != kycApplication.UserID.String() {
		renderError("forbidden", 403, c)
		return
	} else if app != nil && app.ID.String() != kycApplication.ApplicationID.String() {
		renderError("forbidden", 403, c)
		return
	}

	kycApplication.enrich()
	render(kycApplication, 200, c)
}

func createKYCApplicationHandler(c *gin.Context) {
	bearer := bearerAuthToken(c)
	if bearer == nil || (bearer != nil && bearer.ApplicationID == nil && bearer.UserID == nil) {
		renderError("unauthorized", 401, c)
		return
	}

	user := getAuthorizedUser(c)
	if user == nil {
		// FIXME: only support KYC for user_id
		renderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		renderError(err.Error(), 400, c)
		return
	}

	kycApplication := &KYCApplication{}
	err = json.Unmarshal(buf, &kycApplication)
	if err != nil {
		renderError(err.Error(), 400, c)
		return
	}
	kycApplication.ApplicationID = user.ApplicationID
	kycApplication.UserID = &user.ID

	log.Debugf("Creating new KYC application for user %s", bearer.UserID)
	if !kycApplication.Create() {
		err = fmt.Errorf("Failed to create KYC application; %s", *kycApplication.Errors[0].Message)
		log.Warningf(err.Error())
		renderError(err.Error(), 422, c)
		return
	}
	render(kycApplication, 201, c)
}

func updateKYCApplicationHandler(c *gin.Context) {
	bearer := bearerAuthToken(c)
	if bearer == nil || (bearer != nil && bearer.ApplicationID == nil && bearer.UserID == nil) {
		renderError("unauthorized", 401, c)
		return
	}

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

	params := map[string]interface{}{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		renderError(err.Error(), 400, c)
		return
	}

	db := DatabaseConnection()

	kycApplication := &KYCApplication{}
	db.Where("id = ?", c.Param("id")).Find(&kycApplication)
	if kycApplication.ID == uuid.Nil {
		renderError("kyc application not found", 404, c)
		return
	}

	if user.ID.String() != kycApplication.UserID.String() {
		renderError("forbidden", 403, c)
		return
	}

	err = json.Unmarshal(buf, &kycApplication)
	if err != nil {
		renderError(err.Error(), 422, c)
		return
	}

	kycApplication.ApplicationID = user.ApplicationID
	kycApplication.UserID = bearer.UserID

	log.Debugf("Updating KYC application %s for user %s", kycApplication.ID, bearer.UserID)
	if kycApplication.Update() {
		render(kycApplication, 202, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = user.Errors
		render(obj, 422, c)
	}
}
