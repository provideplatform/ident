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
	r.GET("/api/v1/kyc_applications/:id", kycApplicationDetailsHandler)
}

func kycApplicationDetailsHandler(c *gin.Context) {
	bearer := bearerAuthToken(c)
	if bearer == nil || (bearer != nil && bearer.ApplicationID == nil && bearer.UserID == nil) {
		renderError("unauthorized", 401, c)
		return
	}

	if bearer.UserID != nil && bearer.UserID.String() != c.Param("id") {
		renderError("forbidden", 403, c)
		return
	}

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

	kycApplication.enrich()
	render(kycApplication, 200, c)
}

func createKYCApplicationHandler(c *gin.Context) {
	bearer := bearerAuthToken(c)
	if bearer == nil || (bearer != nil && bearer.ApplicationID == nil && bearer.UserID == nil) {
		renderError("unauthorized", 401, c)
		return
	}

	if bearer.UserID == nil {
		// HACK: only support KYC for user_id
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
	kycApplication.UserID = bearer.UserID

	log.Debugf("Creating new KYC application for user %s", bearer.UserID)
	if !kycApplication.Create() {
		err = fmt.Errorf("Failed to create KYC application; %s", *kycApplication.Errors[0].Message)
		log.Warningf(err.Error())
		renderError(err.Error(), 422, c)
		return
	}
	render(kycApplication, 201, c)
}
