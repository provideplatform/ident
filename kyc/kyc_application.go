package kyc

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	pgputil "github.com/kthomas/go-pgputil"
	uuid "github.com/kthomas/go.uuid"
	identitymind "github.com/kthomas/identitymind-golang"
	"github.com/kthomas/vouched-golang"
	"github.com/provideapp/ident/application"
	"github.com/provideapp/ident/common"
	"github.com/provideapp/ident/kyc/providers"
	"github.com/provideapp/ident/user"
	provide "github.com/provideservices/provide-go"
)

const defaultKYCWebhookTimeout = time.Second * 5
const defaultKYCIDNumberOCRSimilarityThreshold = 0.8 // % of OCR'd chars in ID number to use from front and back of string to determine similarity

const kycApplicationStatusAccepted = "accepted"
const kycApplicationStatusFailed = "failed" // the KYC application API call itself failed
const kycApplicationStatusPending = "pending"
const kycApplicationStatusRejected = "rejected"
const kycApplicationStatusSubmitted = "submitted"
const kycApplicationStatusUnderReview = "review"
const kycApplicationStatusUnderRemediate = "remediate"

const defaultKYCProvider = vouchedKYCProvider
const defaultKYCApplicationType = consumerKYCApplicationType
const consumerKYCApplicationType = "kyc"
const businessKYCApplicationType = "kyb"
const identitymindKYCProvider = "identitymind"
const vouchedKYCProvider = "vouched"

func init() {
	db := dbconf.DatabaseConnection()

	db.AutoMigrate(&KYCApplication{})
	db.Model(&KYCApplication{}).AddIndex("idx_kyc_applications_application_id", "application_id")
	db.Model(&KYCApplication{}).AddIndex("idx_kyc_applications_user_id", "user_id")
	db.Model(&KYCApplication{}).AddIndex("idx_kyc_applications_identifier", "identifier")
	db.Model(&KYCApplication{}).AddIndex("idx_kyc_applications_id_number", "id_number")
	db.Model(&KYCApplication{}).AddIndex("idx_kyc_applications_pii_hash", "pii_hash")
	db.Model(&KYCApplication{}).AddIndex("idx_kyc_applications_status", "status")
	db.Model(&KYCApplication{}).AddForeignKey("user_id", "users(id)", "SET NULL", "CASCADE")
}

// KYCAPI is implemented by BillingAccount KYC clients such as identitymind.go
type KYCAPI interface {
	// KYCApplicationParams
	MarshalKYCApplication(map[string]interface{}) map[string]interface{}
	MarshalKYCApplicationParams(map[string]interface{}) map[string]interface{}

	// Cases
	GetCase(string) (interface{}, error)
	CreateCase(map[string]interface{}) (interface{}, error)
	CloseCase(string, map[string]interface{}) (interface{}, error)
	UpdateCase(string, map[string]interface{}) (interface{}, error)

	// Transactions
	EvaluateFraud(map[string]interface{}) (interface{}, error)
	ReportTransaction(string, map[string]interface{}) (interface{}, error)

	// KYC applications
	ApproveApplication(string, map[string]interface{}) (interface{}, error)
	DownloadApplicationDocument(string, string) (interface{}, error)
	GetApplication(string) (interface{}, error)
	ListApplicationDocuments(string) (interface{}, error)
	ProvideApplicationResponse(string, map[string]interface{}) (interface{}, error)
	RejectApplication(string, map[string]interface{}) (interface{}, error)
	SubmitApplication(map[string]interface{}) (interface{}, error)
	UndecideApplication(string, map[string]interface{}) (interface{}, error)
	UploadApplicationDocument(string, map[string]interface{}) (interface{}, error)
	UploadApplicationDocumentVerificationImage(string, map[string]interface{}) (interface{}, error)

	// KYB applications
	ApproveBusinessApplication(string, map[string]interface{}) (interface{}, error)
	DownloadBusinessApplicationDocument(string, string) (interface{}, error)
	GetBusinessApplication(string) (interface{}, error)
	ListBusinessApplicationDocuments(string) (interface{}, error)
	SubmitBusinessApplication(map[string]interface{}) (interface{}, error)
	ReevaluateBusinessApplication(string) (interface{}, error)
	RejectBusinessApplication(string, map[string]interface{}) (interface{}, error)
	UndecideBusinessApplication(string, map[string]interface{}) (interface{}, error)
	UploadBusinessApplicationDocument(string, map[string]interface{}) (interface{}, error)
	UploadBusinessApplicationDocumentVerificationImage(string, map[string]interface{}) (interface{}, error)

	// Merchant aggregation
	CreateMerchant(map[string]interface{}) (interface{}, error)
	GetMerchant(string) (interface{}, error)
	UpdateMerchant(string, map[string]interface{}) (interface{}, error)

	// Merchant KYC
	GetMerchantApplication(string) (interface{}, error)
	SubmitMerchantApplication(map[string]interface{}) (interface{}, error)
	DownloadMerchantApplicationDocument(string, string) (interface{}, error)
	UploadMerchantApplicationDocument(string, map[string]interface{}) (interface{}, error)
	UploadMerchantApplicationDocumentVerificationImage(string, map[string]interface{}) (interface{}, error)
	ApproveMerchantApplication(string, map[string]interface{}) (interface{}, error)
	RejectMerchantApplication(string, map[string]interface{}) (interface{}, error)
	UndecideMerchantApplication(string, map[string]interface{}) (interface{}, error)
	ProvideMerchantApplicationResponse(string, map[string]interface{}) (interface{}, error)

	// Merchant KYB
	RejectMerchantBusinessApplication(string, map[string]interface{}) (interface{}, error)
	GetMerchantBusinessApplication(string) (interface{}, error)
	ReevaluateMerchantBusinessApplication(string) (interface{}, error)
	SubmitMerchantBusinessApplication(map[string]interface{}) (interface{}, error)
	ListMerchantBusinessApplicationDocuments(string) (interface{}, error)
	DownloadMerchantBusinessApplicationDocument(string, string) (interface{}, error)
	UploadMerchantBusinessApplicationDocument(string, map[string]interface{}) (interface{}, error)
	UploadMerchantBusinessApplicationDocumentVerificationImage(string, map[string]interface{}) (interface{}, error)
	ApproveMerchantBusinessApplication(string, map[string]interface{}) (interface{}, error)
	UndecideMerchantBusinessApplication(string, map[string]interface{}) (interface{}, error)

	// Merchant Transactions
	EvaluateMerchantFraud(string, map[string]interface{}) (interface{}, error)
	ReportMerchantTransaction(string, string, map[string]interface{}) (interface{}, error)
}

// KYCApplication represents a KYC application process
type KYCApplication struct {
	provide.Model
	ApplicationID          *uuid.UUID             `sql:"type:uuid" json:"application_id"`
	UserID                 *uuid.UUID             `sql:"type:uuid" json:"user_id"`
	Provider               *string                `sql:"not null" json:"provider"`
	Identifier             *string                `json:"identifier"`
	Type                   *string                `sql:"not null" json:"type"`
	Status                 *string                `sql:"not null;default:'pending'" json:"status"`
	Name                   *string                `json:"name"`
	Description            *string                `json:"description"`
	Params                 *KYCApplicationParams  `sql:"-" json:"params,omitempty"`
	EncryptedParams        *string                `sql:"type:bytea" json:"-"`
	ProviderRepresentation map[string]interface{} `sql:"-" json:"provider_representation,omitempty"`
	PIIHash                *string                `json:"-"`
	IDNumber               *string                `json:"-"`
	SimilarKYCApplications []*KYCApplication      `sql:"-" json:"similar_kyc_applications,omitempty"`
	SimilarUsers           []*user.UserResponse   `sql:"-" json:"similar_users,omitempty"`
}

// KYCApplicationParams represents a vendor-agnostic KYC application parameter object
type KYCApplicationParams struct {
	// Params is the provider API representation
	Params map[string]interface{} `json:"params,omitempty"`

	IDNumber    *string `json:"id_number,omitempty"`
	DateOfBirth *string `json:"date_of_birth,omitempty"`
	FirstName   *string `json:"first_name,omitempty"`
	LastName    *string `json:"last_name,omitempty"`
	Name        *string `json:"name,omitempty"`
	IDPhoto     *string `json:"id_photo,omitempty"`
	IDPhotoBack *string `json:"id_photo_back,omitempty"`
	Selfie      *string `json:"selfie,omitempty"`
	SelfieVideo *string `json:"selfie_video,omitempty"`
	Type        *string `json:"type,omitempty"`
	WebhookURL  *string `json:"webhook_url,omitempty"`
}

func (p *KYCApplicationParams) goMap() (map[string]interface{}, error) {
	var params map[string]interface{}
	paramsJSON, err := json.Marshal(p)
	if err != nil {
		common.Log.Warningf("Failed to marshal KYC application params to JSON; %s", err.Error())
		return nil, err
	}

	err = json.Unmarshal(paramsJSON, &params)
	if err != nil {
		common.Log.Warningf("Failed to unmarshal KYC application params; %s", err.Error())
		return nil, err
	}
	return params, nil
}

// KYCApplicationsByUserID returns a list of KYC applications which have been
// created for the given user id
func KYCApplicationsByUserID(userID *uuid.UUID, status *string) []KYCApplication {
	db := dbconf.DatabaseConnection()
	var kycApplications []KYCApplication
	query := db.Where("user_id = ?", userID)
	if status != nil {
		query = query.Where("status = ?", *status)
	}
	query.Find(&kycApplications)
	return kycApplications
}

// Create and persist a new BillingAccount
func (k *KYCApplication) Create(db *gorm.DB) bool {
	if k.Provider == nil {
		k.Provider = common.StringOrNil(defaultKYCProvider)
	}

	if k.Type == nil {
		k.Type = common.StringOrNil(defaultKYCApplicationType)
	} else {
		k.Type = common.StringOrNil(strings.ToLower(*k.Type))
	}

	if k.Name == nil {
		if k.Params != nil && k.Params.Name != nil {
			k.Name = k.Params.Name
		} else if k.Params != nil && k.Params.FirstName != nil && k.Params.LastName != nil {
			name := fmt.Sprintf("%s %s", *k.Params.FirstName, *k.Params.LastName)
			k.Name = &name
		} else {
			user := k.User(db)
			if user != nil && user.ID != uuid.Nil {
				k.Name = user.Name
			}
		}
	}

	if !k.Validate(db) {
		return false
	}

	k.enrichPIIHash(db)
	k.setEncryptedParams(k.Params)

	if db.NewRecord(k) {
		result := db.Create(&k)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				k.Errors = append(k.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
		if !db.NewRecord(k) {
			success := rowsAffected > 0
			if success {
				payload, _ := json.Marshal(map[string]interface{}{
					"kyc_application_id": k.ID.String(),
				})
				natsutil.NatsPublish(natsSubmitKYCApplicationSubject, payload)
			}
			return success
		}
	}
	return false
}

// Update an existing KYC application; if status is non-nil, the application
// status will be updated, provided the state change is valid
func (k *KYCApplication) Update(status *string) bool {
	db := dbconf.DatabaseConnection()

	var initialStatus string
	if k.Status != nil {
		initialStatus = *k.Status
	}

	if status != nil && *status != initialStatus {
		common.Log.Debugf("KYC application status change requested from %s to %s for KYC application %s", initialStatus, *k.Status, k.ID)
		k.Status = status
	} else {
		common.Log.Debugf("Short-circuiting no-op KYC application status change request from %s to %s for KYC application %s", initialStatus, *k.Status, k.ID)
		return true
	}

	if !k.Validate(db) {
		return false
	}

	result := db.Save(&k)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			k.Errors = append(k.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	} else {
		payload, _ := json.Marshal(map[string]interface{}{
			"kyc_application_id": k.ID.String(),
			"status":             status,
		})
		natsutil.NatsPublish(natsDispatchKYCApplicationWebhookSubject, payload)
	}

	return len(k.Errors) == 0
}

// Validate a KYCApplication for persistence
func (k *KYCApplication) Validate(db *gorm.DB) bool {
	k.Errors = make([]*provide.Error, 0)
	if k.UserID == nil || *k.UserID == uuid.Nil {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil("Unable to persist a KYC application without an associated user"),
		})
	} else {
		user := k.User(db)
		if user != nil {
			if user.ApplicationID != nil && *user.ApplicationID != uuid.Nil {
				if k.ApplicationID == nil || *k.ApplicationID != *user.ApplicationID {
					k.Errors = append(k.Errors, &provide.Error{
						Message: common.StringOrNil("Unable to persist a KYC application on behalf of an application user without matching application_id"),
					})
				}
			}
		}
	}
	if k.Provider == nil {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil("Unable to persist a KYC application without a provider-specific identifier"),
		})
	}
	if k.Type == nil || (*k.Type != consumerKYCApplicationType && *k.Type != businessKYCApplicationType) {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil("Unable to persist a KYC application without a type"),
		})
	}
	return len(k.Errors) == 0
}

// Application retrieves the application related to the KYC application
func (k *KYCApplication) Application(db *gorm.DB) *application.Application {
	if k.ApplicationID == nil || *k.ApplicationID == uuid.Nil {
		return nil
	}
	app := &application.Application{}
	db.Where("id = ?", k.ApplicationID).Find(&app)
	if app == nil || app.ID == uuid.Nil {
		return nil
	}
	return app
}

// User retrieves the user related to the KYC application
func (k *KYCApplication) User(db *gorm.DB) *user.User {
	if k.UserID == nil || *k.UserID == uuid.Nil {
		return nil
	}
	user := &user.User{}
	db.Where("id = ?", k.UserID).Find(&user)
	if user == nil || user.ID == uuid.Nil {
		return nil
	}
	return user
}

// submit the KYCApplication to the provider
func (k *KYCApplication) submit(db *gorm.DB) error {
	apiClient, err := k.KYCAPIClient()
	if err != nil {
		common.Log.Warningf("Failed to submit KYC application; no KYC API client resolved for provider: %s; %s", *k.Provider, err.Error())
		return err
	}

	var decryptedParams *KYCApplicationParams
	if k.Params != nil {
		decryptedParams = k.Params
	} else {
		decryptedParams, err = k.decryptedParams()
		if err != nil {
			common.Log.Warningf("Failed to submit KYC application; failed to decrypt params; %s", err.Error())
			return err
		}
	}

	var params map[string]interface{}
	if decryptedParams != nil {
		params, err = decryptedParams.goMap()
		if err != nil {
			common.Log.Warningf("Failed to submit KYC application; failed to marshal decrypted params to go map; %s", err.Error())
			return err
		}
		params = apiClient.MarshalKYCApplication(params)
	}

	resp, err := apiClient.SubmitApplication(params)
	if err != nil {
		common.Log.Warningf("Failed to resolve KYC API client; %s", err.Error())
		return err
	}

	k.Params, _ = k.decryptedParams()

	switch *k.Provider {
	case identitymindKYCProvider:
		if k.Identifier == nil {
			if apiResponse, apiResponseOk := resp.(map[string]interface{}); apiResponseOk {
				k.ProviderRepresentation = apiResponse

				if mtid, mtidOk := apiResponse["mtid"].(string); mtidOk {
					common.Log.Debugf("Resolved identitymind KYC application identifier '%s' for KYC application: %s", mtid, k.ID)
					k.Identifier = common.StringOrNil(mtid)
					k.updateStatus(db, kycApplicationStatusSubmitted, nil)
				} else {
					desc, _ := apiResponse["error_message"].(string)
					k.updateStatus(db, kycApplicationStatusFailed, common.StringOrNil(desc))
					return fmt.Errorf("Identitymind KYC application submission failed to return valid identifier: %s; response: %s", k.ID, apiResponse)
				}
			}
		}
	case vouchedKYCProvider:
		if k.Identifier == nil {
			if apiResponse, apiResponseOk := resp.(*vouched.KYCApplicationResponse); apiResponseOk {
				provideRepresentationJSON, _ := json.Marshal(apiResponse)
				providerRepresentation := map[string]interface{}{}
				json.Unmarshal(provideRepresentationJSON, &providerRepresentation)
				k.ProviderRepresentation = providerRepresentation

				if len(apiResponse.Errors) == 0 {
					common.Log.Debugf("Resolved vouched KYC application identifier '%s' for KYC application: %s", *apiResponse.Data.Job.ID, k.ID)
					k.Identifier = apiResponse.Data.Job.ID
					k.updateStatus(db, kycApplicationStatusSubmitted, nil)
				} else {
					desc := apiResponse.Errors[0].Message
					k.updateStatus(db, kycApplicationStatusFailed, desc)
					return fmt.Errorf("Vouched KYC application submission failed to return valid identifier: %s; response: %s", k.ID, resp)
				}
			}
		}
	default:
		// no-op
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"kyc_application_id": k.ID.String(),
	})
	natsutil.NatsPublish(natsCheckKYCApplicationStatusSubject, payload)
	return nil
}

// enrich the KYCApplication with the provider's current representation
func (k *KYCApplication) enrich(db *gorm.DB) (interface{}, error) {
	apiClient, err := k.KYCAPIClient()
	if err != nil {
		common.Log.Warningf("Failed to enrich KYC application; no KYC API client resolved for provider: %s", *k.Provider)
		return nil, err
	}
	if k.Identifier == nil {
		msg := fmt.Sprintf("Failed to enrich KYC application for provider: %s; KYC application id: %s", *k.Provider, k.ID)
		common.Log.Warning(msg)
		return nil, errors.New(msg)
	}
	resp, err := apiClient.GetApplication(*k.Identifier)
	if err != nil {
		common.Log.Warningf("Failed to resolve KYC API client; %s", err.Error())
		return nil, err
	}

	k.Params, _ = k.decryptedParams()
	if k.Params.Params != nil {
		common.Log.Debugf("Enriching standard KYCApplicationParams using provider params")
		standardizedParams := apiClient.MarshalKYCApplicationParams(k.Params.Params)
		standardizedParamsJSON, _ := json.Marshal(standardizedParams)
		json.Unmarshal(standardizedParamsJSON, &k.Params)
		k.Params.Params = nil
	}

	var marshaledResponse interface{}

	switch *k.Provider {
	case identitymindKYCProvider:
		if apiResponse, apiResponseOk := resp.(map[string]interface{}); apiResponseOk {
			k.ProviderRepresentation = apiResponse

			apiResponseJSON, _ := json.Marshal(apiResponse)
			marshaledResponse = &identitymind.KYCApplication{}
			err = json.Unmarshal(apiResponseJSON, &marshaledResponse)
			if err != nil {
				return nil, fmt.Errorf("Failed to unmarshal identitymind KYC application response to struct; %s", err.Error())
			}

			// TODO: enrich errors if similar applications have been detected in k.SimilarUsers
		}
	case vouchedKYCProvider:
		if apiResponse, apiResponseOk := resp.(*vouched.KYCApplication); apiResponseOk {
			fuzzySimilarity := true
			if apiResponse.Result != nil && apiResponse.Result.ID != nil {
				piiDigest := sha256.New()
				piiDigest.Write([]byte(*apiResponse.Result.ID))
				hash := hex.EncodeToString(piiDigest.Sum(nil))
				k.PIIHash = &hash
				fuzzySimilarity = false
			}

			err = k.enrichSimilar(db)
			if err != nil {
				common.Log.Debugf("Similar user enrichment failed for KYC application: %s; %s", k.ID, err.Error())
			}
			if len(k.SimilarKYCApplications) > 0 {
				var msg string
				if fuzzySimilarity {
					msg = "KYC application is similar to others; manual remediation required"
					apiResponse.Errors = append(apiResponse.Errors, &vouched.Error{
						Message: &msg,
						Type:    common.StringOrNil("SimilarApplicationError"),
					})
				} else {
					msg = "KYC application matches others; manual remediation required"
					apiResponse.Errors = append(apiResponse.Errors, &vouched.Error{
						Message: &msg,
						Type:    common.StringOrNil("DuplicateApplicationError"),
					})
				}
				common.Log.Debugf("%s for KYC application: %s", msg, k.ID)
			}

			provideRepresentationJSON, _ := json.Marshal(apiResponse)
			providerRepresentation := map[string]interface{}{}
			json.Unmarshal(provideRepresentationJSON, &providerRepresentation)
			delete(providerRepresentation, "request")
			k.ProviderRepresentation = providerRepresentation

			marshaledResponse = apiResponse
		}
	default:
		// no-op
	}

	return marshaledResponse, nil
}

// enrichPIIHash calculates and sets the PII hash based on the metadata in the KYC application
func (k *KYCApplication) enrichPIIHash(db *gorm.DB) error {
	var name *string
	var dob *string

	piiDigest := sha256.New()
	if k.Params.IDNumber != nil {
		piiDigest.Write([]byte(*k.Params.IDNumber))
	} else {
		if k.Params.Name != nil {
			name = k.Params.Name
		} else if k.Params.FirstName != nil && k.Params.LastName != nil {
			nameStr := fmt.Sprintf("%s %s", *k.Params.FirstName, *k.Params.LastName)
			name = &nameStr
		} else if k.Name != nil {
			name = k.Name
		}

		if k.Params.DateOfBirth != nil {
			dob = k.Params.DateOfBirth
		}

		if name == nil && dob == nil {
			return fmt.Errorf("Not enriching PII hash without name or dob for KYC application: %s", k.ID)
		}

		if name != nil {
			piiDigest.Write([]byte(*name))
		}
		if dob != nil {
			piiDigest.Write([]byte(*dob))
		}
	}

	hash := hex.EncodeToString(piiDigest.Sum(nil))
	k.PIIHash = &hash
	return nil
}

// enrichSimilar retrieves and enriches a list of other KYC applications and users which
// appear to be similar to this KYC application instance or its associated user; uses PII
// hash for metadata comparison
func (k *KYCApplication) enrichSimilar(db *gorm.DB) error {
	if k.UserID == nil || *k.UserID == uuid.Nil {
		return fmt.Errorf("Unable to search for similar users by PII hash without associated user for KYC application: %s", k.ID)
	}
	if k.IDNumber == nil && k.PIIHash == nil {
		return fmt.Errorf("Unable to search for similar users by id number or PII hash for KYC application: %s", k.ID)
	}
	similarUsers := make([]*user.UserResponse, 0)
	similarUserIDs := map[string]struct{}{}
	var similarKYCApplications []*KYCApplication

	if k.IDNumber != nil {
		dropchars := int(float64(len(*k.IDNumber)) - math.Round(float64(len(*k.IDNumber))*defaultKYCIDNumberOCRSimilarityThreshold))
		idNumberQueryMatchAnyTrailing := (*k.IDNumber)[0 : len(*k.IDNumber)-dropchars]
		idNumberQueryMatchAnyLeading := (*k.IDNumber)[dropchars:]

		db.Where(
			"application_id != ? AND user_id != ? AND (id_number LIKE ? OR id_number LIKE ?)",
			k.ApplicationID, k.UserID, fmt.Sprintf("%s%%", idNumberQueryMatchAnyTrailing), fmt.Sprintf("%%%s", idNumberQueryMatchAnyLeading),
		).Find(&similarKYCApplications)

		if similarKYCApplications != nil && len(similarKYCApplications) > 0 {
			common.Log.Debugf("Resolved similar KYC applications based on partial id number match for KYC application: %s", k.ID)
		}
	}

	if similarKYCApplications == nil || len(similarKYCApplications) == 0 && k.PIIHash != nil {
		db.Where("application_id != ? AND user_id != ? AND pii_hash = ?", k.ApplicationID, k.UserID, k.PIIHash).Find(&similarKYCApplications)
		for _, similar := range similarKYCApplications {
			similarUser := similar.User(db)
			if similarUser != nil {
				userIDStr := similarUser.ID.String()
				_, userOk := similarUserIDs[userIDStr]
				if !userOk && similarUser.Name != nil && similarUser.Email != nil {
					similarUsers = append(similarUsers, &user.UserResponse{
						ID:        similarUser.ID,
						CreatedAt: similarUser.CreatedAt,
						Name:      *similarUser.Name,
						Email:     *similarUser.Email,
					})
					similarUserIDs[userIDStr] = struct{}{}
				}
			}
		}
	}
	k.SimilarKYCApplications = similarKYCApplications
	k.SimilarUsers = similarUsers
	return nil
}

func (k *KYCApplication) decryptedParams() (*KYCApplicationParams, error) {
	decryptedParams := &KYCApplicationParams{}
	if k.EncryptedParams != nil {
		encryptedParamsJSON, err := pgputil.PGPPubDecrypt([]byte(*k.EncryptedParams))
		if err != nil {
			common.Log.Warningf("Failed to decrypt encrypted KYC application params; %s", err.Error())
			return decryptedParams, err
		}

		err = json.Unmarshal(encryptedParamsJSON, &decryptedParams)
		if err != nil {
			common.Log.Warningf("Failed to unmarshal decrypted KYC application params; %s", err.Error())
			return decryptedParams, err
		}
	}
	return decryptedParams, nil
}

func (k *KYCApplication) encryptParams() bool {
	if k.EncryptedParams != nil {
		encryptedParams, err := pgputil.PGPPubEncrypt([]byte(*k.EncryptedParams))
		if err != nil {
			common.Log.Warningf("Failed to encrypt KYC application params; %s", err.Error())
			k.Errors = append(k.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
			return false
		}
		k.EncryptedParams = common.StringOrNil(string(encryptedParams))
	}
	return true
}

func (k *KYCApplication) setEncryptedParams(params *KYCApplicationParams) {
	paramsJSON, _ := json.Marshal(params)
	_paramsJSON := string(json.RawMessage(paramsJSON))
	k.EncryptedParams = &_paramsJSON
	k.encryptParams()
	k.Params = params
}

func (k *KYCApplication) dispatchWebhookRequest(params map[string]interface{}) error {
	if !k.hasWebhookConfiguration() {
		return fmt.Errorf("KYC application %s does not have a configured webhook_url and application-configured webhook_secret", k.ID)
	}

	webhookSecret := k.webhookSecret()
	webhookURL := k.webhookURL()
	if webhookURL == nil {
		return fmt.Errorf("KYC application %s does not have a configured webhook_url", k.ID)
	}

	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
		Timeout: defaultKYCWebhookTimeout,
	}

	// enrich the params
	params["kyc_application_id"] = k.ID
	params["status"] = k.Status

	payload, err := json.Marshal(params)
	if err != nil {
		common.Log.Warningf("Failed to marshal JSON payload for KYC application webhook notification; kyc application id: %s; %s", k.ID, err.Error())
		return err
	}

	signedTimestamp := time.Now().Unix()
	signedPayload := []byte(fmt.Sprintf("%v.%s", signedTimestamp, string(payload)))

	hash := hmac.New(sha256.New, webhookSecret)
	hash.Write(signedPayload)
	signature := hex.EncodeToString(hash.Sum(nil))
	signatureHeader := fmt.Sprintf("t=%v,s=%s", signedTimestamp, signature)

	req, _ := http.NewRequest("POST", *webhookURL, bytes.NewReader(payload))
	req.Header = map[string][]string{
		"Accept-Encoding":     {"gzip, deflate"},
		"Accept-Language":     {"en-us"},
		"Accept":              {"application/json"},
		"Content-Type":        {"application/json"},
		"X-Request-Signature": {signatureHeader},
	}

	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		common.Log.Warningf("Failed to dispatch KYC application notification to configured webhook url: %s; kyc application id: %s; %s", *webhookURL, k.ID, err.Error())
		return err
	} else if resp.StatusCode >= 300 {
		msg := fmt.Sprintf("Dispatched KYC application notification returned %v response: to configured webhook url %s; kyc application id: %s", resp.StatusCode, *webhookURL, k.ID)
		common.Log.Warning(msg)
		return errors.New(msg)
	}

	common.Log.Debugf("Dispatched KYC application notification to configured webhook url: %s (%v response); kyc application id: %s", *webhookURL, resp.StatusCode, k.ID)
	return nil
}

func (k *KYCApplication) hasReachedDecision() bool {
	return k.isAccepted() || k.isRejected()
}

func (k *KYCApplication) hasWebhookConfiguration() bool {
	return k.hasWebhookSecret() && k.hasWebhookURL()
}

func (k *KYCApplication) hasWebhookSecret() bool {
	if k.webhookSecret() != nil {
		return true
	}
	return false
}

func (k *KYCApplication) hasWebhookURL() bool {
	if k.webhookURL() != nil {
		return true
	}
	return false
}

func (k *KYCApplication) isAccepted() bool {
	if k.Status == nil {
		return false
	}
	return strings.ToLower(*k.Status) == kycApplicationStatusAccepted
}

func (k *KYCApplication) isPending() bool {
	if k.Status == nil {
		return false
	}
	return strings.ToLower(*k.Status) == kycApplicationStatusPending
}

func (k *KYCApplication) isRejected() bool {
	if k.Status == nil {
		return false
	}
	return strings.ToLower(*k.Status) == kycApplicationStatusRejected
}

func (k *KYCApplication) isSubmitted() bool {
	if k.Status == nil {
		return false
	}
	return strings.ToLower(*k.Status) == kycApplicationStatusSubmitted
}

func (k *KYCApplication) isUnderReview() bool {
	if k.Status == nil {
		return false
	}
	return strings.ToLower(*k.Status) == kycApplicationStatusUnderReview
}

func (k *KYCApplication) requiresRemediation() bool {
	return len(k.SimilarKYCApplications) > 0 || len(k.SimilarUsers) > 0
}

func (k *KYCApplication) updateStatus(db *gorm.DB, status string, description *string) {
	var initialStatus string
	if k.Status != nil {
		initialStatus = *k.Status
	}

	if status == initialStatus {
		common.Log.Debugf("Short-circuiting no-op KYC application status change request from %s to %s for KYC application %s", initialStatus, *k.Status, k.ID)
		return
	}

	k.Status = common.StringOrNil(status)
	k.Description = description
	result := db.Save(&k)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			k.Errors = append(k.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	} else {
		payload, _ := json.Marshal(map[string]interface{}{
			"kyc_application_id": k.ID.String(),
		})
		natsutil.NatsPublish(natsDispatchKYCApplicationWebhookSubject, payload)
	}
}

func (k *KYCApplication) accept(db *gorm.DB) error {
	if k.Status != nil && *k.Status == kycApplicationStatusAccepted {
		return fmt.Errorf("Failed to accept application: %s; application already accepted", k.ID)
	}

	apiClient, err := k.KYCAPIClient()
	if err != nil {
		common.Log.Warningf("Failed to accept application: %s; %s", k.ID, err.Error())
		return err
	}

	if k.Identifier == nil {
		msg := fmt.Sprintf("Failed to accept application: %s; KYC application identifier not set", k.ID)
		common.Log.Warning(msg)
		return errors.New(msg)
	}

	_, err = apiClient.ApproveApplication(*k.Identifier, map[string]interface{}{})
	if err != nil {
		common.Log.Warningf("Failed to accept application: %s; %s", k.ID, err.Error())
		return err
	}

	k.updateStatus(db, kycApplicationStatusAccepted, nil)

	return nil
}

func (k *KYCApplication) reject(db *gorm.DB) error {
	if k.Status != nil && *k.Status == kycApplicationStatusRejected {
		return fmt.Errorf("Failed to reject application: %s; application already rejected", k.ID)
	}

	apiClient, err := k.KYCAPIClient()
	if err != nil {
		common.Log.Warningf("Failed to reject application: %s; %s", k.ID, err.Error())
		return err
	}

	if k.Identifier == nil {
		msg := fmt.Sprintf("Failed to reject application: %s; KYC application identifier not set", k.ID)
		common.Log.Warning(msg)
		return errors.New(msg)
	}

	_, err = apiClient.RejectApplication(*k.Identifier, map[string]interface{}{})
	if err != nil {
		common.Log.Warningf("Failed to reject application: %s; %s", k.ID, err.Error())
		return err
	}

	k.updateStatus(db, kycApplicationStatusRejected, nil)

	return nil
}

func (k *KYCApplication) undecide(db *gorm.DB) error {
	if k.Status != nil && *k.Status == kycApplicationStatusUnderReview {
		return fmt.Errorf("Failed to undecide application: %s; application already under review", k.ID)
	}

	apiClient, err := k.KYCAPIClient()
	if err != nil {
		common.Log.Warningf("Failed to undecide application: %s; %s", k.ID, err.Error())
		return err
	}

	if k.Identifier == nil {
		msg := fmt.Sprintf("Failed to undecide application: %s; KYC application identifier not set", k.ID)
		common.Log.Warning(msg)
		return errors.New(msg)
	}

	_, err = apiClient.UndecideApplication(*k.Identifier, map[string]interface{}{})
	if err != nil {
		common.Log.Warningf("Failed to undecide application: %s; %s", k.ID, err.Error())
		return err
	}

	k.updateStatus(db, kycApplicationStatusUnderReview, nil)

	return nil
}

func (k *KYCApplication) webhookSecret() []byte {
	app := k.Application(dbconf.DatabaseConnection())
	if app == nil {
		return nil
	}
	decryptedAppConfig, err := app.DecryptedConfig()
	if err != nil {
		return nil
	}
	if webhookSecret, webhookSecretOk := decryptedAppConfig["webhook_secret"].(string); webhookSecretOk {
		return []byte(webhookSecret)
	}
	return nil
}

func (k *KYCApplication) webhookURL() *string {
	params, err := k.decryptedParams()
	if err != nil {
		return nil
	}
	if params.WebhookURL != nil {
		return params.WebhookURL
	}
	return nil
}

// KYCAPIClient returns an instance of the billing account's underlying KYCAPI
func (k *KYCApplication) KYCAPIClient() (KYCAPI, error) {
	if k.Provider == nil {
		return nil, fmt.Errorf("Failed to resolve KYC provider for KYC application %s", k.ID)
	}

	var apiClient KYCAPI

	switch *k.Provider {
	case identitymindKYCProvider:
		apiClient = providers.InitIdentityMind()
	case vouchedKYCProvider:
		apiClient = providers.InitVouched()
	default:
		return nil, fmt.Errorf("Failed to resolve KYC provider for billing account %s", k.ID)
	}

	return apiClient, nil
}
