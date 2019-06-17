package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	identitymind "github.com/kthomas/identitymind-golang"
	provide "github.com/provideservices/provide-go"
)

const kycApplicationStatusAccepted = "accepted"
const kycApplicationStatusFailed = "failed" // the KYC application API call itself failed
const kycApplicationStatusPending = "pending"
const kycApplicationStatusRejected = "rejected"
const kycApplicationStatusSubmitted = "submitted"
const kycApplicationStatusUnderReview = "review"

const defaultKYCProvider = identitymindKYCProvider
const defaultKYCApplicationType = consumerKYCApplicationType
const consumerKYCApplicationType = "kyc"
const businessKYCApplicationType = "kyb"
const identitymindKYCProvider = "identitymind"

func init() {
	db := dbconf.DatabaseConnection()

	db.AutoMigrate(&KYCApplication{})
	db.Model(&KYCApplication{}).AddIndex("idx_kyc_applications_application_id", "application_id")
	db.Model(&KYCApplication{}).AddIndex("idx_kyc_applications_user_id", "user_id")
	db.Model(&KYCApplication{}).AddIndex("idx_kyc_applications_identifier", "identifier")
	db.Model(&KYCApplication{}).AddIndex("idx_kyc_applications_status", "status")
	db.Model(&KYCApplication{}).AddForeignKey("user_id", "users(id)", "SET NULL", "CASCADE")
}

// KYCAPI is implemented by BillingAccount KYC clients such as identitymind.go
type KYCAPI interface {
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
	Description            *string                `json:"description"`
	Params                 map[string]interface{} `sql:"-" json:"params"`
	EncryptedParams        *string                `sql:"type:bytea" json:"-"`
	ProviderRepresentation map[string]interface{} `sql:"-" json:"provider_representation"`
}

// Create and persist a new BillingAccount
func (k *KYCApplication) Create(db *gorm.DB) bool {
	if k.Provider == nil {
		k.Provider = stringOrNil(defaultKYCProvider)
	}

	if k.Type == nil {
		k.Type = stringOrNil(defaultKYCApplicationType)
	} else {
		k.Type = stringOrNil(strings.ToLower(*k.Type))
	}

	if !k.Validate(db) {
		return false
	}

	k.setEncryptedParams(k.Params)

	if db.NewRecord(k) {
		result := db.Create(&k)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				k.Errors = append(k.Errors, &provide.Error{
					Message: stringOrNil(err.Error()),
				})
			}
		}
		if !db.NewRecord(k) {
			success := rowsAffected > 0
			if success {
				payload, _ := json.Marshal(map[string]interface{}{
					"kyc_application_id": k.ID.String(),
				})
				natsConnection, _ := natsutil.GetNatsStreamingConnection(time.Second*30, nil)
				natsConnection.Publish(natsSubmitKYCApplicationSubject, payload)
			}
			return success
		}
	}
	return false
}

// Update an existing KYC application; if status is non-nil, the application
// status will be updated, provided the state change is valid
func (k *KYCApplication) Update(status *string) bool {
	db := DatabaseConnection()

	if !k.Validate(db) {
		return false
	}

	k.setEncryptedParams(k.Params)

	result := db.Save(&k)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			k.Errors = append(k.Errors, &provide.Error{
				Message: stringOrNil(err.Error()),
			})
		}
	} else {
		payload, _ := json.Marshal(map[string]interface{}{
			"kyc_application_id": k.ID.String(),
			"status":             status,
		})
		natsConnection, _ := natsutil.GetNatsStreamingConnection(time.Second*30, nil)
		natsConnection.Publish(natsSubmitKYCApplicationSubject, payload)
	}

	return len(k.Errors) == 0
}

// Validate a KYCApplication for persistence
func (k *KYCApplication) Validate(db *gorm.DB) bool {
	k.Errors = make([]*provide.Error, 0)
	if k.UserID == nil || *k.UserID == uuid.Nil {
		k.Errors = append(k.Errors, &provide.Error{
			Message: stringOrNil("Unable to persist a KYC application without an associated user"),
		})
	} else {
		user := k.User(db)
		if user != nil {
			if user.ApplicationID != nil && *user.ApplicationID != uuid.Nil {
				if k.ApplicationID == nil || *k.ApplicationID != *user.ApplicationID {
					k.Errors = append(k.Errors, &provide.Error{
						Message: stringOrNil("Unable to persist a KYC application on behalf of an application user without matching application_id"),
					})
				}
			}
		}
	}
	if k.Provider == nil {
		k.Errors = append(k.Errors, &provide.Error{
			Message: stringOrNil("Unable to persist a KYC application without a provider-specific identifier"),
		})
	}
	if k.Type == nil || (*k.Type != consumerKYCApplicationType && *k.Type != businessKYCApplicationType) {
		k.Errors = append(k.Errors, &provide.Error{
			Message: stringOrNil("Unable to persist a KYC application without a type"),
		})
	}
	return len(k.Errors) == 0
}

// User retrieves the user related to the KYC application
func (k *KYCApplication) User(db *gorm.DB) *User {
	if k.UserID == nil || *k.UserID == uuid.Nil {
		return nil
	}
	user := &User{}
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
		log.Warningf("Failed to submit KYC application; no KYC API client resolved for provider: %s; %s", *k.Provider, err.Error())
		return err
	}
	var params map[string]interface{}
	if k.Params != nil {
		params = k.Params
	} else {
		params, err = k.decryptedParams()
		if err != nil {
			log.Warningf("Failed to submit KYC application; failed to decrypt params; %s", err.Error())
			return err
		}
	}
	resp, err := apiClient.SubmitApplication(params)
	if err != nil {
		log.Warningf("Failed to resolve KYC API client; %s", err.Error())
		return err
	}
	if apiResponse, apiResponseOk := resp.(map[string]interface{}); apiResponseOk {
		k.Params, _ = k.decryptedParams()
		k.ProviderRepresentation = apiResponse

		switch *k.Provider {
		case identitymindKYCProvider:
			if k.Identifier == nil {
				if mtid, mtidOk := apiResponse["mtid"].(string); mtidOk {
					log.Debugf("Resolved identitymind KYC application identifier '%s' for KYC application: %s", mtid, k.ID)
					k.Identifier = stringOrNil(mtid)
					k.updateStatus(db, kycApplicationStatusSubmitted, nil)
				} else {
					desc, _ := apiResponse["error_message"].(string)
					k.updateStatus(db, kycApplicationStatusFailed, stringOrNil(desc))
					return fmt.Errorf("Identitymind KYC application submission failed to return valid identifier: %s; response: %s", k.ID, apiResponse)
				}
			}
		default:
			// no-op
		}
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"kyc_application_id": k.ID.String(),
	})

	natsConnection, _ := natsutil.GetNatsStreamingConnection(time.Second*30, nil)
	natsConnection.Publish(natsCheckKYCApplicationStatusSubject, payload)
	return nil
}

// enrich the KYCApplication with the provider's current representation
func (k *KYCApplication) enrich() (interface{}, error) {
	apiClient, err := k.KYCAPIClient()
	if err != nil {
		log.Warningf("Failed to enrich KYC application; no KYC API client resolved for provider: %s", *k.Provider)
		return nil, err
	}
	if k.Identifier == nil {
		msg := fmt.Sprintf("Failed to enrich KYC application for provider: %s; KYC application id: %s", *k.Provider, k.ID)
		log.Warning(msg)
		return nil, errors.New(msg)
	}
	resp, err := apiClient.GetApplication(*k.Identifier)
	if err != nil {
		log.Warningf("Failed to resolve KYC API client; %s", err.Error())
		return nil, err
	}
	var marshaledResponse interface{}
	if apiResponse, apiResponseOk := resp.(map[string]interface{}); apiResponseOk {
		k.Params, _ = k.decryptedParams()
		k.ProviderRepresentation = apiResponse

		switch *k.Provider {
		case identitymindKYCProvider:
			apiResponseJSON, _ := json.Marshal(apiResponse)
			marshaledResponse = &identitymind.KYCApplication{}
			err = json.Unmarshal(apiResponseJSON, &marshaledResponse)
			if err != nil {
				return nil, fmt.Errorf("Failed to unmarshal identitymind KYC application response to struct; %s", err.Error())
			}
		default:
			// no-op
		}

	}
	return marshaledResponse, nil
}

func (k *KYCApplication) decryptedParams() (map[string]interface{}, error) {
	decryptedParams := map[string]interface{}{}
	if k.EncryptedParams != nil {
		encryptedParamsJSON, err := PGPPubDecrypt(*k.EncryptedParams, gpgPrivateKey, gpgPassword)
		if err != nil {
			log.Warningf("Failed to decrypt encrypted KYC application params; %s", err.Error())
			return decryptedParams, err
		}

		err = json.Unmarshal(encryptedParamsJSON, &decryptedParams)
		if err != nil {
			log.Warningf("Failed to unmarshal decrypted KYC application params; %s", err.Error())
			return decryptedParams, err
		}
	}
	return decryptedParams, nil
}

func (k *KYCApplication) encryptParams() bool {
	if k.EncryptedParams != nil {
		encryptedParams, err := PGPPubEncrypt(*k.EncryptedParams, gpgPublicKey)
		if err != nil {
			log.Warningf("Failed to encrypt KYC application params; %s", err.Error())
			k.Errors = append(k.Errors, &provide.Error{
				Message: stringOrNil(err.Error()),
			})
			return false
		}
		k.EncryptedParams = encryptedParams
	}
	return true
}

func (k *KYCApplication) setEncryptedParams(params map[string]interface{}) {
	paramsJSON, _ := json.Marshal(params)
	_paramsJSON := string(json.RawMessage(paramsJSON))
	k.EncryptedParams = &_paramsJSON
	k.encryptParams()
	k.Params = params
}

func (k *KYCApplication) hasReachedDecision() bool {
	return k.isAccepted() || k.isRejected()
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

func (k *KYCApplication) updateStatus(db *gorm.DB, status string, description *string) {
	k.Status = stringOrNil(status)
	k.Description = description
	result := db.Save(&k)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			k.Errors = append(k.Errors, &provide.Error{
				Message: stringOrNil(err.Error()),
			})
		}
	}
}

func (k *KYCApplication) accept(db *gorm.DB) error {
	if k.Status != nil && *k.Status == kycApplicationStatusAccepted {
		return fmt.Errorf("Failed to accept application: %s; application already accepted", k.ID)
	}

	apiClient, err := k.KYCAPIClient()
	if err != nil {
		log.Warningf("Failed to accept application: %s; %s", k.ID, err.Error())
		return err
	}

	if k.Identifier == nil {
		msg := fmt.Sprintf("Failed to accept application: %s; KYC application identifier not set", k.ID)
		log.Warning(msg)
		return errors.New(msg)
	}

	_, err = apiClient.ApproveApplication(*k.Identifier, map[string]interface{}{})
	if err != nil {
		log.Warningf("Failed to accept application: %s; %s", k.ID, err.Error())
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
		log.Warningf("Failed to reject application: %s; %s", k.ID, err.Error())
		return err
	}

	if k.Identifier == nil {
		msg := fmt.Sprintf("Failed to reject application: %s; KYC application identifier not set", k.ID)
		log.Warning(msg)
		return errors.New(msg)
	}

	_, err = apiClient.RejectApplication(*k.Identifier, map[string]interface{}{})
	if err != nil {
		log.Warningf("Failed to reject application: %s; %s", k.ID, err.Error())
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
		log.Warningf("Failed to undecide application: %s; %s", k.ID, err.Error())
		return err
	}

	if k.Identifier == nil {
		msg := fmt.Sprintf("Failed to undecide application: %s; KYC application identifier not set", k.ID)
		log.Warning(msg)
		return errors.New(msg)
	}

	_, err = apiClient.UndecideApplication(*k.Identifier, map[string]interface{}{})
	if err != nil {
		log.Warningf("Failed to undecide application: %s; %s", k.ID, err.Error())
		return err
	}

	k.updateStatus(db, kycApplicationStatusUnderReview, nil)

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
		apiClient = InitIdentityMind()
	default:
		return nil, fmt.Errorf("Failed to resolve KYC provider for billing account %s", k.ID)
	}

	return apiClient, nil
}
