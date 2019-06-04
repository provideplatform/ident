package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
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
	DownloadDocument(string, string) (interface{}, error)
	GetApplication(string) (interface{}, error)
	ListDocuments(string) (interface{}, error)
	RejectApplication(string, map[string]interface{}) (interface{}, error)
	SubmitApplication(map[string]interface{}) (interface{}, error)
	UploadDocument(string, map[string]interface{}) (interface{}, error)
	UploadDocumentVerificationImage(string, map[string]interface{}) (interface{}, error)

	// KYB applications
	ApproveBusinessApplication(string, map[string]interface{}) (interface{}, error)
	DownloadBusinessDocument(string, string) (interface{}, error)
	GetBusinessApplication(string) (interface{}, error)
	ListBusinessDocuments(string) (interface{}, error)
	SubmitBusinessApplication(map[string]interface{}) (interface{}, error)
	ReevaluateBusinessApplication(string) (interface{}, error)
	RejectBusinessApplication(string, map[string]interface{}) (interface{}, error)
	UploadBusinessDocument(string, map[string]interface{}) (interface{}, error)
	UploadBusinessDocumentVerificationImage(string, map[string]interface{}) (interface{}, error)
}

// KYCApplication represents a KYC application process
type KYCApplication struct {
	provide.Model
	UserID                 *uuid.UUID             `sql:"type:uuid not null" json:"user_id"`
	Provider               *string                `sql:"not null" json:"provider"`
	Identifier             *string                `json:"identifier"`
	Type                   *string                `sql:"not null" json:"type"`
	Status                 *string                `sql:"not null;default:'pending'" json:"status"`
	Params                 map[string]interface{} `sql:"-" json:"params"`
	EncryptedParams        *string                `sql:"type:bytea" json:"-"`
	ProviderRepresentation map[string]interface{} `sql:"-" json:"provider_representation"`
}

// Create and persist a new BillingAccount
func (k *KYCApplication) Create() bool {
	db := DatabaseConnection()

	if k.Provider == nil {
		k.Provider = stringOrNil(defaultKYCProvider)
	}

	if k.Type == nil {
		k.Type = stringOrNil(defaultKYCApplicationType)
	} else {
		k.Type = stringOrNil(strings.ToLower(*k.Type))
	}

	if !k.Validate() {
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
				natsConnection := getNatsStreamingConnection()
				natsConnection.Publish(natsSubmitKYCApplicationSubject, payload)
			}
			return success
		}
	}
	return false
}

// Validate a KYCApplication for persistence
func (k *KYCApplication) Validate() bool {
	k.Errors = make([]*provide.Error, 0)
	if k.UserID == nil || *k.UserID == uuid.Nil {
		k.Errors = append(k.Errors, &provide.Error{
			Message: stringOrNil("Unable to create a KYC application without an associated user"),
		})
	}
	if k.Provider == nil {
		k.Errors = append(k.Errors, &provide.Error{
			Message: stringOrNil("Unable to create a KYC application without a provider-specific identifier"),
		})
	}
	if k.Type == nil || (*k.Type != consumerKYCApplicationType && *k.Type != businessKYCApplicationType) {
		k.Errors = append(k.Errors, &provide.Error{
			Message: stringOrNil("Unable to create a KYC application without a type"),
		})
	}
	return len(k.Errors) == 0
}

// submit the KYCApplication to the provider
func (k *KYCApplication) submit(db *gorm.DB) error {
	if !k.isPending() {
		return fmt.Errorf("KYC application has been submitted; not attempting to resubmit KYC application: %s", k.ID)
	}
	apiClient, err := k.KYCAPIClient()
	if err != nil {
		log.Warningf("Failed to submit KYC application; no KYC API client resolved for provider: %s; %s", *k.Provider, err.Error())
		return err
	}
	params, err := k.decryptedParams()
	if err != nil {
		log.Warningf("Failed to submit KYC application; failed to decrypt params; %s", err.Error())
		return err
	}
	resp, err := apiClient.SubmitApplication(params)
	if err != nil {
		log.Warningf("Failed to resolve KYC API client; %s", err.Error())
		return err
	}
	if apiResponse, apiResponseOk := resp.(map[string]interface{}); apiResponseOk {
		k.ProviderRepresentation = apiResponse

		switch *k.Provider {
		case identitymindKYCProvider:
			if mtid, mtidOk := apiResponse["mtid"].(string); mtidOk {
				log.Debugf("Resolved identitymind KYC application identifier '%s' for KYC application: %s", mtid, k.ID)
				k.Identifier = stringOrNil(mtid)
			} else {
				k.updateStatus(db, kycApplicationStatusFailed)
				return fmt.Errorf("Identitymind KYC application submission failed to return valid identifier: %s", k.ID)
			}
		default:
			// no-op
		}
	}
	k.updateStatus(db, kycApplicationStatusSubmitted)
	payload, _ := json.Marshal(map[string]interface{}{
		"kyc_application_id": k.ID.String(),
	})
	natsConnection := getNatsStreamingConnection()
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

func (k *KYCApplication) updateStatus(db *gorm.DB, status string) {
	k.Status = stringOrNil(status)
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
