package main

import (
	"encoding/json"
	"fmt"
	"strings"

	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideservices/provide-go"
)

const kycApplicationStatusAccepted = "accepted"
const kycApplicationStatusPending = "pending"
const kycApplicationStatusRejected = "rejected"
const kycApplicationStatusUnderReview = "review"

const defaultKYCProvider = identitymindKYCProvider
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
	UserID     uuid.UUID `sql:"type:uuid not null" json:"user_id"`
	Provider   *string   `sql:"not null" json:"provider"`
	Identifier *string   `json:"identifier"`
	Status     *string   `sql:"not null;default:'pending'" json:"identifier"`
}

// Create and persist a new BillingAccount
func (k *KYCApplication) Create() bool {
	db := DatabaseConnection()

	if k.Provider == nil {
		k.Provider = stringOrNil(defaultKYCProvider)
	}

	if !k.Validate() {
		return false
	}

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
				natsConnection.Publish(natsCheckKYCApplicationStatusSubject, payload)
			}
			return success
		}
	}
	return false
}

// Validate a KYCApplication for persistence
func (k *KYCApplication) Validate() bool {
	k.Errors = make([]*provide.Error, 0)
	if k.UserID == uuid.Nil {
		k.Errors = append(k.Errors, &provide.Error{
			Message: stringOrNil("Unable to create a KYC application without an associated user"),
		})
	}
	if k.Provider == nil {
		k.Errors = append(k.Errors, &provide.Error{
			Message: stringOrNil("Unable to create a KYC application without a provider-specific identifier"),
		})
	}
	return len(k.Errors) == 0
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

func (k *KYCApplication) isUnderReview() bool {
	if k.Status == nil {
		return false
	}
	return strings.ToLower(*k.Status) == kycApplicationStatusUnderReview
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
