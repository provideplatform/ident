package main

import (
	identitymind "github.com/kthomas/identitymind-golang"
)

// IdentityMind API client; conforms to MoneyServiceAPI interface
type IdentityMind struct {
	apiClient *identitymind.IdentityMindAPIClient
}

// InitIdentityMind initializes a new IdentityMind client instance using the given user and api key
func InitIdentityMind() *IdentityMind {
	apiClient, _ := identitymind.NewIdentityMindAPIClient()
	return &IdentityMind{
		apiClient: apiClient,
	}
}

// Cases

// GetCase retrieves an existing case
func (i *IdentityMind) GetCase(caseID string) (interface{}, error) {
	return i.apiClient.GetCase(caseID)
}

// CreateCase creates a new case
func (i *IdentityMind) CreateCase(params map[string]interface{}) (interface{}, error) {
	return i.apiClient.CreateCase(params)
}

// CloseCase closes a case
func (i *IdentityMind) CloseCase(caseID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.CloseCase(caseID, params)
}

// UpdateCase updates an open case
func (i *IdentityMind) UpdateCase(caseID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.UpdateCase(caseID, params)
}

// Transactions

// EvaluateFraud evaluates a transaction for payment fraud
func (i *IdentityMind) EvaluateFraud(params map[string]interface{}) (interface{}, error) {
	return i.apiClient.EvaluateFraud(params)
}

// ReportTransaction reports various kinds of transactions including deposits, withdrawals and internal transfer
func (i *IdentityMind) ReportTransaction(txType string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.ReportTransaction(txType, params)
}

// KYC

// ApproveApplication approves consumer KYC application
func (i *IdentityMind) ApproveApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.ApproveApplication(applicationID, params)
}

// RejectApplication rejects consumer KYC application
func (i *IdentityMind) RejectApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.RejectApplication(applicationID, params)
}

// SubmitApplication submits consumer KYC application
func (i *IdentityMind) SubmitApplication(params map[string]interface{}) (interface{}, error) {
	return i.apiClient.SubmitApplication(params)
}

// UploadDocument attaches a document to a KYC application
func (i *IdentityMind) UploadDocument(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.UploadDocument(applicationID, params)
}

// UploadDocumentVerificationImage attaches a document image to a KYC application for verification
func (i *IdentityMind) UploadDocumentVerificationImage(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.UploadDocumentVerificationImage(applicationID, params)
}

// GetApplication fetches a KYC application
func (i *IdentityMind) GetApplication(applicationID string) (interface{}, error) {
	return i.apiClient.GetApplication(applicationID)
}

// ListDocuments retrieves a list of documents attached to a KYC application
func (i *IdentityMind) ListDocuments(applicationID string) (interface{}, error) {
	return i.apiClient.ListDocuments(applicationID)
}

// DownloadDocument retrieves a specific document attached to a KYC application
func (i *IdentityMind) DownloadDocument(applicationID, documentID string) (interface{}, error) {
	return i.apiClient.DownloadDocument(applicationID, documentID)
}

// KYB

// ApproveBusinessApplication approves a KYB application
func (i *IdentityMind) ApproveBusinessApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.ApproveBusinessApplication(applicationID, params)
}

// RejectBusinessApplication rejects a KYB application
func (i *IdentityMind) RejectBusinessApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.RejectBusinessApplication(applicationID, params)
}

// ReevaluateBusinessApplication reevaluates a KYB application
func (i *IdentityMind) ReevaluateBusinessApplication(applicationID string) (interface{}, error) {
	return i.apiClient.ReevaluateBusinessApplication(applicationID)
}

// SubmitBusinessApplication submits a KYB application
func (i *IdentityMind) SubmitBusinessApplication(params map[string]interface{}) (interface{}, error) {
	return i.apiClient.SubmitBusinessApplication(params)
}

// UploadBusinessDocument attaches a document to a KYB application
func (i *IdentityMind) UploadBusinessDocument(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.UploadBusinessDocument(applicationID, params)
}

// UploadBusinessDocumentVerificationImage attaches a document image to a KYB application for verification
func (i *IdentityMind) UploadBusinessDocumentVerificationImage(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.UploadBusinessDocumentVerificationImage(applicationID, params)
}

// DownloadBusinessDocument retrieves a specific document attached to a KYB application
func (i *IdentityMind) DownloadBusinessDocument(applicationID, documentID string) (interface{}, error) {
	return i.apiClient.DownloadBusinessDocument(applicationID, documentID)
}

// GetBusinessApplication fetches a KYB application
func (i *IdentityMind) GetBusinessApplication(applicationID string) (interface{}, error) {
	return i.apiClient.GetBusinessApplication(applicationID)
}

// ListBusinessDocuments retrieves a list of documents attached to a KYB application
func (i *IdentityMind) ListBusinessDocuments(applicationID string) (interface{}, error) {
	return i.apiClient.ListBusinessDocuments(applicationID)
}
