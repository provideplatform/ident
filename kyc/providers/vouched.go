package providers

import (
	vouched "github.com/kthomas/vouched-golang"
)

// Vouched API client; conforms to KYCAPI interface
type Vouched struct {
	apiClient *vouched.VouchedAPIClient
}

// InitVouched initializes a new Vouched client instance using the given api key
func InitVouched() *Vouched {
	apiClient, _ := vouched.NewVouchedAPIClient()
	return &Vouched{
		apiClient: apiClient,
	}
}

// MarshalKYCApplication transforms the given map representation of KYCApplicationParams to the Vouched equivalent
func (v *Vouched) MarshalKYCApplication(params map[string]interface{}) map[string]interface{} {
	vouchedParams := map[string]interface{}{
		"dob":       params["date_of_birth"],
		"firstName": params["first_name"],
		"lastName":  params["last_name"],
	}
	if idPhoto, idPhotoOk := params["id_photo"]; idPhotoOk {
		vouchedParams["idPhoto"] = idPhoto
	}
	if idPhotoBack, idPhotoBackOk := params["id_photo_back"]; idPhotoBackOk {
		vouchedParams["idPhotoBack"] = idPhotoBack
	}
	if selfie, selfieOk := params["selfie"]; selfieOk {
		vouchedParams["userPhoto"] = selfie
	}
	if nestedParams, nestedParamsOk := params["params"].(map[string]interface{}); nestedParamsOk {
		for k, v := range nestedParams {
			vouchedParams[k] = v
		}
	}
	return map[string]interface{}{
		"params":      vouchedParams,
		"type":        params["type"],
		"callbackURL": params["webhook_url"],
	}
}

// MarshalKYCApplicationParams transforms the given Vouched KYC application map representation to the KYCApplicationParams
func (v *Vouched) MarshalKYCApplicationParams(vouchedParams map[string]interface{}) map[string]interface{} {
	params := map[string]interface{}{
		"date_of_birth": vouchedParams["date_of_birth"],
		"first_name":    vouchedParams["firstName"],
		"last_name":     vouchedParams["lastName"],
	}
	if idPhoto, idPhotoOk := vouchedParams["idPhoto"]; idPhotoOk {
		params["id_photo"] = idPhoto
	}
	if idPhotoBack, idPhotoBackOk := vouchedParams["idPhotoBack"]; idPhotoBackOk {
		params["id_photo_back"] = idPhotoBack
	}
	if selfie, selfieOk := vouchedParams["userPhoto"]; selfieOk {
		params["selfie"] = selfie
	}
	return params
}

// Cases

// GetCase retrieves an existing case
func (v *Vouched) GetCase(caseID string) (interface{}, error) {
	return v.apiClient.GetCase(caseID)
}

// CreateCase creates a new case
func (v *Vouched) CreateCase(params map[string]interface{}) (interface{}, error) {
	return v.apiClient.CreateCase(params)
}

// CloseCase closes a case
func (v *Vouched) CloseCase(caseID string, params map[string]interface{}) (interface{}, error) {
	return v.apiClient.CloseCase(caseID, params)
}

// UpdateCase updates an open case
func (v *Vouched) UpdateCase(caseID string, params map[string]interface{}) (interface{}, error) {
	return v.apiClient.UpdateCase(caseID, params)
}

// Transactions

// EvaluateFraud evaluates a transaction for payment fraud
func (v *Vouched) EvaluateFraud(params map[string]interface{}) (interface{}, error) {
	return v.apiClient.EvaluateFraud(params)
}

// ReportTransaction reports various kinds of transactions including deposits, withdrawals and internal transfer
func (v *Vouched) ReportTransaction(txType string, params map[string]interface{}) (interface{}, error) {
	return v.apiClient.ReportTransaction(txType, params)
}

// KYC

// ApproveApplication approves consumer KYC application
func (v *Vouched) ApproveApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return v.apiClient.ApproveApplication(applicationID, params)
}

// RejectApplication rejects consumer KYC application
func (v *Vouched) RejectApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return v.apiClient.RejectApplication(applicationID, params)
}

// SubmitApplication submits consumer KYC application
func (v *Vouched) SubmitApplication(params map[string]interface{}) (interface{}, error) {
	return v.apiClient.SubmitApplication(params)
}

// UndecideApplication marks the consumer KYC application undecided
func (v *Vouched) UndecideApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return v.apiClient.UndecideApplication(applicationID, params)
}

// UploadApplicationDocument attaches a document to a KYC application
func (v *Vouched) UploadApplicationDocument(applicationID string, params map[string]interface{}) (interface{}, error) {
	return v.apiClient.UploadApplicationDocument(applicationID, params)
}

// UploadApplicationDocumentVerificationImage attaches a document image to a KYC application for verification
func (v *Vouched) UploadApplicationDocumentVerificationImage(applicationID string, params map[string]interface{}) (interface{}, error) {
	return v.apiClient.UploadApplicationDocumentVerificationImage(applicationID, params)
}

// GetApplication fetches a KYC application
func (v *Vouched) GetApplication(applicationID string) (interface{}, error) {
	return v.apiClient.GetApplication(applicationID)
}

// ListApplicationDocuments retrieves a list of documents attached to a KYC application
func (v *Vouched) ListApplicationDocuments(applicationID string) (interface{}, error) {
	return v.apiClient.ListApplicationDocuments(applicationID)
}

// DownloadApplicationDocument retrieves a specific document attached to a KYC application
func (v *Vouched) DownloadApplicationDocument(applicationID, documentID string) (interface{}, error) {
	return v.apiClient.DownloadApplicationDocument(applicationID, documentID)
}

// KYB

// ApproveBusinessApplication approves a KYB application
func (v *Vouched) ApproveBusinessApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return v.apiClient.ApproveBusinessApplication(applicationID, params)
}

// RejectBusinessApplication rejects a KYB application
func (v *Vouched) RejectBusinessApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return v.apiClient.RejectBusinessApplication(applicationID, params)
}

// ReevaluateBusinessApplication reevaluates a KYB application
func (v *Vouched) ReevaluateBusinessApplication(applicationID string) (interface{}, error) {
	return v.apiClient.ReevaluateBusinessApplication(applicationID)
}

// SubmitBusinessApplication submits a KYB application
func (v *Vouched) SubmitBusinessApplication(params map[string]interface{}) (interface{}, error) {
	return v.apiClient.SubmitBusinessApplication(params)
}

// UndecideBusinessApplication marks the consumer KYC application undecided
func (v *Vouched) UndecideBusinessApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return v.apiClient.UndecideBusinessApplication(applicationID, params)
}

// UploadBusinessApplicationDocument attaches a document to a KYB application
func (v *Vouched) UploadBusinessApplicationDocument(applicationID string, params map[string]interface{}) (interface{}, error) {
	return v.apiClient.UploadBusinessApplicationDocument(applicationID, params)
}

// UploadBusinessApplicationDocumentVerificationImage attaches a document image to a KYB application for verification
func (v *Vouched) UploadBusinessApplicationDocumentVerificationImage(applicationID string, params map[string]interface{}) (interface{}, error) {
	return v.apiClient.UploadBusinessApplicationDocumentVerificationImage(applicationID, params)
}

// DownloadBusinessApplicationDocument retrieves a specific document attached to a KYB application
func (v *Vouched) DownloadBusinessApplicationDocument(applicationID, documentID string) (interface{}, error) {
	return v.apiClient.DownloadBusinessApplicationDocument(applicationID, documentID)
}

// GetBusinessApplication fetches a KYB application
func (v *Vouched) GetBusinessApplication(applicationID string) (interface{}, error) {
	return v.apiClient.GetBusinessApplication(applicationID)
}

// ListBusinessApplicationDocuments retrieves a list of documents attached to a KYB application
func (v *Vouched) ListBusinessApplicationDocuments(applicationID string) (interface{}, error) {
	return v.apiClient.ListBusinessApplicationDocuments(applicationID)
}

// Merchant aggregation

// CreateMerchant creates a new merchant account
func (v *Vouched) CreateMerchant(params map[string]interface{}) (interface{}, error) {
	return v.CreateMerchant(params)
}

// GetMerchant retrieves a merchant account by id
func (v *Vouched) GetMerchant(merchantID string) (interface{}, error) {
	return v.GetMerchant(merchantID)
}

// UpdateMerchant updates an existing merchant account
func (v *Vouched) UpdateMerchant(merchantID string, params map[string]interface{}) (interface{}, error) {
	return v.UpdateMerchant(merchantID, params)
}

// Merchant KYC

// ApproveMerchantApplication approves consumer KYC application
func (v *Vouched) ApproveMerchantApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return v.apiClient.ApproveMerchantApplication(applicationID, params)
}

// RejectMerchantApplication rejects consumer KYC application
func (v *Vouched) RejectMerchantApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return v.apiClient.RejectMerchantApplication(applicationID, params)
}

// SubmitMerchantApplication submits consumer KYC application
func (v *Vouched) SubmitMerchantApplication(params map[string]interface{}) (interface{}, error) {
	return v.apiClient.SubmitMerchantApplication(params)
}

// UndecideMerchantApplication marks the consumer KYC application undecided
func (v *Vouched) UndecideMerchantApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return v.apiClient.UndecideMerchantApplication(applicationID, params)
}

// UploadMerchantApplicationDocument attaches a document to a KYC application
func (v *Vouched) UploadMerchantApplicationDocument(applicationID string, params map[string]interface{}) (interface{}, error) {
	return v.apiClient.UploadMerchantApplicationDocument(applicationID, params)
}

// UploadMerchantApplicationDocumentVerificationImage attaches a document image to a KYC application for verification
func (v *Vouched) UploadMerchantApplicationDocumentVerificationImage(applicationID string, params map[string]interface{}) (interface{}, error) {
	return v.apiClient.UploadMerchantApplicationDocumentVerificationImage(applicationID, params)
}

// GetMerchantApplication fetches a KYC application
func (v *Vouched) GetMerchantApplication(applicationID string) (interface{}, error) {
	return v.apiClient.GetMerchantApplication(applicationID)
}

// ListMerchantApplicationDocuments retrieves a list of documents attached to a KYC application
func (v *Vouched) ListMerchantApplicationDocuments(applicationID string) (interface{}, error) {
	return v.apiClient.ListMerchantApplicationDocuments(applicationID)
}

// DownloadMerchantApplicationDocument retrieves a specific document attached to a KYC application
func (v *Vouched) DownloadMerchantApplicationDocument(applicationID, documentID string) (interface{}, error) {
	return v.apiClient.DownloadMerchantApplicationDocument(applicationID, documentID)
}

// ProvideApplicationResponse provides a response to a KYC application `prompt
func (v *Vouched) ProvideApplicationResponse(applicationID string, params map[string]interface{}) (interface{}, error) {
	return v.apiClient.ProvideApplicationResponse(applicationID, params)
}

// Merchant KYB

// RejectMerchantBusinessApplication see https://edoc.identitymind.com/reference#feedback_1
func (v *Vouched) RejectMerchantBusinessApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return v.RejectMerchantBusinessApplication(applicationID, params)
}

// GetMerchantBusinessApplication see https://edoc.identitymind.com/reference#getmerchantkyc
func (v *Vouched) GetMerchantBusinessApplication(applicationID string) (interface{}, error) {
	return v.GetMerchantBusinessApplication(applicationID)
}

// ReevaluateMerchantBusinessApplication see https://edoc.identitymind.com/reference#reevaluatemerchant
func (v *Vouched) ReevaluateMerchantBusinessApplication(applicationID string) (interface{}, error) {
	return v.GetMerchantBusinessApplication(applicationID)
}

// SubmitMerchantBusinessApplication see https://edoc.identitymind.com/reference#merchant
func (v *Vouched) SubmitMerchantBusinessApplication(params map[string]interface{}) (interface{}, error) {
	return v.SubmitMerchantBusinessApplication(params)
}

// ListMerchantBusinessApplicationDocuments see https://edoc.identitymind.com/reference#getfilelistforapplicationformerchant
func (v *Vouched) ListMerchantBusinessApplicationDocuments(applicationID string) (interface{}, error) {
	return v.ListMerchantBusinessApplicationDocuments(applicationID)
}

// DownloadMerchantBusinessApplicationDocument see https://edoc.identitymind.com/reference#reevaluatemerchant
func (v *Vouched) DownloadMerchantBusinessApplicationDocument(applicationID, documentID string) (interface{}, error) {
	return v.DownloadMerchantBusinessApplicationDocument(applicationID, documentID)
}

// UploadMerchantBusinessApplicationDocument see https://edoc.identitymind.com/reference#processfileuploadrequestformerchantkyc
func (v *Vouched) UploadMerchantBusinessApplicationDocument(applicationID string, params map[string]interface{}) (interface{}, error) {
	return v.UploadMerchantBusinessApplicationDocument(applicationID, params)
}

// UploadMerchantBusinessApplicationDocumentVerificationImage see https://edoc.identitymind.com/reference#processfileuploadrequestformerchantkyc
func (v *Vouched) UploadMerchantBusinessApplicationDocumentVerificationImage(applicationID string, params map[string]interface{}) (interface{}, error) {
	return v.UploadMerchantBusinessApplicationDocumentVerificationImage(applicationID, params)
}

// ApproveMerchantBusinessApplication see https://edoc.identitymind.com/reference#feedback_1
func (v *Vouched) ApproveMerchantBusinessApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return v.ApproveMerchantBusinessApplication(applicationID, params)
}

// UndecideMerchantBusinessApplication marks the consumer KYC application undecided
func (v *Vouched) UndecideMerchantBusinessApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return v.apiClient.UndecideMerchantBusinessApplication(applicationID, params)
}

// ProvideMerchantApplicationResponse provides a response to a merchant KYC application prompt
func (v *Vouched) ProvideMerchantApplicationResponse(applicationID string, params map[string]interface{}) (interface{}, error) {
	return v.apiClient.ProvideMerchantApplicationResponse(applicationID, params)
}

// Merchant Transactions

// EvaluateMerchantFraud evaluates payment fraud on behalf of a merchant
func (v *Vouched) EvaluateMerchantFraud(merchantID string, params map[string]interface{}) (interface{}, error) {
	return v.EvaluateMerchantFraud(merchantID, params)
}

// ReportMerchantTransaction reports a transaction on behalf of a merchant
func (v *Vouched) ReportMerchantTransaction(merchantID, txType string, params map[string]interface{}) (interface{}, error) {
	return v.ReportMerchantTransaction(merchantID, txType, params)
}
