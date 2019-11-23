package providers

import (
	"fmt"
	"strings"

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

// MarshalKYCApplication transforms the given map representation of KYCApplicationParams to the IdentityMind equivalent
func (i *IdentityMind) MarshalKYCApplication(params map[string]interface{}) map[string]interface{} {
	identitymindParams := map[string]interface{}{
		"dob": params["date_of_birth"],
		"man": strings.Trim(fmt.Sprintf("%s %s", params["first_name"], params["last_name"]), " "),
	}
	if merchantID, merchantIDOk := params["merchant_id"]; merchantIDOk {
		params["m"] = merchantID
	}
	if affiliateID, affiliateIDOk := params["affiliate_id"]; affiliateIDOk {
		params["aflid"] = affiliateID
	}
	if merchantApplicationID, merchantApplicationIDOk := params["merchant_application_id"]; merchantApplicationIDOk {
		params["merchantAid"] = merchantApplicationID
	}
	if authService, authServiceOk := params["authorized_by"]; authServiceOk {
		params["soc"] = authService
	}
	if ipAddr, ipAddrOk := params["ip"]; ipAddrOk {
		params["ip"] = ipAddr
	}
	if email, emailOk := params["email"]; emailOk {
		params["tea"] = email
	}
	if ssn, ssnOk := params["ssn"]; ssnOk {
		params["assn"] = ssn
	}
	if phone, phoneOk := params["mobile"]; phoneOk {
		params["phn"] = phone
	}
	if mobile, mobileOk := params["mobile"]; mobileOk {
		params["pm"] = mobile
	}
	if address, addressOk := params["street_address"]; addressOk {
		params["bsn"] = address
	}
	if city, cityOk := params["city"]; cityOk {
		params["bc"] = city
	}
	if state, stateOk := params["state"]; stateOk {
		params["bs"] = state
	}
	if postalCode, postalCodeOk := params["postal_code"]; postalCodeOk {
		params["bz"] = postalCode
	}
	// if idNumber, idNumberOk := params["id"]; idNumberOk {
	// 	params["id"] = idNumber
	// }
	if idPhoto, idPhotoOk := params["id_photo"]; idPhotoOk {
		identitymindParams["scanData"] = idPhoto
	}
	if idPhotoBack, idPhotoBackOk := params["id_photo_back"]; idPhotoBackOk {
		identitymindParams["backsideImageData"] = idPhotoBack
	}
	if selfie, selfieOk := params["selfie"]; selfieOk {
		identitymindParams["faceImageData"] = selfie
	}
	if sourceDigitalCurrencyAddresses, sourceDigitalCurrencyAddressesOk := params["source_digital_currency_addresses"]; sourceDigitalCurrencyAddressesOk {
		identitymindParams["sdcad"] = sourceDigitalCurrencyAddresses
	}
	if destinationDigitalCurrencyAddresses, destinationDigitalCurrencyAddressesOk := params["destination_digital_currency_addresses"]; destinationDigitalCurrencyAddressesOk {
		identitymindParams["ddcad"] = destinationDigitalCurrencyAddresses
	}
	if nestedParams, nestedParamsOk := params["params"].(map[string]interface{}); nestedParamsOk {
		for k, v := range nestedParams {
			identitymindParams[k] = v
		}
	}
	return identitymindParams
}

// MarshalKYCApplicationParams transforms the given IdentityMind KYC application map representation to the KYCApplicationParams
func (i *IdentityMind) MarshalKYCApplicationParams(identitymindParams map[string]interface{}) map[string]interface{} {
	name := identitymindParams["man"].(string)
	params := map[string]interface{}{
		"date_of_birth": identitymindParams["dob"],
		"first_name":    strings.Trim(strings.Split(name, " ")[0], " "),
		"last_name":     strings.Trim(strings.Split(name, " ")[len(strings.Split(name, " "))-1], " "),
	}
	// if idNumber, idNumberOk := params["id"]; idNumberOk {
	// 	params["id"] = idNumber
	// }
	if idPhoto, idPhotoOk := params["scanData"]; idPhotoOk {
		params["id_photo"] = idPhoto
	}
	if idPhotoBack, idPhotoBackOk := params["backsideImageData"]; idPhotoBackOk {
		params["id_photo_back"] = idPhotoBack
	}
	if selfie, selfieOk := params["faceImageData"]; selfieOk {
		params["selfie"] = selfie
	}
	if merchantID, merchantIDOk := params["m"]; merchantIDOk {
		params["merchant_id"] = merchantID
	}
	if affiliateID, affiliateIDOk := params["aflid"]; affiliateIDOk {
		params["affiliate_id"] = affiliateID
	}
	if merchantApplicationID, merchantApplicationIDOk := params["merchantAid"]; merchantApplicationIDOk {
		params["merchant_application_id"] = merchantApplicationID
	}
	if authService, authServiceOk := params["soc"]; authServiceOk {
		params["authorized_by"] = authService
	}
	if ipAddr, ipAddrOk := params["ip"]; ipAddrOk {
		params["ip"] = ipAddr
	}
	if email, emailOk := params["tea"]; emailOk {
		params["email"] = email
	}
	if ssn, ssnOk := params["assn"]; ssnOk {
		params["ssn"] = ssn
	}
	if phone, phoneOk := params["phn"]; phoneOk {
		params["phone"] = phone
	}
	if mobile, mobileOk := params["pm"]; mobileOk {
		params["mobile"] = mobile
	}
	if address, addressOk := params["bsn"]; addressOk {
		params["street_address"] = address
	}
	if city, cityOk := params["bc"]; cityOk {
		params["city"] = city
	}
	if state, stateOk := params["bs"]; stateOk {
		params["state"] = state
	}
	if postalCode, postalCodeOk := params["bz"]; postalCodeOk {
		params["postal_code"] = postalCode
	}
	if sourceDigitalCurrencyAddresses, sourceDigitalCurrencyAddressesOk := params["sdcad"]; sourceDigitalCurrencyAddressesOk {
		params["source_digital_currency_addresses"] = sourceDigitalCurrencyAddresses
	}
	if destinationDigitalCurrencyAddresses, destinationDigitalCurrencyAddressesOk := params["ddcad"]; destinationDigitalCurrencyAddressesOk {
		params["destination_digital_currency_addresses"] = destinationDigitalCurrencyAddresses
	}
	return params
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

// UndecideApplication marks the consumer KYC application undecided
func (i *IdentityMind) UndecideApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.UndecideApplication(applicationID, params)
}

// UploadApplicationDocument attaches a document to a KYC application
func (i *IdentityMind) UploadApplicationDocument(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.UploadApplicationDocument(applicationID, params)
}

// UploadApplicationDocumentVerificationImage attaches a document image to a KYC application for verification
func (i *IdentityMind) UploadApplicationDocumentVerificationImage(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.UploadApplicationDocumentVerificationImage(applicationID, params)
}

// GetApplication fetches a KYC application
func (i *IdentityMind) GetApplication(applicationID string) (interface{}, error) {
	return i.apiClient.GetApplication(applicationID)
}

// ListApplicationDocuments retrieves a list of documents attached to a KYC application
func (i *IdentityMind) ListApplicationDocuments(applicationID string) (interface{}, error) {
	return i.apiClient.ListApplicationDocuments(applicationID)
}

// DownloadApplicationDocument retrieves a specific document attached to a KYC application
func (i *IdentityMind) DownloadApplicationDocument(applicationID, documentID string) (interface{}, error) {
	return i.apiClient.DownloadApplicationDocument(applicationID, documentID)
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

// UndecideBusinessApplication marks the consumer KYC application undecided
func (i *IdentityMind) UndecideBusinessApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.UndecideBusinessApplication(applicationID, params)
}

// UploadBusinessApplicationDocument attaches a document to a KYB application
func (i *IdentityMind) UploadBusinessApplicationDocument(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.UploadBusinessApplicationDocument(applicationID, params)
}

// UploadBusinessApplicationDocumentVerificationImage attaches a document image to a KYB application for verification
func (i *IdentityMind) UploadBusinessApplicationDocumentVerificationImage(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.UploadBusinessApplicationDocumentVerificationImage(applicationID, params)
}

// DownloadBusinessApplicationDocument retrieves a specific document attached to a KYB application
func (i *IdentityMind) DownloadBusinessApplicationDocument(applicationID, documentID string) (interface{}, error) {
	return i.apiClient.DownloadBusinessApplicationDocument(applicationID, documentID)
}

// GetBusinessApplication fetches a KYB application
func (i *IdentityMind) GetBusinessApplication(applicationID string) (interface{}, error) {
	return i.apiClient.GetBusinessApplication(applicationID)
}

// ListBusinessApplicationDocuments retrieves a list of documents attached to a KYB application
func (i *IdentityMind) ListBusinessApplicationDocuments(applicationID string) (interface{}, error) {
	return i.apiClient.ListBusinessApplicationDocuments(applicationID)
}

// Merchant aggregation

// CreateMerchant creates a new merchant account
func (i *IdentityMind) CreateMerchant(params map[string]interface{}) (interface{}, error) {
	return i.CreateMerchant(params)
}

// GetMerchant retrieves a merchant account by id
func (i *IdentityMind) GetMerchant(merchantID string) (interface{}, error) {
	return i.GetMerchant(merchantID)
}

// UpdateMerchant updates an existing merchant account
func (i *IdentityMind) UpdateMerchant(merchantID string, params map[string]interface{}) (interface{}, error) {
	return i.UpdateMerchant(merchantID, params)
}

// Merchant KYC

// ApproveMerchantApplication approves consumer KYC application
func (i *IdentityMind) ApproveMerchantApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.ApproveMerchantApplication(applicationID, params)
}

// RejectMerchantApplication rejects consumer KYC application
func (i *IdentityMind) RejectMerchantApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.RejectMerchantApplication(applicationID, params)
}

// SubmitMerchantApplication submits consumer KYC application
func (i *IdentityMind) SubmitMerchantApplication(params map[string]interface{}) (interface{}, error) {
	return i.apiClient.SubmitMerchantApplication(params)
}

// UndecideMerchantApplication marks the consumer KYC application undecided
func (i *IdentityMind) UndecideMerchantApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.UndecideMerchantApplication(applicationID, params)
}

// UploadMerchantApplicationDocument attaches a document to a KYC application
func (i *IdentityMind) UploadMerchantApplicationDocument(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.UploadMerchantApplicationDocument(applicationID, params)
}

// UploadMerchantApplicationDocumentVerificationImage attaches a document image to a KYC application for verification
func (i *IdentityMind) UploadMerchantApplicationDocumentVerificationImage(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.UploadMerchantApplicationDocumentVerificationImage(applicationID, params)
}

// GetMerchantApplication fetches a KYC application
func (i *IdentityMind) GetMerchantApplication(applicationID string) (interface{}, error) {
	return i.apiClient.GetMerchantApplication(applicationID)
}

// ListMerchantApplicationDocuments retrieves a list of documents attached to a KYC application
func (i *IdentityMind) ListMerchantApplicationDocuments(applicationID string) (interface{}, error) {
	return i.apiClient.ListMerchantApplicationDocuments(applicationID)
}

// DownloadMerchantApplicationDocument retrieves a specific document attached to a KYC application
func (i *IdentityMind) DownloadMerchantApplicationDocument(applicationID, documentID string) (interface{}, error) {
	return i.apiClient.DownloadMerchantApplicationDocument(applicationID, documentID)
}

// ProvideApplicationResponse provides a response to a KYC application `prompt
func (i *IdentityMind) ProvideApplicationResponse(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.ProvideApplicationResponse(applicationID, params)
}

// Merchant KYB

// RejectMerchantBusinessApplication see https://edoc.identitymind.com/reference#feedback_1
func (i *IdentityMind) RejectMerchantBusinessApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.RejectMerchantBusinessApplication(applicationID, params)
}

// GetMerchantBusinessApplication see https://edoc.identitymind.com/reference#getmerchantkyc
func (i *IdentityMind) GetMerchantBusinessApplication(applicationID string) (interface{}, error) {
	return i.GetMerchantBusinessApplication(applicationID)
}

// ReevaluateMerchantBusinessApplication see https://edoc.identitymind.com/reference#reevaluatemerchant
func (i *IdentityMind) ReevaluateMerchantBusinessApplication(applicationID string) (interface{}, error) {
	return i.GetMerchantBusinessApplication(applicationID)
}

// SubmitMerchantBusinessApplication see https://edoc.identitymind.com/reference#merchant
func (i *IdentityMind) SubmitMerchantBusinessApplication(params map[string]interface{}) (interface{}, error) {
	return i.SubmitMerchantBusinessApplication(params)
}

// ListMerchantBusinessApplicationDocuments see https://edoc.identitymind.com/reference#getfilelistforapplicationformerchant
func (i *IdentityMind) ListMerchantBusinessApplicationDocuments(applicationID string) (interface{}, error) {
	return i.ListMerchantBusinessApplicationDocuments(applicationID)
}

// DownloadMerchantBusinessApplicationDocument see https://edoc.identitymind.com/reference#reevaluatemerchant
func (i *IdentityMind) DownloadMerchantBusinessApplicationDocument(applicationID, documentID string) (interface{}, error) {
	return i.DownloadMerchantBusinessApplicationDocument(applicationID, documentID)
}

// UploadMerchantBusinessApplicationDocument see https://edoc.identitymind.com/reference#processfileuploadrequestformerchantkyc
func (i *IdentityMind) UploadMerchantBusinessApplicationDocument(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.UploadMerchantBusinessApplicationDocument(applicationID, params)
}

// UploadMerchantBusinessApplicationDocumentVerificationImage see https://edoc.identitymind.com/reference#processfileuploadrequestformerchantkyc
func (i *IdentityMind) UploadMerchantBusinessApplicationDocumentVerificationImage(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.UploadMerchantBusinessApplicationDocumentVerificationImage(applicationID, params)
}

// ApproveMerchantBusinessApplication see https://edoc.identitymind.com/reference#feedback_1
func (i *IdentityMind) ApproveMerchantBusinessApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.ApproveMerchantBusinessApplication(applicationID, params)
}

// UndecideMerchantBusinessApplication marks the consumer KYC application undecided
func (i *IdentityMind) UndecideMerchantBusinessApplication(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.UndecideMerchantBusinessApplication(applicationID, params)
}

// ProvideMerchantApplicationResponse provides a response to a merchant KYC application prompt
func (i *IdentityMind) ProvideMerchantApplicationResponse(applicationID string, params map[string]interface{}) (interface{}, error) {
	return i.apiClient.ProvideMerchantApplicationResponse(applicationID, params)
}

// Merchant Transactions

// EvaluateMerchantFraud evaluates payment fraud on behalf of a merchant
func (i *IdentityMind) EvaluateMerchantFraud(merchantID string, params map[string]interface{}) (interface{}, error) {
	return i.EvaluateMerchantFraud(merchantID, params)
}

// ReportMerchantTransaction reports a transaction on behalf of a merchant
func (i *IdentityMind) ReportMerchantTransaction(merchantID, txType string, params map[string]interface{}) (interface{}, error) {
	return i.ReportMerchantTransaction(merchantID, txType, params)
}
