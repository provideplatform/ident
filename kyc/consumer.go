package kyc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"

	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	identitymind "github.com/kthomas/identitymind-golang"
	"github.com/kthomas/vouched-golang"
	stan "github.com/nats-io/stan.go"
	"github.com/provideapp/ident/common"
)

const natsCheckKYCApplicationStatusSubject = "ident.kyc.status"
const natsCheckKYCApplicationStatusMaxInFlight = 2048
const checkKYCApplicationStatusAckWait = time.Second * 30

const natsSubmitKYCApplicationSubject = "ident.kyc.submit"
const natsSubmitKYCApplicationMaxInFlight = 2048
const submitKYCApplicationAckWait = time.Minute * 1
const natsSubmitKYCApplicationTimeout = int64(time.Minute * 5)

const natsDispatchKYCApplicationWebhookSubject = "ident.kyc.webhook"
const natsDispatchKYCApplicationWebhookMaxInFlight = 2048
const dispatchKYCApplicationWebhookAckWait = time.Second * 30
const natsDispatchKYCApplicationWebhookTimeout = int64(time.Minute * 5)

var instantKYCEnabled = strings.ToLower(os.Getenv("INSTANT_KYC")) == "true"

func init() {
	var waitGroup sync.WaitGroup

	createNatsCheckKYCApplicationStatusSubscriptions(&waitGroup)
	createNatsDispatchKYCApplicationWebhookSubscriptions(&waitGroup)
	createNatsSubmitKYCApplicationSubscriptions(&waitGroup)
}

func createNatsSubmitKYCApplicationSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			submitKYCApplicationAckWait,
			natsSubmitKYCApplicationSubject,
			natsSubmitKYCApplicationSubject,
			consumeSubmitKYCApplicationMsg,
			submitKYCApplicationAckWait,
			natsSubmitKYCApplicationMaxInFlight,
		)
	}
}

func createNatsCheckKYCApplicationStatusSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			checkKYCApplicationStatusAckWait,
			natsCheckKYCApplicationStatusSubject,
			natsCheckKYCApplicationStatusSubject,
			consumeCheckKYCApplicationStatusMsg,
			checkKYCApplicationStatusAckWait,
			natsCheckKYCApplicationStatusMaxInFlight,
		)
	}
}

func createNatsDispatchKYCApplicationWebhookSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			dispatchKYCApplicationWebhookAckWait,
			natsDispatchKYCApplicationWebhookSubject,
			natsDispatchKYCApplicationWebhookSubject,
			consumeDispatchKYCApplicationWebhookMsg,
			dispatchKYCApplicationWebhookAckWait,
			natsDispatchKYCApplicationWebhookMaxInFlight,
		)
	}
}

func consumeSubmitKYCApplicationMsg(msg *stan.Msg) {
	common.Log.Debugf("Consuming %d-byte NATS KYC application submit message on subject: %s", msg.Size(), msg.Subject)

	var params map[string]interface{}

	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("Failed to umarshal KYC application submit message; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	kycApplicationID, kycApplicationIDOk := params["kyc_application_id"].(string)
	if !kycApplicationIDOk {
		common.Log.Warningf("Failed to unmarshal kyc_application_id during NATS %v message handling", msg.Subject)
		natsutil.Nack(msg)
		return
	}

	db := dbconf.DatabaseConnection()

	kycApplication := &KYCApplication{}
	db.Where("id = ?", kycApplicationID).Find(&kycApplication)

	if kycApplication == nil || kycApplication.ID == uuid.Nil {
		common.Log.Warningf("Failed to find KYC application for id: %s", kycApplicationID)
		natsutil.Nack(msg)
		return
	}

	err = kycApplication.submit(db)
	if err != nil {
		common.Log.Warningf("Failed to submit KYC application %s during NATS %v message handling; %s", kycApplication.ID, msg.Subject, err.Error())
		natsutil.AttemptNack(msg, natsSubmitKYCApplicationTimeout)
		return
	}

	status, statusOk := params["status"].(string)
	if statusOk {
		switch status {
		case kycApplicationStatusAccepted:
			kycApplication.accept(db)
		case kycApplicationStatusRejected:
			kycApplication.reject(db)
		case kycApplicationStatusUnderReview:
			kycApplication.undecide(db)
		default:
			// no-op
		}
	}

	common.Log.Debugf("KYC application submitted: %s", kycApplication.ID)
	msg.Ack()
}

func consumeCheckKYCApplicationStatusMsg(msg *stan.Msg) {
	common.Log.Debugf("Consuming %d-byte NATS KYC application status message on subject: %s", msg.Size(), msg.Subject)

	var params map[string]interface{}

	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("Failed to umarshal KYC application status message; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	kycApplicationID, kycApplicationIDOk := params["kyc_application_id"].(string)
	if !kycApplicationIDOk {
		common.Log.Warningf("Failed to unmarshal kyc_application_id during NATS %v message handling", msg.Subject)
		natsutil.Nack(msg)
		return
	}

	db := dbconf.DatabaseConnection()

	kycApplication := &KYCApplication{}
	db.Where("id = ?", kycApplicationID).Find(&kycApplication)

	if kycApplication == nil || kycApplication.ID == uuid.Nil {
		common.Log.Warningf("Failed to find KYC application for id: %s", kycApplicationID)
		natsutil.Nack(msg)
		return
	}

	application, err := kycApplication.enrich(db)
	if err != nil {
		common.Log.Warningf("Failed to enrich KYC application with using KYC provider API; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	switch application.(type) {
	case *identitymind.KYCApplication:
		identitymindApplication := application.(*identitymind.KYCApplication)
		if identitymindApplication.State != nil {
			common.Log.Debugf("Resolved identitymind KYC application status to '%s' for KYC application: %s", *identitymindApplication.State, kycApplication.ID)
			if identitymindApplication.IsAccepted() {
				kycApplication.updateStatus(db, kycApplicationStatusAccepted, nil)
			} else if identitymindApplication.IsRejected() {
				kycApplication.updateStatus(db, kycApplicationStatusRejected, nil)
			} else if identitymindApplication.IsUnderReview() {
				kycApplication.updateStatus(db, kycApplicationStatusUnderReview, nil)
			}
		} else {
			common.Log.Warningf("Identitymind KYC application does not contain a status for KYC application: %s", kycApplication.ID)
			natsutil.Nack(msg)
			return
		}
	case *vouched.KYCApplication:
		vouchedApplication := application.(*vouched.KYCApplication)
		if vouchedApplication.Status != nil {
			common.Log.Debugf("Resolved vouched KYC application status to '%s' for KYC application: %s", *vouchedApplication.Status, kycApplication.ID)
			if vouchedApplication.Result != nil && vouchedApplication.Result.ID != nil {
				piiDigest := sha256.New()
				piiDigest.Write([]byte(*vouchedApplication.Result.ID))
				hash := hex.EncodeToString(piiDigest.Sum(nil))
				kycApplication.PIIHash = &hash
				db.Save(&kycApplication)
				kycApplication.enrich(db)
			}

			if vouchedApplication.Status != nil && *vouchedApplication.Status == "completed" && kycApplication.requiresRemediation() {
				kycApplication.updateStatus(db, kycApplicationStatusUnderRemediate, nil)
			} else if vouchedApplication.IsAccepted() {
				kycApplication.updateStatus(db, kycApplicationStatusAccepted, nil)
			} else if vouchedApplication.IsRejected() {
				kycApplication.updateStatus(db, kycApplicationStatusRejected, nil)
			} else if vouchedApplication.IsUnderReview() {
				kycApplication.updateStatus(db, kycApplicationStatusUnderReview, nil)
			}
		} else {
			common.Log.Warningf("Vouched KYC application does not contain a status for KYC application: %s", kycApplication.ID)
			natsutil.Nack(msg)
			return
		}
	default:
		common.Log.Warningf("Unable to complete status check for KYC application: %s; unsupported KYC provider: %s", kycApplication.ID, *kycApplication.Provider)
		natsutil.Nack(msg)
		return
	}

	if kycApplication.hasReachedDecision() || instantKYCEnabled {
		common.Log.Debugf("KYC application decision has been reached; status '%s' for KYC application %s", *kycApplication.Status, kycApplication.ID)
		msg.Ack()
	}
}

func consumeDispatchKYCApplicationWebhookMsg(msg *stan.Msg) {
	common.Log.Debugf("Consuming %d-byte NATS KYC application webhook dispatch message on subject: %s", msg.Size(), msg.Subject)

	var params map[string]interface{}

	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("Failed to umarshal KYC application submit message; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	kycApplicationID, kycApplicationIDOk := params["kyc_application_id"].(string)
	if !kycApplicationIDOk {
		common.Log.Warningf("Failed to unmarshal kyc_application_id during NATS %v message handling", msg.Subject)
		natsutil.Nack(msg)
		return
	}

	db := dbconf.DatabaseConnection()

	kycApplication := &KYCApplication{}
	db.Where("id = ?", kycApplicationID).Find(&kycApplication)

	if kycApplication == nil || kycApplication.ID == uuid.Nil {
		common.Log.Warningf("Failed to find KYC application for id: %s", kycApplicationID)
		natsutil.Nack(msg)
		return
	}

	err = kycApplication.dispatchWebhookRequest(params)
	if err != nil {
		common.Log.Warningf("Failed to dispatch webhook notification for KYC application %s during NATS %v message handling; %s", kycApplication.ID, msg.Subject, err.Error())
		natsutil.AttemptNack(msg, natsDispatchKYCApplicationWebhookTimeout)
		return
	}

	common.Log.Debugf("Webhook notification dispatched for KYC application: %s", kycApplication.ID)
	msg.Ack()
}
