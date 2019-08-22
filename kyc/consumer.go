package kyc

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	identitymind "github.com/kthomas/identitymind-golang"
	stan "github.com/nats-io/stan.go"
	"github.com/provideapp/ident/common"
)

const natsCheckKYCApplicationStatusSubject = "ident.kyc.status"
const natsCheckKYCApplicationStatusMaxInFlight = 2048
const checkKYCApplicationStatusAckWait = time.Minute * 10

const natsSubmitKYCApplicationSubject = "ident.kyc.submit"
const natsSubmitKYCApplicationMaxInFlight = 2048
const submitKYCApplicationAckWait = time.Minute * 1

var instantKYCEnabled = strings.ToLower(os.Getenv("INSTANT_KYC")) == "true"

func init() {
	var waitGroup sync.WaitGroup

	createNatsCheckKYCApplicationStatusSubscriptions(&waitGroup)
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

func consumeSubmitKYCApplicationMsg(msg *stan.Msg) {
	common.Log.Debugf("Consuming %d-byte NATS KYC application submit message on subject: %s", msg.Size(), msg.Subject)

	var params map[string]interface{}

	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("Failed to umarshal KYC application submit message; %s", err.Error())
		natsutil.Nack(common.SharedNatsConnection, msg)
		return
	}

	kycApplicationID, kycApplicationIDOk := params["kyc_application_id"].(string)
	if !kycApplicationIDOk {
		common.Log.Warningf("Failed to unmarshal kyc_application_id during NATS %v message handling", msg.Subject)
		natsutil.Nack(common.SharedNatsConnection, msg)
		return
	}

	db := dbconf.DatabaseConnection()

	kycApplication := &KYCApplication{}
	db.Where("id = ?", kycApplicationID).Find(&kycApplication)

	if kycApplication == nil || kycApplication.ID == uuid.Nil {
		common.Log.Warningf("Failed to find KYC application for id: %s", kycApplicationID)
		natsutil.Nack(common.SharedNatsConnection, msg)
		return
	}

	err = kycApplication.submit(db)
	if err != nil {
		common.Log.Warningf("Failed to submit KYC application %s during NATS %v message handling; %s", kycApplication.ID, msg.Subject, err.Error())
		natsutil.Nack(common.SharedNatsConnection, msg)
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
		natsutil.Nack(common.SharedNatsConnection, msg)
		return
	}

	kycApplicationID, kycApplicationIDOk := params["kyc_application_id"].(string)
	if !kycApplicationIDOk {
		common.Log.Warningf("Failed to unmarshal kyc_application_id during NATS %v message handling", msg.Subject)
		natsutil.Nack(common.SharedNatsConnection, msg)
		return
	}

	db := dbconf.DatabaseConnection()

	kycApplication := &KYCApplication{}
	db.Where("id = ?", kycApplicationID).Find(&kycApplication)

	if kycApplication == nil || kycApplication.ID == uuid.Nil {
		common.Log.Warningf("Failed to find KYC application for id: %s", kycApplicationID)
		natsutil.Nack(common.SharedNatsConnection, msg)
		return
	}

	application, err := kycApplication.enrich()
	if err != nil {
		common.Log.Warningf("Failed to enrich KYC application with using KYC provider API; %s", err.Error())
		natsutil.Nack(common.SharedNatsConnection, msg)
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
			natsutil.Nack(common.SharedNatsConnection, msg)
			return
		}
	default:
		common.Log.Warningf("Unable to complete status check for KYC application: %s; unsupported KYC provider: %s", kycApplication.ID, *kycApplication.Provider)
		natsutil.Nack(common.SharedNatsConnection, msg)
		return
	}

	if kycApplication.hasReachedDecision() || instantKYCEnabled {
		common.Log.Debugf("KYC application decision has been reached; status '%s' for KYC application %s", *kycApplication.Status, kycApplication.ID)
		msg.Ack()
	}
}