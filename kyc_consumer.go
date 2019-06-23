package main

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
	log.Debugf("Consuming %d-byte NATS KYC application submit message on subject: %s", msg.Size(), msg.Subject)

	var params map[string]interface{}

	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		log.Warningf("Failed to umarshal KYC application submit message; %s", err.Error())
		nack(msg)
		return
	}

	kycApplicationID, kycApplicationIDOk := params["kyc_application_id"].(string)
	if !kycApplicationIDOk {
		log.Warningf("Failed to unmarshal kyc_application_id during NATS %v message handling", msg.Subject)
		nack(msg)
		return
	}

	db := dbconf.DatabaseConnection()

	kycApplication := &KYCApplication{}
	db.Where("id = ?", kycApplicationID).Find(&kycApplication)

	if kycApplication == nil || kycApplication.ID == uuid.Nil {
		log.Warningf("Failed to find KYC application for id: %s", kycApplicationID)
		nack(msg)
		return
	}

	err = kycApplication.submit(db)
	if err != nil {
		log.Warningf("Failed to submit KYC application %s during NATS %v message handling; %s", kycApplication.ID, msg.Subject, err.Error())
		nack(msg)
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

	log.Debugf("KYC application submitted: %s", kycApplication.ID)
	msg.Ack()
}

func consumeCheckKYCApplicationStatusMsg(msg *stan.Msg) {
	log.Debugf("Consuming %d-byte NATS KYC application status message on subject: %s", msg.Size(), msg.Subject)

	var params map[string]interface{}

	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		log.Warningf("Failed to umarshal KYC application status message; %s", err.Error())
		nack(msg)
		return
	}

	kycApplicationID, kycApplicationIDOk := params["kyc_application_id"].(string)
	if !kycApplicationIDOk {
		log.Warningf("Failed to unmarshal kyc_application_id during NATS %v message handling", msg.Subject)
		nack(msg)
		return
	}

	db := dbconf.DatabaseConnection()

	kycApplication := &KYCApplication{}
	db.Where("id = ?", kycApplicationID).Find(&kycApplication)

	if kycApplication == nil || kycApplication.ID == uuid.Nil {
		log.Warningf("Failed to find KYC application for id: %s", kycApplicationID)
		nack(msg)
		return
	}

	application, err := kycApplication.enrich()
	if err != nil {
		log.Warningf("Failed to enrich KYC application with using KYC provider API; %s", err.Error())
		nack(msg)
		return
	}

	switch application.(type) {
	case *identitymind.KYCApplication:
		identitymindApplication := application.(*identitymind.KYCApplication)
		if identitymindApplication.State != nil {
			log.Debugf("Resolved identitymind KYC application status to '%s' for KYC application: %s", *identitymindApplication.State, kycApplication.ID)
			if identitymindApplication.IsAccepted() {
				kycApplication.updateStatus(db, kycApplicationStatusAccepted, nil)
			} else if identitymindApplication.IsRejected() {
				kycApplication.updateStatus(db, kycApplicationStatusRejected, nil)
			} else if identitymindApplication.IsUnderReview() {
				kycApplication.updateStatus(db, kycApplicationStatusUnderReview, nil)
			}
		} else {
			log.Warningf("Identitymind KYC application does not contain a status for KYC application: %s", kycApplication.ID)
			nack(msg)
			return
		}
	default:
		log.Warningf("Unable to complete status check for KYC application: %s; unsupported KYC provider: %s", kycApplication.ID, *kycApplication.Provider)
		nack(msg)
		return
	}

	if kycApplication.hasReachedDecision() || instantKYCEnabled {
		log.Debugf("KYC application decision has been reached; status '%' for KYC application %s", *kycApplication.Status, kycApplication.ID)
		msg.Ack()
	}
}
