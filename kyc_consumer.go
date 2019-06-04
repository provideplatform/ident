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
	stan "github.com/nats-io/go-nats-streaming"
)

const natsCheckKYCApplicationStatusSubject = "ident.kyc.status"
const natsCheckKYCApplicationStatusMaxInFlight = 2048
const checkKYCApplicationStatusAckWait = time.Minute * 10

var instantKYCEnabled = strings.ToLower(os.Getenv("INSTANT_KYC")) == "true"

func init() {
	natsConnection := getNatsStreamingConnection()
	if natsConnection == nil {
		return
	}

	var waitGroup sync.WaitGroup

	createNatsCheckKYCApplicationStatusSubscriptions(natsConnection, &waitGroup)
}

func createNatsCheckKYCApplicationStatusSubscriptions(natsConnection stan.Conn, wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		wg.Add(1)
		go func() {
			defer natsConnection.Close()

			kycSubscription, err := natsConnection.QueueSubscribe(natsCheckKYCApplicationStatusSubject, natsCheckKYCApplicationStatusSubject, consumeCheckKYCApplicationStatusMsg, stan.SetManualAckMode(), stan.AckWait(checkKYCApplicationStatusAckWait), stan.MaxInflight(natsCheckKYCApplicationStatusMaxInFlight), stan.DurableName(natsCheckKYCApplicationStatusSubject))
			if err != nil {
				log.Warningf("Failed to subscribe to NATS subject: %s", natsCheckKYCApplicationStatusSubject)
				wg.Done()
				return
			}
			defer kycSubscription.Unsubscribe()
			log.Debugf("Subscribed to NATS subject: %s", natsCheckKYCApplicationStatusSubject)

			wg.Wait()
		}()
	}
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

	if kycApplication.isAccepted() || kycApplication.isRejected() {
		log.Debugf("KYC application status has been finalized; not attempting to update KYC verification status for id: %s", kycApplication.ID)
		msg.Ack()
		return
	}

	apiClient, err := kycApplication.KYCAPIClient()
	if err != nil {
		log.Warningf("Failed to resolve KYC provider for KYC application %s during NATS %v message handling", kycApplication.ID, msg.Subject)
		nack(msg)
		return
	}

	if kycApplication.Identifier == nil {
		log.Warningf("Failed to resolve KYC application %s during NATS %v message handling", kycApplication.ID, msg.Subject)
		nack(msg)
		return
	}

	application, err := apiClient.GetApplication(*kycApplication.Identifier)
	if err != nil {
		log.Warningf("Failed to fetch account from KYC provider; %s", err.Error())
		nack(msg)
		return
	}

	switch application.(type) {
	case *identitymind.KYCApplication:
		identitymindApplication := application.(*identitymind.KYCApplication)
		if identitymindApplication.State != nil {
			log.Debugf("Resolved identitymind KYC application status to '%s' for KYC application: %s; will attempt to redeliver %s message", *identitymindApplication.State, kycApplication.ID, msg.Subject)
			if identitymindApplication.IsAccepted() {
				kycApplication.updateStatus(db, kycApplicationStatusAccepted)
			} else if identitymindApplication.IsRejected() {
				kycApplication.updateStatus(db, kycApplicationStatusRejected)
			} else if identitymindApplication.IsUnderReview() {
				kycApplication.updateStatus(db, kycApplicationStatusUnderReview)
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
		db.Save(&kycApplication)
		msg.Ack()
	}
}
