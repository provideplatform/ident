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

const natsSubmitKYCApplicationSubject = "ident.kyc.submit"
const natsSubmitKYCApplicationMaxInFlight = 2048
const submitKYCApplicationAckWait = time.Minute * 1

var instantKYCEnabled = strings.ToLower(os.Getenv("INSTANT_KYC")) == "true"

func init() {
	natsConnection := getNatsStreamingConnection()
	if natsConnection == nil {
		return
	}

	var waitGroup sync.WaitGroup

	createNatsCheckKYCApplicationStatusSubscriptions(natsConnection, &waitGroup)
	createNatsSubmitKYCApplicationSubscriptions(natsConnection, &waitGroup)
}

func createNatsSubmitKYCApplicationSubscriptions(natsConnection stan.Conn, wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		wg.Add(1)
		go func() {
			defer natsConnection.Close()

			kycSubscription, err := natsConnection.QueueSubscribe(natsSubmitKYCApplicationSubject, natsSubmitKYCApplicationSubject, consumeSubmitKYCApplicationMsg, stan.SetManualAckMode(), stan.AckWait(submitKYCApplicationAckWait), stan.MaxInflight(natsSubmitKYCApplicationMaxInFlight), stan.DurableName(natsSubmitKYCApplicationSubject))
			if err != nil {
				log.Warningf("Failed to subscribe to NATS subject: %s", natsSubmitKYCApplicationSubject)
				wg.Done()
				return
			}
			defer kycSubscription.Unsubscribe()
			log.Debugf("Subscribed to NATS subject: %s", natsSubmitKYCApplicationSubject)

			wg.Wait()
		}()
	}
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
		msg.Ack()
	}
}
