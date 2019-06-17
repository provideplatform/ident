package main

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/kthomas/go-natsutil"
	"github.com/nats-io/stan.go"
	provide "github.com/provideservices/provide-go"
)

const apiUsageDaemonBufferSize = 256
const apiUsageDaemonFlushInterval = 30000

const natsDefaultClusterID = "provide"
const natsAPIUsageEventNotificationSubject = "api.usage.event"
const natsAPIUsageEventNotificationMaxInFlight = 32
const natsSiaApplicationNotificationSubject = "sia.application.notification"
const natsSiaUserNotificationSubject = "sia.user.notification"

var (
	waitGroup              sync.WaitGroup
	consumerNatsConnection stan.Conn
)

type apiUsageDelegate struct {
	natsConnection stan.Conn
}

func init() {
	// FIXME -- handle errors
	consumerNatsConnection, _ = natsutil.GetNatsStreamingConnection(10*time.Second, nil)
}

func (d *apiUsageDelegate) Track(apiCall *provide.APICall) {
	payload, _ := json.Marshal(apiCall)
	d.natsConnection.Publish(natsAPIUsageEventNotificationSubject, payload)
}

func runAPIUsageDaemon() {
	delegate := new(apiUsageDelegate)
	natsConnection, err := natsutil.GetNatsStreamingConnection(time.Second*30, nil)
	if err != nil {
		log.Warningf("Failed to establish NATS connection for API usage delegate; %s", err.Error())
	}
	delegate.natsConnection = natsConnection
	provide.RunAPIUsageDaemon(apiUsageDaemonBufferSize, apiUsageDaemonFlushInterval, delegate)
}

// attemptNack tries to Nack the given message if it meets basic time-based deadlettering
func attemptNack(msg *stan.Msg, timeout int64) {
	if shouldDeadletter(msg, timeout) {
		log.Debugf("Nacking redelivered %d-byte message after %dms timeout: %s", msg.Size(), timeout, msg.Subject)
		nack(msg)
	}
}

// nack the given message
func nack(msg *stan.Msg) {
	if msg.Redelivered {
		log.Warningf("Nacking redelivered %d-byte message without checking subject-specific deadletter business logic on subject: %s", msg.Size(), msg.Subject)
		natsutil.Nack(&consumerNatsConnection, msg)
	} else {
		log.Debugf("nack() attempted but given NATS message has not yet been redelivered on subject: %s", msg.Subject)
	}
}

// shouldDeadletter determines if a given message should be deadlettered
func shouldDeadletter(msg *stan.Msg, deadletterTimeout int64) bool {
	return msg.Redelivered && time.Now().Unix()-msg.Timestamp >= deadletterTimeout
}
