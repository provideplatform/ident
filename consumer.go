package main

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/kthomas/go-natsutil"
	"github.com/nats-io/go-nats-streaming"
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
	waitGroup sync.WaitGroup
)

type apiUsageDelegate struct{}

func (d *apiUsageDelegate) Track(apiCall *provide.APICall) {
	payload, _ := json.Marshal(apiCall)
	natsConnection := getNatsStreamingConnection()
	natsConnection.Publish(natsAPIUsageEventNotificationSubject, payload)
}

func runAPIUsageDaemon() {
	delegate := new(apiUsageDelegate)
	provide.RunAPIUsageDaemon(apiUsageDaemonBufferSize, apiUsageDaemonFlushInterval, delegate)
}

func getNatsStreamingConnection() stan.Conn {
	conn := natsutil.GetNatsStreamingConnection(func(_ stan.Conn, reason error) {
		subscribeNatsStreaming()
	})
	if conn == nil {
		return nil
	}
	return *conn
}

func subscribeNatsStreaming() {
	natsConnection := getNatsStreamingConnection()
	if natsConnection == nil {
		return
	}

	// no-op
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
		natsConn := getNatsStreamingConnection()
		natsutil.Nack(&natsConn, msg)
	} else {
		log.Debugf("nack() attempted but given NATS message has not yet been redelivered on subject: %s", msg.Subject)
	}
}

// shouldDeadletter determines if a given message should be deadlettered
func shouldDeadletter(msg *stan.Msg, deadletterTimeout int64) bool {
	return msg.Redelivered && time.Now().Unix()-msg.Timestamp >= deadletterTimeout
}
