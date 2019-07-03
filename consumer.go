package main

import (
	"encoding/json"
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

type apiUsageDelegate struct {
	natsConnection *stan.Conn
}

// Track receives an API call from the API daemon's underlying buffered channel for local processing
func (d *apiUsageDelegate) Track(apiCall *provide.APICall) {
	payload, _ := json.Marshal(apiCall)
	if d != nil && d.natsConnection != nil {
		(*d.natsConnection).PublishAsync(natsAPIUsageEventNotificationSubject, payload, func(_ string, err error) {
			if err != nil {
				log.Warningf("Failed to asnychronously publish %s; %s", natsAPIUsageEventNotificationSubject, err.Error())
				d.initNatsStreamingConnection()
				defer d.Track(apiCall)
			}
		})
	} else {
		log.Warningf("Failed to asnychronously publish %s; no NATS streaming connection", natsAPIUsageEventNotificationSubject)
	}
}

func (d *apiUsageDelegate) initNatsStreamingConnection() {
	natsConnection, err := GetSharedNatsStreamingConnection()
	if err != nil {
		log.Warningf("Failed to resolve shared NATS connection for API usage delegate; %s", err.Error())
		return
	}
	d.natsConnection = natsConnection
}

// runAPIUsageDaemon runs the usage daemon
func runAPIUsageDaemon() {
	delegate := new(apiUsageDelegate)
	delegate.initNatsStreamingConnection()
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
		natsutil.Nack(SharedNatsConnection, msg)
	} else {
		log.Debugf("nack() attempted but given NATS message has not yet been redelivered on subject: %s", msg.Subject)
	}
}

// shouldDeadletter determines if a given message should be deadlettered
func shouldDeadletter(msg *stan.Msg, deadletterTimeout int64) bool {
	return msg.Redelivered && time.Now().Unix()-msg.Timestamp >= deadletterTimeout
}
