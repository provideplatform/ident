package main

import (
	"encoding/json"
	"sync"

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
