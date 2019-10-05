package consumer

import (
	"encoding/json"
	"time"

	natsutil "github.com/kthomas/go-natsutil"
	provide "github.com/provideservices/provide-go"
)

const apiUsageDaemonBufferSize = 256
const apiUsageDaemonFlushInterval = 10000

const natsAPIUsageEventNotificationSubject = "api.usage.event"
const natsAPIUsageEventNotificationFlushTimeout = time.Second * 10

type apiUsageDelegate struct {
	// natsConnection *stan.Conn
}

// Track receives an API call from the API daemon's underlying buffered channel for local processing
func (d *apiUsageDelegate) Track(apiCall *provide.APICall) {
	// defer func() {
	// 	if r := recover(); r != nil {
	// 		common.Log.Debugf("Recovered from failed API call tracking attempt; %s\nAPI call: %v", r, apiCall)
	// 		// d.Track(apiCall)
	// 	}
	// }()

	payload, _ := json.Marshal(apiCall)
	natsutil.NatsPublishAsync(natsAPIUsageEventNotificationSubject, payload)
}

// func (d *apiUsageDelegate) initNatsStreamingConnection() {
// 	natsConnection, err := natsutil.GetNatsStreamingConnection(natsAPIUsageEventNotificationFlushTimeout, func(_ stan.Conn, err error) {
// 		d.initNatsStreamingConnection()
// 	})
// 	if err != nil {
// 		common.Log.Warningf("Failed to establish NATS connection for API usage delegate; %s", err.Error())
// 		return
// 	}
// 	d.natsConnection = natsConnection
// }

// RunAPIUsageDaemon runs the usage daemon
func RunAPIUsageDaemon() {
	delegate := new(apiUsageDelegate)
	// delegate.initNatsStreamingConnection()
	provide.RunAPIUsageDaemon(apiUsageDaemonBufferSize, apiUsageDaemonFlushInterval, delegate)
}
