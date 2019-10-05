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

type apiUsageDelegate struct{}

// Track receives an API call from the API daemon's underlying buffered channel for local processing
func (d *apiUsageDelegate) Track(apiCall *provide.APICall) {
	payload, _ := json.Marshal(apiCall)
	natsutil.NatsPublishAsync(natsAPIUsageEventNotificationSubject, payload)
}

// RunAPIUsageDaemon runs the usage daemon
func RunAPIUsageDaemon() {
	delegate := new(apiUsageDelegate)
	provide.RunAPIUsageDaemon(apiUsageDaemonBufferSize, apiUsageDaemonFlushInterval, delegate)
}
