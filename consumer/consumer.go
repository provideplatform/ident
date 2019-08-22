package consumer

import (
	"encoding/json"
	"time"

	"github.com/kthomas/go-natsutil"
	"github.com/nats-io/stan.go"
	"github.com/provideapp/ident/common"
	provide "github.com/provideservices/provide-go"
)

const apiUsageDaemonBufferSize = 256
const apiUsageDaemonFlushInterval = 30000

const natsDefaultClusterID = "provide"
const natsAPIUsageEventNotificationSubject = "api.usage.event"
const natsAPIUsageEventNotificationMaxInFlight = 1024

type apiUsageDelegate struct {
	natsConnection *stan.Conn
}

// Track receives an API call from the API daemon's underlying buffered channel for local processing
func (d *apiUsageDelegate) Track(apiCall *provide.APICall) {
	payload, _ := json.Marshal(apiCall)
	if d != nil && d.natsConnection != nil {
		(*d.natsConnection).PublishAsync(natsAPIUsageEventNotificationSubject, payload, func(_ string, err error) {
			if err != nil {
				common.Log.Warningf("Failed to asnychronously publish %s; %s", natsAPIUsageEventNotificationSubject, err.Error())
				d.initNatsStreamingConnection()
				defer d.Track(apiCall)
			}
		})
	} else {
		common.Log.Warningf("Failed to asnychronously publish %s; no NATS streaming connection", natsAPIUsageEventNotificationSubject)
	}
}

func (d *apiUsageDelegate) initNatsStreamingConnection() {
	natsConnection, err := natsutil.GetNatsStreamingConnection(time.Second*10, func(_ stan.Conn, err error) {
		d.initNatsStreamingConnection()
	})
	if err != nil {
		common.Log.Warningf("Failed to establish NATS connection for API usage delegate; %s", err.Error())
		return
	}
	d.natsConnection = natsConnection
}

// RunAPIUsageDaemon runs the usage daemon
func RunAPIUsageDaemon() {
	delegate := new(apiUsageDelegate)
	delegate.initNatsStreamingConnection()
	provide.RunAPIUsageDaemon(apiUsageDaemonBufferSize, apiUsageDaemonFlushInterval, delegate)
}
