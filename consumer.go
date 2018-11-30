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
const natsAPIUsageEventNotificationSubject = "api-usage-event"
const natsAPIUsageEventNotificationMaxInFlight = 32
const natsSiaUserNotificationConsumerConcurrency = 4
const natsSiaUserNotificationMaxInFlight = 32
const natsSiaUserNotificationSubject = "sia-user-notification"

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

	createNatsSiaUserNotificationSubscriptions(natsConnection)
}

func createNatsSiaUserNotificationSubscriptions(natsConnection stan.Conn) {
	for i := uint64(0); i < natsSiaUserNotificationConsumerConcurrency; i++ {
		waitGroup.Add(1)
		go func() {
			defer natsConnection.Close()

			siaUserNotificationSubscription, err := natsConnection.QueueSubscribe(natsSiaUserNotificationSubject, natsSiaUserNotificationSubject, consumeSiaUserNotificationMsg, stan.SetManualAckMode(), stan.AckWait(time.Millisecond*10000), stan.MaxInflight(natsSiaUserNotificationMaxInFlight), stan.DurableName(natsSiaUserNotificationSubject))
			if err != nil {
				Log.Warningf("Failed to subscribe to NATS subject: %s", natsSiaUserNotificationSubject)
				waitGroup.Done()
				return
			}
			Log.Debugf("Subscribed to NATS subject: %s", natsSiaUserNotificationSubject)

			waitGroup.Wait()

			siaUserNotificationSubscription.Unsubscribe()
		}()
	}
}

func consumeSiaUserNotificationMsg(msg *stan.Msg) {
	Log.Debugf("Consuming NATS sia user notification message: %s", msg)
	var user *User

	err := json.Unmarshal(msg.Data, &user)
	if err != nil {
		Log.Warningf("Failed to umarshal user notification message; %s", err.Error())
		return
	}

	if siaAPIKey != "" {
		Log.Debugf("Attempting to notify sia about %s", *user.Email)
		CreateSiaAccount(siaAPIKey, map[string]interface{}{
			"prvd_user_id": user.ID,
			"name":         user.Name,
			"email":        user.Email,
		})
		msg.Ack()
	} else {
		Log.Warningf("No sia API key configured in the environment; notification about %s not being reported", *user.Email)
	}
}
