package user

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	natsutil "github.com/kthomas/go-natsutil"
	"github.com/nats-io/nats.go"
	"github.com/provideplatform/ident/common"
	"github.com/provideplatform/ident/token"
)

const defaultNatsStream = "ident"

const natsDispatchInvitationSubject = "ident.invitation.dispatch"
const natsDispatchInvitationMaxInFlight = 2048
const dispatchInvitationAckWait = time.Second * 30

func init() {
	if !common.ConsumeNATSStreamingSubscriptions {
		common.Log.Debug("user package consumer configured to skip NATS streaming subscription setup")
		return
	}

	natsutil.EstablishSharedNatsConnection(nil)
	natsutil.NatsCreateStream(defaultNatsStream, []string{
		fmt.Sprintf("%s.*", defaultNatsStream),
	})

	var waitGroup sync.WaitGroup

	createNatsDispatchInvitationSubscriptions(&waitGroup)
}

func createNatsDispatchInvitationSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		_, err := natsutil.RequireNatsJetstreamSubscription(wg,
			dispatchInvitationAckWait,
			natsDispatchInvitationSubject,
			natsDispatchInvitationSubject,
			consumeDispatchInvitationSubscriptionsMsg,
			dispatchInvitationAckWait,
			natsDispatchInvitationMaxInFlight,
			nil,
		)

		if err != nil {
			common.Log.Panicf("failed to subscribe to NATS stream via subject: %s; %s", natsDispatchInvitationSubject, err.Error())
		}
	}
}

func consumeDispatchInvitationSubscriptionsMsg(msg *nats.Msg) {
	common.Log.Debugf("consuming %d-byte NATS invitation dispatch message on subject: %s", len(msg.Data), msg.Subject)

	var params map[string]interface{}

	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to umarshal invitation dispatch message; %s", err.Error())
		msg.Nak()
		return
	}

	rawToken, rawTokenOk := params["token"].(string)
	if !rawTokenOk {
		common.Log.Warningf("failed to umarshal token during invitation dispatch message; %s", err.Error())
		msg.Nak()
		return
	}

	token, err := token.Parse(rawToken)
	if err != nil {
		common.Log.Warningf("failed to parse token during attempted invitation dispatch; %s", err.Error())
		msg.Nak()
		return
	}

	common.Log.Debugf("dispatch invitation: %s", *token.Token)
	msg.Ack()
}
