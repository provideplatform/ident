package user

import (
	"encoding/json"
	"sync"
	"time"

	natsutil "github.com/kthomas/go-natsutil"
	stan "github.com/nats-io/stan.go"
	"github.com/provideapp/ident/common"
	"github.com/provideapp/ident/token"
)

const natsDispatchInvitationSubject = "ident.invitation.dispatch"
const natsDispatchInvitationMaxInFlight = 2048
const dispatchInvitationAckWait = time.Second * 30
const natsDispatchInvitationTimeout = int64(time.Minute * 5)

func init() {
	if !common.ConsumeNATSStreamingSubscriptions {
		common.Log.Debug("user package consumer configured to skip NATS streaming subscription setup")
		return
	}

	var waitGroup sync.WaitGroup

	createNatsDispatchInvitationSubscriptions(&waitGroup)
}

func createNatsDispatchInvitationSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			dispatchInvitationAckWait,
			natsDispatchInvitationSubject,
			natsDispatchInvitationSubject,
			consumeDispatchInvitationSubscriptionsMsg,
			dispatchInvitationAckWait,
			natsDispatchInvitationMaxInFlight,
			nil,
		)
	}
}

func consumeDispatchInvitationSubscriptionsMsg(msg *stan.Msg) {
	common.Log.Debugf("consuming %d-byte NATS invitation dispatch message on subject: %s", msg.Size(), msg.Subject)

	var params map[string]interface{}

	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to umarshal invitation dispatch message; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	rawToken, rawTokenOk := params["token"].(string)
	if !rawTokenOk {
		common.Log.Warningf("failed to umarshal token during invitation dispatch message; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	token, err := token.Parse(rawToken)
	if err != nil {
		common.Log.Warningf("failed to parse token during attempted invitation dispatch; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	common.Log.Debugf("dispatch invitation: %s", *token.Token)
	msg.Ack()
}
