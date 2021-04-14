package application

import (
	"encoding/json"
	"sync"
	"time"

	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	stan "github.com/nats-io/stan.go"
	"github.com/provideapp/ident/common"
)

const natsApplicationImplicitKeyExchangeInitSubject = "ident.application.keys.exchange.init"
const natsApplicationImplicitKeyExchangeMaxInFlight = 2048
const natsApplicationImplicitKeyExchangeInitAckWait = time.Second * 5
const applicationImplicitKeyExchangeInitTimeout = int64(time.Second * 20)

const natsOrganizationUpdatedSubject = "ident.organization.updated"
const natsOrganizationUpdatedMaxInFlight = 2048
const natsOrganizationUpdatedAckWait = time.Second * 5
const organizationUpdatedTimeout = int64(time.Second * 20)

func init() {
	if !common.ConsumeNATSStreamingSubscriptions {
		common.Log.Debug("application package consumer configured to skip NATS streaming subscription setup")
		return
	}

	natsutil.EstablishSharedNatsStreamingConnection(nil)

	var waitGroup sync.WaitGroup

	createNatsApplicationImplicitKeyExchangeSubscriptions(&waitGroup)
	createNatsApplicationOrganizationUpdatedSubscriptions(&waitGroup)
}

func createNatsApplicationImplicitKeyExchangeSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			natsApplicationImplicitKeyExchangeInitAckWait,
			natsApplicationImplicitKeyExchangeInitSubject,
			natsApplicationImplicitKeyExchangeInitSubject,
			consumeApplicationImplicitKeyExchangeInitMsg,
			natsApplicationImplicitKeyExchangeInitAckWait,
			natsApplicationImplicitKeyExchangeMaxInFlight,
			nil,
		)
	}
}

func createNatsApplicationOrganizationUpdatedSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			natsOrganizationUpdatedAckWait,
			natsOrganizationUpdatedSubject,
			natsOrganizationUpdatedSubject,
			consumeApplicationOrganizationUpdatedMsg,
			natsOrganizationUpdatedAckWait,
			natsOrganizationUpdatedMaxInFlight,
			nil,
		)
	}
}

func consumeApplicationImplicitKeyExchangeInitMsg(msg *stan.Msg) {
	defer func() {
		if r := recover(); r != nil {
			natsutil.AttemptNack(msg, applicationImplicitKeyExchangeInitTimeout)
		}
	}()

	common.Log.Debugf("consuming %d-byte NATS application implicit key exchange message on subject: %s", msg.Size(), msg.Subject)

	params := map[string]interface{}{}
	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to unmarshal organization implicit key exchange message; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	applicationID, applicationIDOk := params["application_id"].(string)
	if !applicationIDOk {
		common.Log.Warning("failed to parse application_id during application implicit key exchange message handler")
		natsutil.Nack(msg)
		return
	}

	organizationID, organizationIDOk := params["organization_id"].(string)
	if !organizationIDOk {
		common.Log.Warning("failed to parse organization_id during application implicit key exchange message handler")
		natsutil.Nack(msg)
		return
	}
	orgUUID, err := uuid.FromString(organizationID)
	if err != nil {
		common.Log.Warning("failed to parse organization_id during application implicit key exchange message handler")
		natsutil.Nack(msg)
		return
	}

	app := &Application{}

	db := dbconf.DatabaseConnection()
	db.Where("id = ?", applicationID).Find(&app)

	if app == nil || app.ID == uuid.Nil {
		common.Log.Warningf("failed to resolve application during application implicit key exchange message handler; organization id: %s", applicationID)
		natsutil.AttemptNack(msg, applicationImplicitKeyExchangeInitTimeout)
		return
	}

	err = app.initImplicitDiffieHellmanKeyExchange(db, orgUUID)
	if err == nil {
		msg.Ack()
	} else {
		common.Log.Warningf("failed to initialize implicit Diffie-Hellman key exchange between app organizations; app id: %s; organization id: %s; %s", applicationID, organizationID, err.Error())
		natsutil.AttemptNack(msg, applicationImplicitKeyExchangeInitTimeout)
	}
}

func consumeApplicationOrganizationUpdatedMsg(msg *stan.Msg) {
	defer func() {
		if r := recover(); r != nil {
			natsutil.AttemptNack(msg, organizationUpdatedTimeout)
		}
	}()

	common.Log.Debugf("consuming %d-byte NATS application organization updated message on subject: %s", msg.Size(), msg.Subject)

	params := map[string]interface{}{}
	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to unmarshal organization updated message; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	organizationID, organizationIDOk := params["organization_id"].(string)
	if !organizationIDOk {
		common.Log.Warning("failed to parse organization_id during organization updated message handler")
		natsutil.Nack(msg)
		return
	}
	orgUUID, err := uuid.FromString(organizationID)
	if err != nil {
		common.Log.Warning("failed to parse organization_id during organization updated message handler")
		natsutil.Nack(msg)
		return
	}

	apps := ApplicationsByOrganizationID(orgUUID, false)

	for _, app := range apps {
		common.Log.Debugf("dispatching async org registration update for application: %s; organization: %s", app.ID, orgUUID)
		payload, _ := json.Marshal(map[string]interface{}{
			"application_id":  app.ID.String(),
			"organization_id": orgUUID.String(),
			"update_registry": true,
		})
		natsutil.NatsStreamingPublish(natsOrganizationRegistrationSubject, payload)
	}

	msg.Ack()
}
