package application

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/nats-io/nats.go"
	"github.com/ockam-network/did"
	"github.com/provideplatform/ident/common"
)

const defaultNatsStream = "ident"

const natsApplicationImplicitKeyExchangeInitSubject = "ident.application.keys.exchange.init"
const natsApplicationImplicitKeyExchangeMaxInFlight = 2048
const natsApplicationImplicitKeyExchangeInitAckWait = time.Second * 5
const natsApplicationImplicitKeyExchangeInitMaxDeliveries = 10

const natsOrganizationUpdatedSubject = "ident.organization.updated"
const natsOrganizationUpdatedMaxInFlight = 2048
const natsOrganizationUpdatedAckWait = time.Second * 5
const natsOrganizationUpdatedMaxDeliveries = 10

func init() {
	if !common.ConsumeNATSStreamingSubscriptions {
		common.Log.Debug("application package consumer configured to skip NATS streaming subscription setup")
		return
	}

	natsutil.EstablishSharedNatsConnection(nil)
	natsutil.NatsCreateStream(defaultNatsStream, []string{
		fmt.Sprintf("%s.>", defaultNatsStream),
	})

	var waitGroup sync.WaitGroup

	createNatsApplicationImplicitKeyExchangeSubscriptions(&waitGroup)
	createNatsApplicationOrganizationUpdatedSubscriptions(&waitGroup)
}

func createNatsApplicationImplicitKeyExchangeSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		_, err := natsutil.RequireNatsJetstreamSubscription(wg,
			natsApplicationImplicitKeyExchangeInitAckWait,
			natsApplicationImplicitKeyExchangeInitSubject,
			natsApplicationImplicitKeyExchangeInitSubject,
			natsApplicationImplicitKeyExchangeInitSubject,
			consumeApplicationImplicitKeyExchangeInitMsg,
			natsApplicationImplicitKeyExchangeInitAckWait,
			natsApplicationImplicitKeyExchangeMaxInFlight,
			natsApplicationImplicitKeyExchangeInitMaxDeliveries,
			nil,
		)

		if err != nil {
			common.Log.Panicf("failed to subscribe to NATS stream via subject: %s; %s", natsApplicationImplicitKeyExchangeInitSubject, err.Error())
		}
	}
}

func createNatsApplicationOrganizationUpdatedSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		_, err := natsutil.RequireNatsJetstreamSubscription(wg,
			natsOrganizationUpdatedAckWait,
			natsOrganizationUpdatedSubject,
			natsOrganizationUpdatedSubject,
			natsOrganizationUpdatedSubject,
			consumeApplicationOrganizationUpdatedMsg,
			natsOrganizationUpdatedAckWait,
			natsOrganizationUpdatedMaxInFlight,
			natsOrganizationUpdatedMaxDeliveries,
			nil,
		)

		if err != nil {
			common.Log.Panicf("failed to subscribe to NATS stream via subject: %s; %s", natsOrganizationUpdatedSubject, err.Error())
		}
	}
}

func consumeApplicationImplicitKeyExchangeInitMsg(msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			msg.Nak()
		}
	}()

	common.Log.Debugf("consuming %d-byte NATS application implicit key exchange message on subject: %s", len(msg.Data), msg.Subject)

	params := map[string]interface{}{}
	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to unmarshal organization implicit key exchange message; %s", err.Error())
		msg.Nak()
		return
	}

	applicationID, applicationIDOk := params["application_id"].(string)
	if !applicationIDOk {
		common.Log.Warning("failed to parse application_id during application implicit key exchange message handler")
		msg.Nak()
		return
	}

	organizationID, organizationIDOk := params["organization_id"].(string)
	if !organizationIDOk {
		common.Log.Warning("failed to parse organization_id during application implicit key exchange message handler")
		msg.Nak()
		return
	}
	_, err = did.Parse(organizationID)
	// orgUUID, err := uuid.FromString(organizationID)
	if err != nil {
		common.Log.Warning("failed to parse organization_id during application implicit key exchange message handler")
		msg.Nak()
		return
	}

	app := &Application{}

	db := dbconf.DatabaseConnection()
	db.Where("id = ?", applicationID).Find(&app)

	if app == nil || app.ID == uuid.Nil {
		common.Log.Warningf("failed to resolve application during application implicit key exchange message handler; organization id: %s", applicationID)
		msg.Nak()
		return
	}

	err = app.initImplicitDiffieHellmanKeyExchange(db, organizationID)
	if err == nil {
		msg.Ack()
	} else {
		common.Log.Warningf("failed to initialize implicit Diffie-Hellman key exchange between app organizations; app id: %s; organization id: %s; %s", applicationID, organizationID, err.Error())
		msg.Nak()
	}
}

func consumeApplicationOrganizationUpdatedMsg(msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			msg.Nak()
		}
	}()

	common.Log.Debugf("consuming %d-byte NATS application organization updated message on subject: %s", len(msg.Data), msg.Subject)

	params := map[string]interface{}{}
	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to unmarshal organization updated message; %s", err.Error())
		msg.Nak()
		return
	}

	organizationID, organizationIDOk := params["organization_id"].(string)
	if !organizationIDOk {
		common.Log.Warning("failed to parse organization_id during organization updated message handler")
		msg.Nak()
		return
	}
	orgUUID, err := uuid.FromString(organizationID)
	if err != nil {
		common.Log.Warning("failed to parse organization_id during organization updated message handler")
		msg.Nak()
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
		natsutil.NatsJetstreamPublish(natsOrganizationRegistrationSubject, payload)
	}

	msg.Ack()
}
