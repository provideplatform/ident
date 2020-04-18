package organization

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

const natsCreatedOrganizationCreatedSubject = "ident.organization.created"
const natsCreatedOrganizationCreatedMaxInFlight = 2048
const createOrganizationAckWait = time.Second * 5
const createOrganizationTimeout = int64(time.Second * 20)

const natsSiaOrganizationNotificationSubject = "sia.organization.notification"

func init() {
	if !common.ConsumeNATSStreamingSubscriptions {
		common.Log.Debug("organization package consumer configured to skip NATS streaming subscription setup")
		return
	}

	natsutil.EstablishSharedNatsStreamingConnection(nil)

	var waitGroup sync.WaitGroup

	createNatsOrganizationCreatedSubscriptions(&waitGroup)
}

func createNatsOrganizationCreatedSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			createOrganizationAckWait,
			natsCreatedOrganizationCreatedSubject,
			natsCreatedOrganizationCreatedSubject,
			consumeCreatedOrganizationMsg,
			createOrganizationAckWait,
			natsCreatedOrganizationCreatedMaxInFlight,
			nil,
		)
	}
}

func consumeCreatedOrganizationMsg(msg *stan.Msg) {
	defer func() {
		if r := recover(); r != nil {
			natsutil.AttemptNack(msg, createOrganizationTimeout)
		}
	}()

	common.Log.Debugf("consuming %d-byte NATS created organization message on subject: %s", msg.Size(), msg.Subject)

	params := map[string]interface{}{}
	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to unmarshal organization created message; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	organizationID, organizationIDOk := params["organization_id"].(string)
	if !organizationIDOk {
		common.Log.Warning("failed to unmarshal organization_id during created message handler")
		natsutil.Nack(msg)
		return
	}

	db := dbconf.DatabaseConnection()

	organization := &Organization{}
	db.Where("id = ?", organizationID).Find(&organization)

	if organization == nil || organization.ID == uuid.Nil {
		common.Log.Warningf("failed to resolve organization during created message handler; organization id: %s", organizationID)
		natsutil.Nack(msg)
		return
	}

	vault, err := organization.createVault(db)
	if err == nil {
		common.Log.Debugf("Created default vault for organization: %s", *organization.Name)
		msg.Ack()
	} else {
		common.Log.Warningf("Failed to create default vault for organization: %s; %s", *organization.Name, *vault.Errors[0].Message)
		natsutil.AttemptNack(msg, createOrganizationTimeout)
	}
}
