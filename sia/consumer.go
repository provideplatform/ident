package sia

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"

	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	stan "github.com/nats-io/stan.go"
	"github.com/provideapp/ident/common"
	"github.com/provideservices/provide-go"
)

const natsSiaUserNotificationSubject = "sia.user.notification"
const natsSiaUserNotificationMaxInFlight = 1024
const siaUserNotificationAckWait = time.Second * 15
const siaUserNotificationTimeout = int64(time.Minute * 5)

const natsSiaApplicationNotificationSubject = "sia.user.notification"
const natsSiaApplicationNotificationMaxInFlight = 1024
const siaApplicationNotificationAckWait = time.Second * 15
const siaApplicationNotificationTimeout = int64(time.Minute * 5)

const natsSiaAPIUsageEventSubject = "api.usage.event"
const natsSiaAPIUsageEventMaxInFlight = 2048
const siaAPIUsageEventAckWait = time.Second * 30
const natsSiaAPIUsageEventTimeout = int64(time.Minute * 5)

var instantKYCEnabled = strings.ToLower(os.Getenv("INSTANT_KYC")) == "true"

// db.Exec("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\";")

type siaAPICall struct {
	siaModel
	provide.APICall

	Hash          *string
	Raw           []byte
	ApplicationID *uuid.UUID
	UserID        *uuid.UUID
}

func (siaAPICall) TableName() string {
	return "api_calls"
}

type siaAccount struct {
	siaModel
	Name   *string    `json:"name"`
	Email  *string    `json:"email"`
	UserID *uuid.UUID `json:"prvd_user_id"`
}

func (siaAccount) TableName() string {
	return "accounts"
}

type siaApplication struct {
	siaModel
	Name          *string    `json:"name"`
	ApplicationID *uuid.UUID `json:"prvd_application_id"`
	UserID        *uuid.UUID `json:"prvd_user_id"`
}

func (siaApplication) TableName() string {
	return "applications"
}

type siaModel struct {
	ID        uuid.UUID        `json:"id"`
	CreatedAt time.Time        `json:"created_at,omitempty"`
	Errors    []*provide.Error `sql:"-" json:"-"`
}

func init() {
	var waitGroup sync.WaitGroup

	createNatsSiaUserNotificationSubscriptions(&waitGroup)
	createNatsSiaApplicationNotificationSubscriptions(&waitGroup)
	createNatsSiaAPIUsageEventsSubscriptions(&waitGroup)
}

func createNatsSiaUserNotificationSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			siaUserNotificationAckWait,
			natsSiaUserNotificationSubject,
			natsSiaUserNotificationSubject,
			consumeSiaUserNotificationMsg,
			siaUserNotificationAckWait,
			natsSiaUserNotificationMaxInFlight,
		)
	}
}

func createNatsSiaApplicationNotificationSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			siaApplicationNotificationAckWait,
			natsSiaApplicationNotificationSubject,
			natsSiaApplicationNotificationSubject,
			consumeSiaApplicationNotificationMsg,
			siaApplicationNotificationAckWait,
			natsSiaApplicationNotificationMaxInFlight,
		)
	}
}

func createNatsSiaAPIUsageEventsSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			siaAPIUsageEventAckWait,
			natsSiaAPIUsageEventSubject,
			natsSiaAPIUsageEventSubject,
			consumeSiaAPIUsageEventsMsg,
			siaAPIUsageEventAckWait,
			natsSiaAPIUsageEventMaxInFlight,
		)
	}
}

func consumeSiaUserNotificationMsg(msg *stan.Msg) {
	common.Log.Debugf("Consuming %d-byte NATS Sia user notification message on subject: %s", msg.Size(), msg.Subject)

	var params map[string]interface{}

	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("Failed to umarshal Sia user notification event message; %s", err.Error())
		natsutil.Nack(common.SharedNatsConnection, msg)
		return
	}

	siaDB := siaDatabaseConnection()

	account := &siaAccount{
		Name:  common.StringOrNil(params["name"].(string)),
		Email: common.StringOrNil(params["email"].(string)),
	}

	userUUID, err := uuid.FromString(params["id"].(string))
	if err == nil {
		account.UserID = &userUUID
	}

	result := siaDB.Save(&account)
	//rowsAffected := result.RowsAffected
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			common.Log.Warningf("Failed to insert sia account; %s", err.Error())
		}
	}
	if !siaDB.NewRecord(&account) {
		common.Log.Warningf("Failed to persist sia account; %s", err.Error())
		natsConnection, _ := common.GetSharedNatsStreamingConnection()
		natsutil.AttemptNack(natsConnection, msg, siaApplicationNotificationTimeout)
		return
	}

	common.Log.Debugf("Sia user notification message handled for user: %s", account.UserID)
	msg.Ack()
}

func consumeSiaApplicationNotificationMsg(msg *stan.Msg) {
	common.Log.Debugf("Consuming %d-byte NATS Sia application notification message on subject: %s", msg.Size(), msg.Subject)

	var params map[string]interface{}

	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("Failed to umarshal Sia application notification event message; %s", err.Error())
		natsutil.Nack(common.SharedNatsConnection, msg)
		return
	}

	siaDB := siaDatabaseConnection()

	application := &siaApplication{
		Name: common.StringOrNil(params["name"].(string)),
	}

	applicationUUID, err := uuid.FromString(params["id"].(string))
	if err == nil {
		application.ApplicationID = &applicationUUID
	}

	userUUID, err := uuid.FromString(params["user_id"].(string))
	if err == nil {
		application.UserID = &userUUID
	}

	result := siaDB.Save(&application)
	//rowsAffected := result.RowsAffected
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			common.Log.Warningf("Failed to insert sia application; %s", err.Error())
		}
	}
	if !siaDB.NewRecord(&application) {
		common.Log.Warningf("Failed to persist sia application; %s", err.Error())
		natsConnection, _ := common.GetSharedNatsStreamingConnection()
		natsutil.AttemptNack(natsConnection, msg, siaApplicationNotificationTimeout)
		return
	}

	common.Log.Debugf("Sia application notification message handled for application: %s", application.ID)
	msg.Ack()
}

func consumeSiaAPIUsageEventsMsg(msg *stan.Msg) {
	common.Log.Debugf("Consuming %d-byte NATS Sia API usage event message on subject: %s", msg.Size(), msg.Subject)

	var params map[string]interface{}

	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("Failed to umarshal Sia API usage event message; %s", err.Error())
		natsutil.Nack(common.SharedNatsConnection, msg)
		return
	}

	siaDB := siaDatabaseConnection()

	apiCallDigest := sha256.New()
	apiCallDigest.Write(msg.Data)
	hash := apiCallDigest.Sum(nil)

	apiCall := &siaAPICall{}
	siaDB.Where("sha256 = ?", hash).Find(&apiCall)
	if apiCall != nil && apiCall.ID != uuid.Nil { // FIXME- use int?
		common.Log.Warningf("API call event exists for hash: %s", string(hash))
		msg.Ack()
		return
	}

	err = json.Unmarshal(msg.Data, &apiCall)
	if err != nil {
		common.Log.Warningf("Failed to unmarshal API call event; %s", err.Error())
		natsConnection, _ := common.GetSharedNatsStreamingConnection()
		natsutil.AttemptNack(natsConnection, msg, natsSiaAPIUsageEventTimeout)
		return
	}

	apiCall.Hash = common.StringOrNil(string(hash))
	apiCall.Raw = msg.Data

	subjectParts := strings.Split(params["sub"].(string), ":")
	isApplicationSub := subjectParts[0] == "application"
	isUserSub := subjectParts[0] == "user"

	if isApplicationSub {
		applicationID := subjectParts[1]
		applicationUUID, err := uuid.FromString(applicationID)
		if err == nil {
			apiCall.ApplicationID = &applicationUUID
			common.Log.Debugf("Fetching application from siaDB: %s", applicationID)
			// TODO: query siaDB.applications where prvd_application_id = applicationID
			// TODO: query siaDB.accounts where prvd_user_id = application.prvd_user_id
		}
	}

	if isUserSub {
		userID := subjectParts[1]
		userUUID, err := uuid.FromString(userID)
		if err == nil {
			apiCall.UserID = &userUUID
			common.Log.Debugf("Fetching account from siaDB: %s", userID)
			// TODO: query siaDB.accounts where prvd_user_id = userID
		}
	}

	result := siaDB.Save(&apiCall)
	//rowsAffected := result.RowsAffected
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			common.Log.Warningf("Failed to insert API call event: %s; %s", string(hash), err.Error())
		}
	}
	if !siaDB.NewRecord(&apiCall) {
		common.Log.Warningf("Failed to persist API call event; %s", err.Error())
		natsConnection, _ := common.GetSharedNatsStreamingConnection()
		natsutil.AttemptNack(natsConnection, msg, natsSiaAPIUsageEventTimeout)
		return
	}

	msg.Ack()
}
