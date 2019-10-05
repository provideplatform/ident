package sia

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	stan "github.com/nats-io/stan.go"
	"github.com/provideapp/ident/common"
	"github.com/provideservices/provide-go"
)

const defaultTimeZoneID = "Etc/UTC"

const natsSiaUserNotificationSubject = "sia.user.notification"
const natsSiaUserNotificationMaxInFlight = 1024
const siaUserNotificationAckWait = time.Second * 15
const siaUserNotificationTimeout = int64(time.Minute * 5)

const natsSiaApplicationNotificationSubject = "sia.application.notification"
const natsSiaApplicationNotificationMaxInFlight = 1024
const siaApplicationNotificationAckWait = time.Second * 15
const siaApplicationNotificationTimeout = int64(time.Minute * 5)

const natsSiaAPIUsageEventSubject = "api.usage.event"
const natsSiaAPIUsageEventMaxInFlight = 2048
const siaAPIUsageEventAckWait = time.Second * 30
const natsSiaAPIUsageEventTimeout = int64(time.Minute * 5)

type siaAPICall struct {
	SiaModel
	provide.APICall

	AccountID     *uint `json:"account_id"`
	ApplicationID *uint `json:"application_id"`

	Hash *string `gorm:"column:sha256" json:"sha256"`
	Raw  []byte  `json:"raw"`
}

func (siaAPICall) TableName() string {
	return "api_calls"
}

type siaAccount struct {
	SiaModel
	Name          *string    `json:"name"`
	Email         *string    `gorm:"-" json:"email"`
	ApplicationID *uuid.UUID `gorm:"column:prvd_application_id" json:"prvd_application_id"`
	UserID        *uuid.UUID `gorm:"column:prvd_user_id" json:"prvd_user_id"`
}

func (siaAccount) TableName() string {
	return "accounts"
}

type siaContact struct {
	SiaModel
	Name            *string `json:"name"`
	Email           *string `json:"email"`
	ContactableID   *uint   `json:"contactable_id"`
	ContactableType *string `json:"contactable_type"`
	TimeZoneID      *string `json:"time_zone_id"`
}

func (siaContact) TableName() string {
	return "contacts"
}

type siaApplication struct {
	SiaModel
	Name          *string    `json:"name"`
	AccountID     *uint      `json:"account_id"`
	ApplicationID *uuid.UUID `gorm:"column:prvd_application_id" json:"prvd_application_id"`
	UserID        *uuid.UUID `gorm:"column:prvd_user_id" json:"prvd_user_id"`
}

func (siaApplication) TableName() string {
	return "applications"
}

// SiaModel is only exported to workaround a bug in the gorm library
type SiaModel struct {
	ID     uint             `gorm:"primary_key"`
	Errors []*provide.Error `sql:"-" json:"-"`
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
	common.Log.Debugf("Consuming %d-byte NATS sia user notification message on subject: %s", msg.Size(), msg.Subject)

	var params map[string]interface{}

	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("Failed to umarshal sia user notification event message; %s", err.Error())
		natsutil.Nack(&common.SharedNatsConnection, msg)
		return
	}

	siaDB := siaDatabaseConnection()
	tx := siaDB.Begin()
	defer tx.RollbackUnlessCommitted()

	userUUID, err := uuid.FromString(params["id"].(string))
	account := &siaAccount{
		Name:   common.StringOrNil(params["name"].(string)),
		Email:  common.StringOrNil(params["email"].(string)),
		UserID: &userUUID,
	}

	applicationUUID, err := uuid.FromString(params["application_id"].(string))
	if err == nil {
		account.ApplicationID = &applicationUUID
	}

	// save account
	result := tx.Create(&account)
	rowsAffected := result.RowsAffected
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			common.Log.Warningf("Failed to insert sia account; %s", err.Error())
		}
	}
	if rowsAffected == 0 {
		common.Log.Warning("Failed to persist sia account")
		natsConnection, _ := common.GetSharedNatsStreamingConnection()
		natsutil.AttemptNack(&natsConnection, msg, siaApplicationNotificationTimeout)
		return
	}
	// end save account

	// save contact
	contact := &siaContact{
		Name:            account.Name,
		Email:           account.Email,
		TimeZoneID:      common.StringOrNil(defaultTimeZoneID),
		ContactableID:   &account.ID,
		ContactableType: common.StringOrNil("Account"),
	}
	result = tx.Create(&contact)
	rowsAffected = result.RowsAffected
	errors = result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			common.Log.Warningf("Failed to insert sia account contact; %s", err.Error())
		}
	}
	if rowsAffected == 0 {
		common.Log.Warning("Failed to persist sia account contact")
		natsConnection, _ := common.GetSharedNatsStreamingConnection()
		natsutil.AttemptNack(&natsConnection, msg, siaApplicationNotificationTimeout)
		return
	}
	// end save contact

	tx.Commit()

	common.Log.Debugf("Sia user notification message handled for user: %s", account.UserID)
	msg.Ack()
}

func consumeSiaApplicationNotificationMsg(msg *stan.Msg) {
	common.Log.Debugf("Consuming %d-byte NATS sia application notification message on subject: %s", msg.Size(), msg.Subject)

	var params map[string]interface{}

	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("Failed to umarshal sia application notification event message; %s", err.Error())
		natsutil.Nack(&common.SharedNatsConnection, msg)
		return
	}

	siaDB := siaDatabaseConnection()

	application := &siaApplication{
		Name: common.StringOrNil(params["name"].(string)),
	}

	applicationUUID, err := uuid.FromString(params["id"].(string))
	application.ApplicationID = &applicationUUID

	userUUID, err := uuid.FromString(params["user_id"].(string))
	application.UserID = &userUUID

	account := &siaAccount{}
	common.Log.Debugf("Resolving application owner's account from sia db for user: %s; application id: %s", application.UserID, application.ApplicationID)
	siaDB.Where("prvd_user_id = ?", application.UserID).Find(&account)
	if account == nil || account.ID == 0 {
		common.Log.Warningf("Failed to resolve application owner's account from sia db for user: %s; application id: %s", application.UserID, application.ApplicationID)
		natsConnection, _ := common.GetSharedNatsStreamingConnection()
		natsutil.AttemptNack(&natsConnection, msg, siaApplicationNotificationTimeout)
		return
	}
	application.AccountID = &account.ID

	result := siaDB.Create(&application)
	rowsAffected := result.RowsAffected
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			common.Log.Warningf("Failed to insert sia application; %s", err.Error())
		}
	}
	if rowsAffected == 0 {
		common.Log.Warning("Failed to persist sia application")
		natsConnection, _ := common.GetSharedNatsStreamingConnection()
		natsutil.AttemptNack(&natsConnection, msg, siaApplicationNotificationTimeout)
		return
	}

	common.Log.Debugf("Sia application notification message handled for application: %s", application.ApplicationID)
	msg.Ack()
}

func consumeSiaAPIUsageEventsMsg(msg *stan.Msg) {
	common.Log.Debugf("Consuming %d-byte NATS sia API usage event message on subject: %s", msg.Size(), msg.Subject)

	var params map[string]interface{}

	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("Failed to umarshal sia API usage event message; %s", err.Error())
		natsutil.Nack(&common.SharedNatsConnection, msg)
		return
	}

	siaDB := siaDatabaseConnection()

	apiCallDigest := sha256.New()
	apiCallDigest.Write(msg.Data)
	hash := hex.EncodeToString(apiCallDigest.Sum(nil))

	apiCall := &siaAPICall{}
	siaDB.Where("sha256 = ?", hash).Find(&apiCall)
	if apiCall != nil && apiCall.ID != 0 { // FIXME- use int?
		common.Log.Warningf("API call event exists for hash: %s", hash)
		msg.Ack()
		return
	}

	err = json.Unmarshal(msg.Data, &apiCall)
	if err != nil {
		common.Log.Warningf("Failed to unmarshal API call event; %s", err.Error())
		natsConnection, _ := common.GetSharedNatsStreamingConnection()
		natsutil.AttemptNack(&natsConnection, msg, natsSiaAPIUsageEventTimeout)
		return
	}

	apiCall.Hash = common.StringOrNil(hash)
	apiCall.Raw = msg.Data

	subjectParts := strings.Split(params["sub"].(string), ":")
	isApplicationSub := subjectParts[0] == "application"
	isUserSub := subjectParts[0] == "user"

	account := &siaAccount{} // responsible billing account
	var resolverErr error

	resolveApplication := func(applicationUUID uuid.UUID) error {
		var resolveApplicationErr error
		common.Log.Debugf("Resolving responsible account from sia db for application: %s", applicationUUID)
		application := &siaApplication{}
		siaDB.Where("prvd_application_id = ?", applicationUUID).Find(&application)
		if application != nil && application.ID != 0 && application.UserID != nil && *application.UserID != uuid.Nil {
			apiCall.ApplicationID = &application.ID
			common.Log.Debugf("Resolving responsible application owner's account from sia db for user: %s; application id: %s", application.UserID, application.ApplicationID)
			siaDB.Where("prvd_user_id = ?", application.UserID).Find(&account)
		} else if application != nil && application.ID != 0 {
			resolveApplicationErr = fmt.Errorf("Failed to resolve responsible application owner's account from sia db for user: %s; application id: %s", application.UserID, application.ApplicationID)
		} else {
			resolveApplicationErr = fmt.Errorf("Failed to resolve responsible application: %s", applicationUUID)
		}
		return resolveApplicationErr
	}

	if isApplicationSub {
		applicationID := subjectParts[1]
		applicationUUID, err := uuid.FromString(applicationID)
		if err != nil {
			resolverErr = fmt.Errorf("Failed to resolve responsible application; %s", err.Error())
		} else {
			resolverErr = resolveApplication(applicationUUID)
		}
	} else if isUserSub {
		userID := subjectParts[1]
		userUUID, err := uuid.FromString(userID)
		if err == nil {
			common.Log.Debugf("Resolving responsible account from sia db for user: %s", userUUID)
			siaDB.Where("prvd_user_id = ?", userUUID).Find(&account)

			if account != nil && account.ApplicationID != nil && *account.ApplicationID != uuid.Nil {
				resolverErr = resolveApplication(*account.ApplicationID)
			}
		}
	}

	if account == nil || account.ID == 0 {
		resolverErr = fmt.Errorf("Failed to resolve responsible account for API call event: %s", *apiCall.Hash)
	}

	if resolverErr != nil {
		common.Log.Warningf("Failed to persist API call event: %s; %s", *apiCall.Hash, resolverErr.Error())
		natsConnection, _ := common.GetSharedNatsStreamingConnection()
		natsutil.AttemptNack(&natsConnection, msg, natsSiaAPIUsageEventTimeout)
		return
	}

	apiCall.AccountID = &account.ID
	common.Log.Debugf("Resolved responsible account %d for API call event: %s", *apiCall.AccountID, *apiCall.Hash)

	result := siaDB.Create(&apiCall)
	rowsAffected := result.RowsAffected
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			common.Log.Warningf("Failed to insert API call event: %s; %s", hash, err.Error())
		}
	}
	if rowsAffected == 0 {
		common.Log.Warning("Failed to persist API call event")
		natsConnection, _ := common.GetSharedNatsStreamingConnection()
		natsutil.AttemptNack(&natsConnection, msg, natsSiaAPIUsageEventTimeout)
		return
	}

	common.Log.Debugf("sia API call event persisted: %s", hash)
	msg.Ack()
}
