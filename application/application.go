package application

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	"github.com/kthomas/go-pgputil"
	redisutil "github.com/kthomas/go-redisutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/ident/common"
	"github.com/provideapp/ident/organization"
	"github.com/provideapp/ident/token"
	"github.com/provideapp/ident/user"
	provide "github.com/provideservices/provide-go"
)

const applicationResourceKey = "application"
const natsSiaApplicationNotificationSubject = "sia.application.notification"

// Application model which is initially owned by the user who created it
type Application struct {
	provide.Model
	NetworkID       uuid.UUID        `sql:"type:uuid not null" json:"network_id,omitempty"`
	UserID          uuid.UUID        `sql:"type:uuid not null" json:"user_id,omitempty"` // this is the user that initially created the app
	Name            *string          `sql:"not null" json:"name"`
	Description     *string          `json:"description"`
	Status          *string          `sql:"-" json:"status,omitempty"` // this is for enrichment purposes only
	Type            *string          `json:"type"`
	Config          *json.RawMessage `sql:"type:json" json:"config"`
	EncryptedConfig *string          `sql:"type:bytea" json:"-"`
	Hidden          bool             `sql:"not null;default:false" json:"hidden"` // soft-delete mechanism

	Organizations []*organization.Organization `gorm:"many2many:applications_organizations" json:"-"`
	Users         []*user.User                 `gorm:"many2many:applications_users" json:"-"` // not to be confused with `User.ApplicationID`
}

// CreateResponse model
type CreateResponse struct {
	Application *Application `json:"application"`
	Token       *token.Token `json:"token"`
}

// ApplicationsByUserID returns a list of applications which have been created
// by the given user id
func ApplicationsByUserID(userID *uuid.UUID, hidden bool) []Application {
	db := dbconf.DatabaseConnection()
	var apps []Application
	db.Where("user_id = ? AND hidden = ?", userID.String(), hidden).Find(&apps)
	return apps
}

// OrganizationsListQuery returns a db query which joins the organization applications and returns the query for pagination
func (app *Application) OrganizationsListQuery(db *gorm.DB) *gorm.DB {
	query := db.Select("organizations.id, organizations.created_at, organizations.user_id, organizations.name, organizations.description, ao.permissions as permissions")
	query = query.Joins("JOIN applications_organizations as ao ON ao.organization_id = organizations.id")
	return query.Where("ao.application_id = ?", app.ID).Order("organizations.name desc")
}

// UsersListQuery returns a db query which joins the application users and returns the query for pagination
func (app *Application) UsersListQuery(db *gorm.DB) *gorm.DB {
	query := db.Select("users.id, users.created_at, users.first_name, users.last_name, au.permissions as permissions")
	query = query.Joins("JOIN applications_users as au ON au.user_id = users.id").Where("au.application_id = ?", app.ID)
	return query
}

// DecryptedConfig returns the decrypted application config
func (app *Application) DecryptedConfig() (map[string]interface{}, error) {
	decryptedParams := map[string]interface{}{}
	if app.EncryptedConfig != nil {
		encryptedConfigJSON, err := pgputil.PGPPubDecrypt([]byte(*app.EncryptedConfig))
		if err != nil {
			common.Log.Warningf("Failed to decrypt encrypted application config; %s", err.Error())
			return decryptedParams, err
		}

		err = json.Unmarshal(encryptedConfigJSON, &decryptedParams)
		if err != nil {
			common.Log.Warningf("Failed to unmarshal decrypted application config; %s", err.Error())
			return decryptedParams, err
		}
	}
	return decryptedParams, nil
}

func (app *Application) encryptConfig() bool {
	if app.EncryptedConfig != nil {
		encryptedConfig, err := pgputil.PGPPubEncrypt([]byte(*app.EncryptedConfig))
		if err != nil {
			common.Log.Warningf("Failed to encrypt application config; %s", err.Error())
			app.Errors = append(app.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
			return false
		}
		app.EncryptedConfig = common.StringOrNil(string(encryptedConfig))
	}
	return true
}

func (app *Application) mergedConfig() map[string]interface{} {
	cfg := app.ParseConfig()
	encryptedConfig, err := app.DecryptedConfig()
	if err != nil {
		encryptedConfig = map[string]interface{}{}
	}

	for k := range encryptedConfig {
		cfg[k] = encryptedConfig[k]
	}
	return cfg
}

func (app *Application) setConfig(cfg map[string]interface{}) {
	cfgJSON, _ := json.Marshal(cfg)
	_cfgJSON := json.RawMessage(cfgJSON)
	app.Config = &_cfgJSON
}

func (app *Application) setEncryptedConfig(cfg map[string]interface{}) {
	cfgJSON, _ := json.Marshal(cfg)
	_cfgJSON := string(json.RawMessage(cfgJSON))
	app.EncryptedConfig = &_cfgJSON
	app.encryptConfig()
}

func (app *Application) sanitizeConfig() {
	cfg := app.ParseConfig()

	encryptedConfig, err := app.DecryptedConfig()
	if err != nil {
		encryptedConfig = map[string]interface{}{}
	}

	if webhookSecret, webhookSecretOk := cfg["webhook_secret"].(string); webhookSecretOk {
		encryptedConfig["webhook_secret"] = webhookSecret
		delete(cfg, "webhook_secret")
	} else {
		webhookSecretUUID, _ := uuid.NewV4()
		encryptedConfig["webhook_secret"] = strings.Replace(webhookSecretUUID.String(), "-", "", -1)
	}

	app.setConfig(cfg)
	app.setEncryptedConfig(encryptedConfig)
}

// pendingInvitations returns the pending invitations for the application; these are ephemeral, in-memory only
func (app *Application) pendingInvitations() []*user.Invite {
	var invitations []*user.Invite

	key := fmt.Sprintf("application.%s.invitations", app.ID.String())
	rawinvites, err := redisutil.Get(key)
	if err != nil {
		common.Log.Debugf("failed to retrieve cached application invitations from key: %s; %s", key, err.Error())
		return invitations
	}

	json.Unmarshal([]byte(*rawinvites), &invitations)
	return invitations
}

func (app *Application) addOrganization(tx *gorm.DB, org organization.Organization, permissions common.Permission) bool {
	var db *gorm.DB
	if tx != nil {
		db = tx
	} else {
		db = dbconf.DatabaseConnection()
	}

	common.Log.Debugf("adding organization %s to application: %s", org.ID, app.ID)
	result := db.Exec("INSERT INTO applications_organizations (application_id, organization_id, permissions) VALUES (?, ?, ?)", app.ID, org.ID, permissions)
	success := result.RowsAffected == 1
	if success {
		common.Log.Debugf("added organization %s to application: %s", org.ID, app.ID)
	} else {
		common.Log.Warningf("failed to add organization %s to application: %s", org.ID, app.ID)
	}
	return success
}

func (app *Application) removeOrganization(tx *gorm.DB, org organization.Organization) bool {
	var db *gorm.DB
	if tx != nil {
		db = tx
	} else {
		db = dbconf.DatabaseConnection()
	}

	common.Log.Debugf("removing organization %s from application: %s", org.ID, app.ID)
	result := db.Exec("DELETE FROM applications_organizations WHERE application_id = ? AND organization_id = ?", app.ID, org.ID)
	success := result.RowsAffected == 1
	if success {
		common.Log.Debugf("removed organization %s from application: %s", org.ID, app.ID)
	} else {
		common.Log.Warningf("failed to remove organization %s from application: %s", org.ID, app.ID)
	}
	return success
}

func (app *Application) updateOrganization(tx *gorm.DB, org organization.Organization, permissions common.Permission) bool {
	var db *gorm.DB
	if tx != nil {
		db = tx
	} else {
		db = dbconf.DatabaseConnection()
	}

	common.Log.Debugf("updating organization %s for application: %s", org.ID, app.ID)
	result := db.Exec("UPDATE applications_organizations SET permissions = ? WHERE application_id = ? AND organization_id = ?", permissions, app.ID, org.ID)
	success := result.RowsAffected == 1
	if success {
		common.Log.Debugf("updated organization %s for application: %s", org.ID, app.ID)
	} else {
		common.Log.Warningf("failed to update organization %s for application: %s", org.ID, app.ID)
	}
	return success
}

func (app *Application) addUser(tx *gorm.DB, usr user.User, permissions common.Permission) bool {
	var db *gorm.DB
	if tx != nil {
		db = tx
	} else {
		db = dbconf.DatabaseConnection()
	}

	common.Log.Debugf("adding user %s to application: %s", usr.ID, app.ID)
	result := db.Exec("INSERT INTO applications_users (application_id, user_id, permissions) VALUES (?, ?, ?)", app.ID, usr.ID, permissions)
	success := result.RowsAffected == 1
	if success {
		common.Log.Debugf("added user %s to application: %s", usr.ID, app.ID)
	} else {
		common.Log.Warningf("failed to add user %s to application: %s", usr.ID, app.ID)
	}
	return success
}

func (app *Application) removeUser(tx *gorm.DB, usr user.User) bool {
	var db *gorm.DB
	if tx != nil {
		db = tx
	} else {
		db = dbconf.DatabaseConnection()
	}

	common.Log.Debugf("removing user %s from application: %s", usr.ID, app.ID)
	result := db.Exec("DELETE FROM applications_users WHERE application_id = ? AND user_id = ?", app.ID, usr.ID)
	success := result.RowsAffected == 1
	if success {
		common.Log.Debugf("removed user %s from application: %s", usr.ID, app.ID)
	} else {
		common.Log.Warningf("failed to remove user %s from application: %s", usr.ID, app.ID)
	}
	return success
}

func (app *Application) updateUser(tx *gorm.DB, usr user.User, permissions common.Permission) bool {
	var db *gorm.DB
	if tx != nil {
		db = tx
	} else {
		db = dbconf.DatabaseConnection()
	}

	common.Log.Debugf("updating user %s for application: %s", usr.ID, app.ID)
	result := db.Exec("UPDATE applications_users SET permissions = ? WHERE application_id = ? AND user_id = ?", permissions, app.ID, usr.ID)
	success := result.RowsAffected == 1
	if success {
		common.Log.Debugf("updated user %s for application: %s", usr.ID, app.ID)
	} else {
		common.Log.Warningf("failed to update user %s for application: %s", usr.ID, app.ID)
	}
	return success
}

// Create and persist an application
func (app *Application) Create(tx *gorm.DB) (*CreateResponse, error) {
	var db *gorm.DB
	if tx != nil {
		db = tx
	} else {
		db = dbconf.DatabaseConnection()
		db = db.Begin()
		defer db.RollbackUnlessCommitted()
	}

	if !app.validate() {
		return nil, errors.New(*app.Errors[0].Message)
	}

	app.sanitizeConfig()

	if db.NewRecord(app) {
		result := db.Create(&app)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				app.Errors = append(app.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}

		if !db.NewRecord(app) {
			success := rowsAffected > 0
			if success {
				tkn, err := token.VendApplicationToken(db, &app.ID, nil, nil, nil)
				if err != nil {
					return nil, err
				}

				usr := user.Find(&app.UserID)
				if usr != nil && app.addUser(db, *usr, common.DefaultApplicationResourcePermission) {
					db.Commit()
				}

				payload, _ := json.Marshal(app)
				natsutil.NatsPublish(natsSiaApplicationNotificationSubject, payload)

				return &CreateResponse{
					Application: app,
					Token:       tkn,
				}, nil
			}
		}
	}

	return nil, errors.New("failed to create application")
}

// Validate an application for persistence
func (app *Application) validate() bool {
	app.Errors = make([]*provide.Error, 0)
	return len(app.Errors) == 0
}

// Update an existing application
func (app *Application) Update() bool {
	db := dbconf.DatabaseConnection()

	if !app.validate() {
		return false
	}

	app.sanitizeConfig()

	result := db.Save(&app)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			app.Errors = append(app.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}

	return len(app.Errors) == 0
}

// Delete an application
func (app *Application) Delete() bool {
	db := dbconf.DatabaseConnection()
	result := db.Delete(app)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			app.Errors = append(app.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}
	return len(app.Errors) == 0
}

// ParseConfig - parse the Application JSON configuration
func (app *Application) ParseConfig() map[string]interface{} {
	cfg := map[string]interface{}{}
	if app.Config != nil {
		err := json.Unmarshal(*app.Config, &cfg)
		if err != nil {
			common.Log.Warningf("Failed to unmarshal application params; %s", err.Error())
			return nil
		}
	}
	return cfg
}
