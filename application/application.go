package application

import (
	"encoding/json"
	"strings"

	dbconf "github.com/kthomas/go-db-config"
	"github.com/kthomas/go-pgputil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/ident/common"
	provide "github.com/provideservices/provide-go"
)

const natsSiaApplicationNotificationSubject = "sia.application.notification"

func init() {
	db := dbconf.DatabaseConnection()

	db.AutoMigrate(&Application{})
	db.Model(&Application{}).AddIndex("idx_applications_hidden", "hidden")
	db.Model(&Application{}).AddIndex("idx_applications_network_id", "network_id")
	db.Model(&Application{}).AddForeignKey("user_id", "users(id)", "SET NULL", "CASCADE")
}

// Application model which is initially owned by the user who created it
type Application struct {
	provide.Model
	NetworkID       uuid.UUID        `sql:"type:uuid not null" json:"network_id"`
	UserID          uuid.UUID        `sql:"type:uuid not null" json:"user_id"`
	Name            *string          `sql:"not null" json:"name"`
	Description     *string          `json:"description"`
	Config          *json.RawMessage `sql:"type:json" json:"config"`
	EncryptedConfig *string          `sql:"type:bytea" json:"-"`
	Hidden          bool             `sql:"not null;default:false" json:"hidden"` // soft-delete mechanism
}

// ApplicationsByUserID returns a list of applications which have been created
// by the given user id
func ApplicationsByUserID(userID *uuid.UUID, hidden bool) []Application {
	db := dbconf.DatabaseConnection()
	var apps []Application
	db.Where("user_id = ? AND hidden = ?", userID.String(), hidden).Find(&apps)
	return apps
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

// Create and persist an application
func (app *Application) Create() bool {
	db := dbconf.DatabaseConnection()

	if !app.Validate() {
		return false
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
				payload, _ := json.Marshal(app)
				common.NATSPublish(natsSiaApplicationNotificationSubject, payload)
			}
			return success
		}
	}
	return false
}

// Validate an application for persistence
func (app *Application) Validate() bool {
	app.Errors = make([]*provide.Error, 0)
	return len(app.Errors) == 0
}

// Update an existing application
func (app *Application) Update() bool {
	db := dbconf.DatabaseConnection()

	if !app.Validate() {
		return false
	}

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
