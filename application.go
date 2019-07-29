package main

import (
	"encoding/json"
	"fmt"

	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideservices/provide-go"
)

func init() {
	db := dbconf.DatabaseConnection()

	db.AutoMigrate(&Application{})
	db.Model(&Application{}).AddIndex("idx_applications_hidden", "hidden")
	db.Model(&Application{}).AddIndex("idx_applications_network_id", "network_id")
	db.Model(&Application{}).AddForeignKey("user_id", "users(id)", "SET NULL", "CASCADE")
	db.Model(&User{}).AddForeignKey("application_id", "applications(id)", "SET NULL", "CASCADE")

	// FIXME-- remove this

	appIDs := []string{"6d422d32-4639-4958-b8ee-4680adaeaba0", "e2b4ce1b-7efa-4b97-a296-8f7c0594fc83", "024888b4-f85d-4075-97e7-d2d248cc02cb", "5c03a2c8-747f-4a95-8615-7a5e512b2c51", "0c5f0f71-1d8b-476b-81da-96d04e3ae79f", "abfbfab7-9432-4e0b-9e7b-b0fea318ee16", "42ba3834-d605-4696-a5cf-0850c8983524", "6d4e3107-b82d-4415-9c0a-1d571d3e92df", "b02d00bc-5892-4bbc-8da9-b6d97fd67174", "b99bc6de-b84b-442c-8d79-6bb10b77318d", "82cbf4d3-d9e1-4ba2-83de-3ea918e57820", "b43a5c70-7ac1-4428-b79a-7ad80f5eace9", "fa5248ad-344d-41d0-bcf3-05588bd9a842", "982e11ad-c63e-4fb5-af82-bf725686ae9c", "c9009baa-1e4e-45cc-b5e8-59f7db277ac6", "0555170d-a960-414a-84d2-479c62aabe3e", "5048bb4b-c853-4141-aad3-261cd5640ec5", "63cc5873-e86d-4fb5-9201-f76197057335", "bbc3b502-1285-44ac-8f28-8f0378eb9010", "3bdc37eb-2fc6-485e-8394-e50429e9a9b1", "0d408e63-a031-4bad-9234-3e1d1a7ad137", "c4dd138b-07fe-4f48-9b5f-3d0c3d171929", "4f88be8c-8844-46f4-ba2c-b413e1ae8213", "6f989df2-e46b-4a81-9743-a8c1301ab7df", "6c48cd68-1fcb-4f5f-8189-c0e3fdc45e9b", "74680972-ccda-4cd7-9809-ccdfdb7c297e", "593bc003-67c7-4a11-8adf-4d84c1c6cfb6", "e5961e9e-2483-4df2-a57d-1d30d92b6133", "11058e34-d6c5-49ff-9af5-af27452a7e8f", "3bc7751e-85dd-48ab-829b-de14dba8ac6c", "0cd28a4a-a43f-49fe-a726-0c6a45853627", "2fdb8812-3884-4ce2-9ef1-4a8a2d1924f5", "5ea8ba7c-3474-401a-869f-a22f81448021", "9548a1e9-287a-49c1-9ef3-cbf48368bdc1", "cbeff275-a214-4819-8c46-34f5fac70c82", "283178f2-0fe0-4b14-be20-dae0920c1704", "96204845-34aa-475b-b2aa-9b20acb818f4", "55d6c5e8-4ca9-4d68-8739-5c1d6977d28a", "a641e14f-65aa-49a1-a85f-a052dd9ec42f", "744e4a70-4e64-4deb-b141-6686a045a5a7", "2c766bd3-1b2d-4aab-8b45-4f452ae5d084", "938d9d95-7d52-4ba4-b280-6e60c633651b", "5040eeef-7abd-403b-b6fa-1d099aaffa44", "f2446877-3633-44b8-9e58-5a1eac32d603", "fb037146-73d8-4f04-994c-b3a832907cb9", "bbb2bc4e-c904-4603-a2b5-b4f5097893c6", "0b1b550b-1dc5-4988-bae7-36c1742c86a2", "48d64c91-5349-49d2-b413-b69d7c448e36", "d798436f-fc16-4168-8466-330bd31b0f1c", "21d2a178-47cb-4022-b738-680d7923d12a", "98de4cf4-946e-4557-aaed-d24aa282cb71", "f63e0eb6-cb6b-4fc1-9b40-d04a6dc43604", "adac22e5-fd36-4571-9f36-166e709a5e48", "04ada3bb-3d9b-4501-8453-06b975aeebcf", "14fece45-cf89-4a14-a1da-fbfd494daf63", "2dd146b3-2812-46ee-8e8e-6f9be1ffdf27"}
	for _, appID := range appIDs {
		app := &Application{}
		db.Where("id = ?", appID).Find(&app)
		if app != nil && app.ID != uuid.Nil {
			payload, _ := json.Marshal(app)
			NATSPublish(natsSiaApplicationNotificationSubject, payload)
		}
	}
}

// Application model which is initially owned by the user who created it
type Application struct {
	provide.Model
	NetworkID   uuid.UUID        `sql:"type:uuid not null" json:"network_id"`
	UserID      uuid.UUID        `sql:"type:uuid not null" json:"user_id"`
	Name        *string          `sql:"not null" json:"name"`
	Description *string          `json:"description"`
	Config      *json.RawMessage `sql:"type:json" json:"config"`
	Hidden      bool             `sql:"not null;default:false" json:"hidden"` // soft-delete mechanism
}

// Create and persist an application
func (app *Application) Create() bool {
	db := DatabaseConnection()

	if !app.Validate() {
		return false
	}

	if db.NewRecord(app) {
		result := db.Create(&app)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				app.Errors = append(app.Errors, &provide.Error{
					Message: stringOrNil(err.Error()),
				})
			}
		}
		if !db.NewRecord(app) {
			success := rowsAffected > 0
			if success {
				payload, _ := json.Marshal(app)
				NATSPublish(natsSiaApplicationNotificationSubject, payload)
			}
			return success
		}
	}
	return false
}

// CreateToken creates a new token on behalf of the application
func (app *Application) CreateToken() (*Token, error) {
	token := &Token{
		ApplicationID: &app.ID,
	}
	if !token.Create() {
		if len(token.Errors) > 0 {
			return nil, fmt.Errorf("Failed to create token for application: %s; %s", app.ID.String(), *token.Errors[0].Message)
		}
	}
	return token, nil
}

// Validate an application for persistence
func (app *Application) Validate() bool {
	app.Errors = make([]*provide.Error, 0)
	return len(app.Errors) == 0
}

// Update an existing application
func (app *Application) Update() bool {
	db := DatabaseConnection()

	if !app.Validate() {
		return false
	}

	result := db.Save(&app)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			app.Errors = append(app.Errors, &provide.Error{
				Message: stringOrNil(err.Error()),
			})
		}
	}

	return len(app.Errors) == 0
}

// Delete an application
func (app *Application) Delete() bool {
	db := DatabaseConnection()
	result := db.Delete(app)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			app.Errors = append(app.Errors, &provide.Error{
				Message: stringOrNil(err.Error()),
			})
		}
	}
	return len(app.Errors) == 0
}

// GetTokens - retrieve the tokens associated with the application
func (app *Application) GetTokens() []*Token {
	var tokens []*Token
	DatabaseConnection().Where("application_id = ?", app.ID).Find(&tokens)
	return tokens
}

// ParseConfig - parse the Application JSON configuration
func (app *Application) ParseConfig() map[string]interface{} {
	cfg := map[string]interface{}{}
	if app.Config != nil {
		err := json.Unmarshal(*app.Config, &cfg)
		if err != nil {
			log.Warningf("Failed to unmarshal application params; %s", err.Error())
			return nil
		}
	}
	return cfg
}
