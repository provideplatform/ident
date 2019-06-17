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
				identNatsConnection.Publish(natsSiaApplicationNotificationSubject, payload)
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
