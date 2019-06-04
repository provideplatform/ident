package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/badoux/checkmail"
	"github.com/kthomas/go.uuid"
	provide "github.com/provideservices/provide-go"
	"golang.org/x/crypto/bcrypt"
)

// User model
type User struct {
	provide.Model
	ApplicationID          *uuid.UUID `sql:"type:uuid" json:"-"`
	Name                   *string    `sql:"not null" json:"name"`
	Email                  *string    `sql:"not null" json:"email"`
	Password               *string    `sql:"not null" json:"password"`
	PrivacyPolicyAgreedAt  *time.Time `json:"privacy_policy_agreed_at"`
	TermsOfServiceAgreedAt *time.Time `json:"terms_of_service_agreed_at"`
}

// UserResponse is preferred over writing an entire User instance as JSON
type UserResponse struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
}

// UserAuthenticationResponse is returned upon successful authentication using an email address
type UserAuthenticationResponse struct {
	User  *UserResponse  `json:"user"`
	Token *TokenResponse `json:"token"`
}

// AuthenticateUser attempts to authenticate by email address and password
func AuthenticateUser(email, password string, applicationID *uuid.UUID) (*UserAuthenticationResponse, error) {
	var user = &User{}
	db := DatabaseConnection()
	query := db.Where("email = ?", strings.ToLower(email))
	if applicationID != nil && *applicationID != uuid.Nil {
		query = query.Where("application_id = ?", applicationID)
	} else {
		query = query.Where("application_id IS NULL")
	}
	query.First(&user)
	if user != nil && user.ID != uuid.Nil {
		if !user.authenticate(password) {
			return nil, errors.New("authentication failed with given credentials")
		}
	} else {
		return nil, fmt.Errorf("invalid email")
	}
	token := &Token{
		UserID: &user.ID,
	}
	if !token.Create() {
		var err error
		if len(token.Errors) > 0 {
			err = fmt.Errorf("Failed to create token for authenticated user: %s; %s", *user.Email, *token.Errors[0].Message)
			log.Warningf(err.Error())
		}
		return &UserAuthenticationResponse{
			User:  user.AsResponse(),
			Token: nil,
		}, err
	}
	return &UserAuthenticationResponse{
		User:  user.AsResponse(),
		Token: token.AsResponse(),
	}, nil
}

func (u *User) authenticate(password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(*u.Password), []byte(password)) == nil
}

// Applications returns a list of applications which have been created by the user
func (u *User) Applications(hidden bool) []Application {
	db := DatabaseConnection()
	var apps []Application
	db.Where("user_id = ? AND hidden = ?", u.ID, hidden).Find(&apps)
	return apps
}

// Create and persist a user
func (u *User) Create() bool {
	db := DatabaseConnection()

	if !u.Validate() {
		return false
	}

	if db.NewRecord(u) {
		result := db.Create(&u)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				u.Errors = append(u.Errors, &provide.Error{
					Message: stringOrNil(err.Error()),
				})
			}
		}
		if !db.NewRecord(u) {
			success := rowsAffected > 0
			if success && (u.ApplicationID == nil || *u.ApplicationID == uuid.Nil) {
				payload, _ := json.Marshal(u)
				natsConnection := getNatsStreamingConnection()
				natsConnection.Publish(natsSiaUserNotificationSubject, payload)
			}
			return success
		}
	}
	return false
}

// Update an existing user
func (u *User) Update() bool {
	db := DatabaseConnection()

	if !u.Validate() {
		return false
	}

	result := db.Save(&u)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			u.Errors = append(u.Errors, &provide.Error{
				Message: stringOrNil(err.Error()),
			})
		}
	}

	return len(u.Errors) == 0
}

// Validate a user for persistence
func (u *User) Validate() bool {
	u.Errors = make([]*provide.Error, 0)
	db := DatabaseConnection()
	if db.NewRecord(u) {
		if u.Email != nil {
			u.Email = stringOrNil(strings.ToLower(*u.Email))
			err := checkmail.ValidateFormat(*u.Email)
			if err != nil {
				u.Errors = append(u.Errors, &provide.Error{
					Message: stringOrNil(fmt.Sprintf("invalid email address: %s; %s", *u.Email, err.Error())),
				})
			}
		}
		u.rehashPassword()
	}
	return len(u.Errors) == 0
}

func (u *User) rehashPassword() {
	if u.Password != nil {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*u.Password), bcrypt.DefaultCost)
		if err != nil {
			u.Password = nil
			u.Errors = append(u.Errors, &provide.Error{
				Message: stringOrNil(err.Error()),
			})
		} else {
			u.Password = stringOrNil(string(hashedPassword))
		}
	} else {
		u.Errors = append(u.Errors, &provide.Error{
			Message: stringOrNil("invalid password"),
		})
	}
}

// Delete a user
func (u *User) Delete() bool {
	db := DatabaseConnection()
	result := db.Delete(u)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			u.Errors = append(u.Errors, &provide.Error{
				Message: stringOrNil(err.Error()),
			})
		}
	}
	return len(u.Errors) == 0
}

// AsResponse marshals a user into a user response
func (u *User) AsResponse() *UserResponse {
	return &UserResponse{
		ID:        u.ID,
		CreatedAt: u.CreatedAt,
		Name:      *u.Name,
		Email:     *u.Email,
	}
}
