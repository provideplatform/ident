package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/badoux/checkmail"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/kthomas/go.uuid"
	provide "github.com/provideservices/provide-go"
	"golang.org/x/crypto/bcrypt"
)

// Application model which is initially owned by the user who created it
type Application struct {
	provide.Model
	UserID      uuid.UUID        `sql:"type:uuid not null" json:"user_id"`
	Name        *string          `sql:"not null" json:"name"`
	Description *string          `json:"description"`
	Config      *json.RawMessage `sql:"type:json" json:"config"`
	Hidden      bool             `sql:"not null;default:false" json:"hidden"` // soft-delete mechanism
}

// Token model which is represented as JWT; tokens will be used is a wide variety of cases
type Token struct {
	provide.Model
	IssuedAt      *time.Time       `sql:"not null" json:"issued_at"`
	ExpiresAt     *time.Time       `json:"expires_at"`
	Secret        *string          `sql:"secret" json:"-"`
	Token         *string          `json:"token"` // JWT https://tools.ietf.org/html/rfc7519
	ApplicationID *uuid.UUID       `sql:"type:uuid" json:"-"`
	UserID        *uuid.UUID       `sql:"type:uuid" json:"-"`
	Data          *json.RawMessage `sql:"-" json:"data"`
}

// User model
type User struct {
	provide.Model
	ApplicationID *uuid.UUID `sql:"type:uuid" json:"-"`
	Name          *string    `sql:"not null" json:"name"`
	Email         *string    `sql:"not null" json:"email"`
	Password      *string    `sql:"not null" json:"password"`
}

// TokenResponse represents the token portion of the response to a successful authentication request
type TokenResponse struct {
	ID    uuid.UUID `json:"id"`
	Token string    `json:"token"`
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

// Create a new token on behalf of the application
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
			return rowsAffected > 0
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

// GetApplication - retrieve the application associated with the token (or nil if one does not exist)
func (t *Token) GetApplication() *Application {
	if t.ApplicationID == nil {
		return nil
	}
	var app = &Application{}
	DatabaseConnection().Model(t).Related(&app)
	if app.ID == uuid.Nil {
		return nil
	}
	return app
}

// GetUser - retrieve the user associated with the token (or nil if one does not exist)
func (t *Token) GetUser() *User {
	if t.UserID == nil {
		return nil
	}
	var user = &User{}
	DatabaseConnection().Model(t).Related(&user)
	if user.ID == uuid.Nil {
		return nil
	}
	return user
}

// Create and persist a token which may be subsequently used for bearer authorization (among other things)
func (t *Token) Create() bool {
	if !t.Validate() {
		return false
	}

	db := DatabaseConnection()
	if db.NewRecord(t) {
		result := db.Create(&t)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				t.Errors = append(t.Errors, &provide.Error{
					Message: stringOrNil(err.Error()),
				})
			}
		}
		if !db.NewRecord(t) {
			if rowsAffected > 0 {
				var err error
				t.Token, err = t.encodeJWT()
				if err != nil {
					t.Errors = append(t.Errors, &provide.Error{
						Message: stringOrNil(err.Error()),
					})
					return false
				}
				db.Save(&t) // FIXME-- harden for unexpected failure case
				return true
			}
			return false
		}
	}
	return false
}

func (t *Token) encodeJWT() (*string, error) {
	if t.Token != nil {
		return nil, fmt.Errorf("Failed to encode JWT; token has already been issued: %s", *t.Token)
	}

	var sub string
	if t.ApplicationID != nil {
		sub = fmt.Sprintf("application:%s", t.ApplicationID.String())
	} else if t.UserID != nil {
		sub = fmt.Sprintf("user:%s", t.UserID.String())
	}

	var exp *int64
	if t.ExpiresAt != nil {
		expAt := t.ExpiresAt.Unix()
		exp = &expAt
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.MapClaims{
		"jti":  t.ID.String(),
		"iat":  t.IssuedAt.Unix(),
		"sub":  stringOrNil(sub),
		"exp":  exp,
		"data": t.ParseData(),
	})
	token, err := jwtToken.SignedString([]byte(*t.Secret))
	if err != nil {
		Log.Warningf("Failed to sign JWT token; %s", err.Error())
		return nil, err
	}
	return stringOrNil(token), nil
}

// Validate a token for persistence
func (t *Token) Validate() bool {
	t.Errors = make([]*provide.Error, 0)
	db := DatabaseConnection()
	if db.NewRecord(t) {
		if t.ApplicationID != nil && t.UserID != nil {
			t.Errors = append(t.Errors, &provide.Error{
				Message: stringOrNil("ambiguous token subject"),
			})
		}
		if t.IssuedAt != nil {
			t.Errors = append(t.Errors, &provide.Error{
				Message: stringOrNil("token must not attempt assert iat JWT claim"),
			})
		} else {
			iat := time.Now()
			t.IssuedAt = &iat
			if t.ExpiresAt != nil && t.ExpiresAt.Before(*t.IssuedAt) {
				t.Errors = append(t.Errors, &provide.Error{
					Message: stringOrNil("token expiration must not preceed issuance"),
				})
			}
		}
		if t.Secret != nil {
			t.Errors = append(t.Errors, &provide.Error{
				Message: stringOrNil("token secret must not be supplied; it must be generated at this time"),
			})
		} else {
			uuidV4, err := uuid.NewV4()
			if err == nil {
				t.Secret = stringOrNil(uuidV4.String())
			} else {
				t.Errors = append(t.Errors, &provide.Error{
					Message: stringOrNil(fmt.Sprintf("token secret generation failed; %s", err.Error())),
				})
			}
		}
	}
	return len(t.Errors) == 0
}

// Delete a token; effectively revokes the token resulting in subsequent attempts to authorize requests to fail unless a new (valid) token is acquired
func (t *Token) Delete() bool {
	db := DatabaseConnection()
	result := db.Delete(t)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			t.Errors = append(t.Errors, &provide.Error{
				Message: stringOrNil(err.Error()),
			})
		}
	}
	return len(t.Errors) == 0
}

// ParseData - parse the optional token data payload
func (t *Token) ParseData() map[string]interface{} {
	data := map[string]interface{}{}
	if t.Data != nil {
		err := json.Unmarshal(*t.Data, &data)
		if err != nil {
			Log.Warningf("Failed to unmarshal token data; %s", err.Error())
			return nil
		}
	}
	return data
}

// AsResponse marshals a token into a token response
func (t *Token) AsResponse() *TokenResponse {
	return &TokenResponse{
		ID:    t.ID,
		Token: string(*t.Token),
	}
}

// AuthenticateUser attempts to authenticate by email address and password
func AuthenticateUser(email, password string, applicationID *uuid.UUID) (*UserAuthenticationResponse, error) {
	var user = &User{}
	db := DatabaseConnection()
	query := db.Where("email = ?", strings.ToLower(email))
	if applicationID != nil && *applicationID != uuid.Nil {
		query = query.Where("application_id = ?", applicationID)
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
			Log.Warningf(err.Error())
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
			return rowsAffected > 0
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
	return len(u.Errors) == 0
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
