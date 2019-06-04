package main

import (
	"encoding/json"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	dbconf "github.com/kthomas/go-db-config"
	"github.com/kthomas/go.uuid"
	provide "github.com/provideservices/provide-go"
)

func init() {
	db := dbconf.DatabaseConnection()

	db.AutoMigrate(&Token{})
	db.Model(&Token{}).AddIndex("idx_tokens_token", "token")
	db.Model(&Token{}).AddForeignKey("application_id", "applications(id)", "SET NULL", "CASCADE")
	db.Model(&Token{}).AddForeignKey("user_id", "users(id)", "SET NULL", "CASCADE")
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

// TokenResponse represents the token portion of the response to a successful authentication request
type TokenResponse struct {
	ID    uuid.UUID `json:"id"`
	Token string    `json:"token"`
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
		log.Warningf("Failed to sign JWT token; %s", err.Error())
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
			log.Warningf("Failed to unmarshal token data; %s", err.Error())
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
