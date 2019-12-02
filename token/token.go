package token

import (
	"encoding/json"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/ident/common"
	provide "github.com/provideservices/provide-go"
)

// Token model which is represented as JWT; tokens will be used is a wide variety of cases
type Token struct {
	provide.Model
	IssuedAt      *time.Time       `sql:"not null" json:"issued_at"`
	ExpiresAt     *time.Time       `json:"expires_at"`
	Token         *string          `json:"token"` // JWT https://tools.ietf.org/html/rfc7519
	ApplicationID *uuid.UUID       `sql:"type:uuid" json:"-"`
	UserID        *uuid.UUID       `sql:"type:uuid" json:"-"`
	Data          *json.RawMessage `sql:"-" json:"data"`
}

// TokenResponse represents the token portion of the response to a successful authentication request
type TokenResponse struct {
	ID        uuid.UUID `json:"id"`
	Token     string    `json:"token"`
	PublicKey string    `json:"public_key,omitempty"`
}

// // GetApplication - retrieve the application associated with the token (or nil if one does not exist)
// func (t *Token) GetApplication() *Application {
// 	if t.ApplicationID == nil {
// 		return nil
// 	}
// 	var app = &Application{}
// 	dbconf.DatabaseConnection().Model(t).Related(&app)
// 	if app.ID == uuid.Nil {
// 		return nil
// 	}
// 	return app
// }

// GetApplicationTokens - retrieve the tokens associated with the application
func GetApplicationTokens(applicationID *uuid.UUID) []*Token {
	var tokens []*Token
	dbconf.DatabaseConnection().Where("application_id = ?", applicationID).Find(&tokens)
	return tokens
}

// CreateApplicationToken creates a new token on behalf of the application
func CreateApplicationToken(applicationID *uuid.UUID) (*Token, error) {
	token := &Token{
		ApplicationID: applicationID,
	}
	if !token.Create() {
		if len(token.Errors) > 0 {
			return nil, fmt.Errorf("Failed to create token for application: %s; %s", applicationID.String(), *token.Errors[0].Message)
		}
	}
	return token, nil
}

// // GetUser - retrieve the user associated with the token (or nil if one does not exist)
// func (t *Token) GetUser() *user.User {
// 	if t.UserID == nil {
// 		return nil
// 	}
// 	var user = &user.User{}
// 	dbconf.DatabaseConnection().Model(t).Related(&user)
// 	if user != nil && user.ID == uuid.Nil {
// 		return nil
// 	}
// 	return user
// }

// Create and persist a token which may be subsequently used for bearer authorization (among other things)
func (t *Token) Create() bool {
	if !t.Validate() {
		return false
	}

	db := dbconf.DatabaseConnection()
	if db.NewRecord(t) {
		result := db.Create(&t)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				t.Errors = append(t.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
		if !db.NewRecord(t) {
			if rowsAffected > 0 {
				var err error
				t.Token, err = t.encodeJWT()
				if err != nil {
					t.Errors = append(t.Errors, &provide.Error{
						Message: common.StringOrNil(err.Error()),
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

	claims := map[string]interface{}{
		"jti":  t.ID.String(),
		"iat":  t.IssuedAt.Unix(),
		"data": t.ParseData(),
	}

	if t.ApplicationID != nil {
		claims["sub"] = fmt.Sprintf("application:%s", t.ApplicationID.String())
	} else if t.UserID != nil {
		claims["sub"] = fmt.Sprintf("user:%s", t.UserID.String())
	}

	if t.ExpiresAt != nil {
		claims["exp"] = t.ExpiresAt.Unix()
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token, err := jwtToken.SignedString(common.JWTPrivateKey)
	if err != nil {
		common.Log.Warningf("Failed to sign JWT token; %s", err.Error())
		return nil, err
	}
	return common.StringOrNil(token), nil
}

// Validate a token for persistence
func (t *Token) Validate() bool {
	t.Errors = make([]*provide.Error, 0)
	db := dbconf.DatabaseConnection()
	if db.NewRecord(t) {
		if t.ApplicationID != nil && t.UserID != nil {
			t.Errors = append(t.Errors, &provide.Error{
				Message: common.StringOrNil("ambiguous token subject"),
			})
		}
		if t.IssuedAt != nil {
			t.Errors = append(t.Errors, &provide.Error{
				Message: common.StringOrNil("token must not attempt assert iat JWT claim"),
			})
		} else {
			iat := time.Now()
			t.IssuedAt = &iat
			if t.ExpiresAt != nil && t.ExpiresAt.Before(*t.IssuedAt) {
				t.Errors = append(t.Errors, &provide.Error{
					Message: common.StringOrNil("token expiration must not preceed issuance"),
				})
			}
		}
	}
	return len(t.Errors) == 0
}

// Delete a token; effectively revokes the token resulting in subsequent attempts to authorize requests to fail unless a new (valid) token is acquired
func (t *Token) Delete() bool {
	db := dbconf.DatabaseConnection()
	result := db.Delete(t)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			t.Errors = append(t.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
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
			common.Log.Warningf("Failed to unmarshal token data; %s", err.Error())
			return nil
		}
	}
	return data
}

// AsResponse marshals a token into a token response
func (t *Token) AsResponse() *TokenResponse {
	return &TokenResponse{
		ID:        t.ID,
		Token:     string(*t.Token),
		PublicKey: common.JWTPublicKeyPEM,
	}
}
