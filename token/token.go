package token

import (
	"encoding/json"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/ident/common"
	provide "github.com/provideservices/provide-go"
)

const authorizationGrantRefreshToken = "refresh_token"
const authorizationScopeOfflineAccess = "offline_access"

const defaultRefreshTokenTTL = time.Hour * 24
const defaultAccessTokenTTL = time.Minute * 60
const defaultTokenType = "bearer"

const extendedApplicationClaimsKey = "extended"
const wildcardApplicationResource = "*"

var defaultApplicationExtendedPermissions = map[string]common.Permission{
	wildcardApplicationResource: common.DefaultApplicationResourcePermission,
}

// Token instances can be ephemeral (access/refresh style) or "legacy" -- in the sense that
// a "legacy" token never expires and is persisted along with its hashed representation
type Token struct {
	provide.Model

	// Token represents a legacy token authorization which never expires, but is hashed and
	// persisted in the db so therefore it can be revoked; requests which contain authorization
	// headers containing these legacy tokens also present claims, so no db lookup is required
	Token         *string    `sql:"type:bytea" json:"token"`
	Hash          *string    `json:"-"`
	ApplicationID *uuid.UUID `sql:"type:uuid" json:"-"`
	UserID        *uuid.UUID `sql:"type:uuid" json:"-"`

	// OAuth 2 fields
	AccessToken  *string `sql:"-" json:"access_token,omitempty"`
	RefreshToken *string `sql:"-" json:"refresh_token,omitempty"`
	TokenType    *string `sql:"-" json:"token_type,omitempty"`
	Scope        *string `sql:"-" json:"scope,omitempty"`

	// Ephemeral JWT claims; these are here for convenience and are not always populated,
	// even if they exist on the underlying token
	Audience  *string    `sql:"-" json:"audience,omitempty"`
	Issuer    *string    `sql:"-" json:"issuer,omitempty"`
	IssuedAt  *time.Time `sql:"-" json:"issued_at,omitempty"`
	ExpiresAt *time.Time `sql:"-" json:"expires_at,omitempty"`
	NotBefore *time.Time `sql:"-" json:"not_before_at,omitempty"`
	Subject   *string    `sql:"-" json:"subject,omitempty"`

	ApplicationClaimsKey *string           `sql:"-" json:"-"` // string key where application-specific claims are encoded
	Permissions          common.Permission `sql:"-" json:"permissions,omitempty"`
	ExtendedPermissions  *json.RawMessage  `sql:"-" json:"-"`
	TTL                  *int              `sql:"-" json:"-"` // number of seconds this token will be valid; used internally
	Data                 *json.RawMessage  `sql:"-" json:"data,omitempty"`
}

// Response represents the token portion of the response to a successful authentication request
type Response struct {
	ID           *uuid.UUID `json:"id,omitempty"`
	TokenType    *string    `json:"token_type,omitempty"`
	AccessToken  *string    `json:"access_token,omitempty"`
	RefreshToken *string    `json:"refresh_token,omitempty"`
	ExpiresIn    *int64     `json:"expires_in,omitempty"`
	Scope        *string    `sql:"-" json:"scope,omitempty"`
	Token        *string    `json:"token,omitempty"` // token
	PublicKey    *string    `json:"public_key,omitempty"`
	Permissions  *uint32    `json:"permissions,omitempty"`
}

// FindLegacyToken - lookup a legacy token
func FindLegacyToken(token string) *Token {
	tkn := &Token{}
	dbconf.DatabaseConnection().Where("hash = ?", common.SHA256(token)).Find(&tkn)
	if tkn != nil && tkn.ID != uuid.Nil {
		return tkn
	}
	return nil
}

// GetApplicationTokens - retrieve the tokens associated with the application
func GetApplicationTokens(applicationID *uuid.UUID) []*Token {
	var tokens []*Token
	dbconf.DatabaseConnection().Where("application_id = ?", applicationID).Find(&tokens)
	return tokens
}

// ParseData parses and returns any data to be encoded within
// application-specific claims in a bearer JWT
func (t *Token) ParseData() map[string]interface{} {
	var data map[string]interface{}
	if t.Data != nil {
		data = map[string]interface{}{}
		err := json.Unmarshal(*t.Data, &data)
		if err != nil {
			common.Log.Warningf("failed to unmarshal token data; %s", err.Error())
			return nil
		}
	}
	return data
}

// ParseExtendedPermissions parses and returns the extended permissions mapping for
// resources which contains the resource subject name i.e., the `sub` part of the
// encoded subject `<sub>:<id>` mapped to the generic permission mask for that resource
func (t *Token) ParseExtendedPermissions() map[string]interface{} {
	var extendedPermissions map[string]interface{}
	if t.ExtendedPermissions != nil {
		extendedPermissions = map[string]interface{}{}
		err := json.Unmarshal(*t.ExtendedPermissions, &extendedPermissions)
		if err != nil {
			common.Log.Warningf("failed to unmarshal extended permissions; %s", err.Error())
			return nil
		}
	}
	return extendedPermissions
}

// AsResponse marshals a token into a token response
func (t *Token) AsResponse() *Response {
	var expiresIn *int64
	if t.ExpiresAt != nil {
		ttl := t.ExpiresAt.Unix() - time.Now().Unix()
		expiresIn = &ttl
	}

	permissions := uint32(t.Permissions)
	resp := &Response{
		ID:           &t.ID,
		Token:        t.Token, // deprecated
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		TokenType:    t.TokenType,
		ExpiresIn:    expiresIn,
		Scope:        t.Scope,
		PublicKey:    common.StringOrNil(common.JWTPublicKeyPEM),
		Permissions:  &permissions,
	}

	return resp
}

// HasPermission returns true if the permissioned Token instance contains the given permissions
func (t *Token) HasPermission(permission common.Permission) bool {
	return t.Permissions.Has(permission)
}

// HasAnyPermission returns true if the permissioned Token instance contains any the given permissions
func (t *Token) HasAnyPermission(permissions ...common.Permission) bool {
	for _, p := range permissions {
		if t.HasPermission(p) {
			return true
		}
	}
	return false
}

// Vend an access/refresh token pair which may be subsequently used by the bearer to access various platform resources
// as well as obtain new access tokens; legacy API tokens are the only tokens actually written to persistent storage,
// but that method is deprecated and all newly-issued tokens are ephemeral, in-memory only prior to be signed and
// returned to the user. A refresh token is only returned when the offline_access scope is set.
func (t *Token) Vend() bool {
	db := dbconf.DatabaseConnection()
	if db.NewRecord(t) {
		if !t.validate() {
			return false
		}

		common.Log.Debugf("vending signed JWT credential for subject: %s", *t.Subject)
		if t.ID == uuid.Nil {
			// this token is ephemeral (id == 00000000-0000-0000-0000-000000000000)
			jti, _ := uuid.NewV4()
			t.ID = jti
		}

		if t.Scope != nil && *t.Scope == authorizationScopeOfflineAccess {
			if !t.vendRefreshToken() {
				msg := "failed to vend refresh token for access/refresh token pair"
				if len(t.Errors) > 0 {
					msg = fmt.Sprintf("%s; %s", msg, *t.Errors[0].Message)
				}
				return false
			}
		}

		err := t.encodeJWT()
		if err != nil {
			t.Errors = append(t.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
			return false
		}
		return t.Token != nil
	}
	return false
}

func (t *Token) vendRefreshToken() bool {
	if t.ID == uuid.Nil {
		common.Log.Warning("failed to vend refresh token without valid jti")
		return false
	}

	ttl := int(defaultAccessTokenTTL.Seconds())
	refreshToken := &Token{
		TokenType:     common.StringOrNil(defaultTokenType),
		UserID:        t.UserID,
		ApplicationID: t.ApplicationID,
		Audience:      t.Audience,
		Issuer:        t.Issuer,
		Subject:       common.StringOrNil(fmt.Sprintf("token:%s", t.ID.String())),
		TTL:           &ttl,
	}

	if !refreshToken.Vend() {
		common.Log.Warningf("failed to vend refresh token for jti: %s", t.ID.String())
		return false
	}

	t.RefreshToken = refreshToken.Token
	return true
}

// VendApplicationToken creates a new token on behalf of the application;
// these tokens should be used for machine-to-machine applications, and so
// are persisted as "legacy" tokens as described in the VendLegacyToken docs
func VendApplicationToken(tx *gorm.DB, applicationID *uuid.UUID, extPermissions map[string]common.Permission) (*Token, error) {
	var db *gorm.DB
	if tx != nil {
		db = tx
	} else {
		db = dbconf.DatabaseConnection()
	}

	extendedPermissions := extPermissions
	if extendedPermissions == nil {
		extendedPermissions = defaultApplicationExtendedPermissions
	}
	rawExtPermissions, _ := json.Marshal(extendedPermissions)
	extPermissionsJSON := json.RawMessage(rawExtPermissions)

	t := &Token{
		ApplicationID:       applicationID,
		Permissions:         common.DefaultApplicationResourcePermission,
		ExtendedPermissions: &extPermissionsJSON,
	}

	if !t.validate() {
		return nil, fmt.Errorf("failed to vend token for application: %s; %s", applicationID.String(), *t.Errors[0].Message)
	}

	if db.NewRecord(t) {
		// this token is hashed and persisted, in contrast with signed bearer tokens created using t.Vend()
		common.Log.Debugf("vending API token for application; subject: %s", *t.Subject)

		err := t.encodeJWT()
		if err != nil {
			common.Log.Debugf("vending legacy API token for subject: %s", *t.Subject)
			t.Errors = append(t.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
			return nil, fmt.Errorf("failed to vend token for application: %s; %s", applicationID.String(), *t.Errors[0].Message)
		}

		t.Hash = common.StringOrNil(common.SHA256(*t.Token))

		result := db.Create(&t)
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				t.Errors = append(t.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
			return nil, fmt.Errorf("failed to vend token for application: %s; %s", applicationID.String(), *t.Errors[0].Message)
		}
	}

	return t, nil
}

// validate a token; package private due to side-effects of setting
// issue and expiry timestamps, audience, issuer and other derived claims
func (t *Token) validate() bool {
	t.Errors = make([]*provide.Error, 0)

	if t.Token != nil {
		t.Errors = append(t.Errors, &provide.Error{
			Message: common.StringOrNil("token has already been vended"),
		})
	}
	if t.ApplicationID != nil && t.UserID != nil {
		t.Errors = append(t.Errors, &provide.Error{
			Message: common.StringOrNil("ambiguous token subject"),
		})
	}
	if t.IssuedAt != nil {
		t.Errors = append(t.Errors, &provide.Error{
			Message: common.StringOrNil("token must not self-assert iat claim"),
		})
	}
	if t.ExpiresAt != nil {
		t.Errors = append(t.Errors, &provide.Error{
			Message: common.StringOrNil("token must not self-assert exp claim"),
		})
	}

	if len(t.Errors) == 0 {
		iat := time.Now()
		t.IssuedAt = &iat

		var exp time.Time
		if t.TTL != nil {
			exp = t.IssuedAt.Add(time.Second * time.Duration(*t.TTL))
		} else {
			exp = t.IssuedAt.Add(common.JWTAuthorizationTTL)
		}
		t.ExpiresAt = &exp

		if t.ExpiresAt != nil && t.ExpiresAt.Before(*t.IssuedAt) {
			t.Errors = append(t.Errors, &provide.Error{
				Message: common.StringOrNil("token expiration must not preceed issuance"),
			})
		}

		if t.Audience == nil {
			t.Audience = common.StringOrNil(common.JWTAuthorizationAudience)
		}

		if t.Issuer == nil {
			t.Issuer = common.StringOrNil(common.JWTAuthorizationIssuer)
		}

		if t.Subject == nil {
			var sub *string
			if t.UserID != nil {
				sub = common.StringOrNil(fmt.Sprintf("user:%s", t.UserID.String()))
			} else if t.ApplicationID != nil {
				sub = common.StringOrNil(fmt.Sprintf("application:%s", t.ApplicationID.String()))
			}
			t.Subject = sub
		}
	}
	return len(t.Errors) == 0
}

// Delete a legacy API token; effectively revokes the legacy token by permanently removing it from
// persistent storage; subsequent attempts to authorize requests with this token will fail after
// calling this method
func (t *Token) Delete(db *gorm.DB) bool {
	if t.ID == uuid.Nil {
		common.Log.Warning("attempted to delete ephemeral token instance")
		return false
	}

	result := db.Delete(&t)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			t.Errors = append(t.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}
	success := len(t.Errors) == 0
	return success
}

func (t *Token) encodeJWT() error {
	claims := map[string]interface{}{
		"aud": t.Audience,
		"exp": t.ExpiresAt.Unix(),
		"iat": t.IssuedAt.Unix(),
		"iss": t.Issuer,
		"jti": t.ID,
		"sub": t.Subject,
	}

	if t.NotBefore != nil {
		claims["nbf"] = t.NotBefore.Unix()
	}

	appClaimsKey := common.JWTApplicationClaimsKey
	if t.ApplicationClaimsKey != nil {
		appClaimsKey = *t.ApplicationClaimsKey
	}
	claims[appClaimsKey] = t.encodeJWTAppClaims()

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token, err := jwtToken.SignedString(common.JWTPrivateKey)
	if err != nil {
		common.Log.Warningf("failed to sign JWT; %s", err.Error())
		return nil
	}
	t.Token = common.StringOrNil(token)
	t.AccessToken = t.Token
	return nil
}

func (t *Token) encodeJWTAppClaims() map[string]interface{} {
	appClaims := map[string]interface{}{
		"permissions": t.Permissions,
	}

	if t.ApplicationID != nil {
		appClaims["application_id"] = t.ApplicationID
	}

	if t.UserID != nil {
		appClaims["user_id"] = t.UserID
	}

	extendedPermissions := t.ParseExtendedPermissions()
	if extendedPermissions != nil {
		appClaims[extendedApplicationClaimsKey] = map[string]interface{}{
			"permissions": extendedPermissions,
		}
	}

	appData := t.ParseData()
	if appData != nil {
		appClaims["data"] = appData
	}

	return appClaims
}
