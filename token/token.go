package token

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/badoux/checkmail"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/ident/common"
	provide "github.com/provideservices/provide-go/api"
	prvdcommon "github.com/provideservices/provide-go/common"
)

const authorizationGrantRefreshToken = "refresh_token"
const authorizationScopeOfflineAccess = "offline_access"

const authorizationSubjectApplication = "application"
const authorizationSubjectInvite = "invite"
const authorizationSubjectOrganization = "organization"
const authorizationSubjectToken = "token"
const authorizationSubjectUser = "user"

const defaultRefreshTokenTTL = time.Hour * 24 * 30
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
	Token *string `sql:"type:bytea" json:"token,omitempty"`
	Hash  *string `json:"-"`

	// Associations
	ApplicationID  *uuid.UUID `sql:"type:uuid" json:"-"`
	OrganizationID *uuid.UUID `sql:"type:uuid" json:"-"`
	UserID         *uuid.UUID `sql:"type:uuid" json:"-"`

	// OAuth 2 fields
	AccessToken  *string `sql:"-" json:"access_token,omitempty"`
	RefreshToken *string `sql:"-" json:"refresh_token,omitempty"`
	TokenType    *string `sql:"-" json:"token_type,omitempty"`
	Scope        *string `sql:"-" json:"scope,omitempty"`

	// Ephemeral JWT header fields and claims; these are here for convenience and are not
	// always populated, even if they exist on the underlying token
	Kid       *string    `sql:"-" json:"kid,omitempty"` // key fingerprint
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

	NatsClaims map[string]interface{} `sql:"-" json:"-"` // NATS claims
}

// Response represents the token portion of the response to a successful authentication request
type Response struct {
	ID           *uuid.UUID `json:"id,omitempty"`
	TokenType    *string    `json:"token_type,omitempty"`
	AccessToken  *string    `json:"access_token,omitempty"`
	RefreshToken *string    `json:"refresh_token,omitempty"`
	IDToken      *string    `json:"id_token,omitempty"`
	ExpiresIn    *int64     `json:"expires_in,omitempty"`
	Scope        *string    `sql:"-" json:"scope,omitempty"`
	Token        *string    `json:"token,omitempty"` // token
	Permissions  *uint32    `json:"permissions,omitempty"`
}

// Revocation represents a previously-issued token which has since been revoked; this primarily applies to legacy
// API tokens (i.e., application-authorized tokens for machine-to-machine API calls that never expire), but revocations
// can be applied to any issued token; this is particularly useful for long-lived invitation tokens whichh should be
// invalidated after use.
type Revocation struct {
	Hash      *string    `sql:"not null" gorm:"primary_key" json:"-"`
	ExpiresAt *time.Time `json:"expires_at"` // this is the token expiration timestamp
	RevokedAt *time.Time `sql:"not null" json:"revoked_at"`
}

// TableName returns the db table name for gorm
func (r *Revocation) TableName() string {
	return "token_revocations"
}

// IsRevoked returns true if the given token has been revoked
func IsRevoked(token *Token) bool {
	if token.Hash == nil {
		token.CalculateHash()
	}

	var totalResults uint64
	dbconf.DatabaseConnection().Model(&Revocation{}).Where("hash = ?", token.Hash).Count(&totalResults)
	return totalResults == 1
}

// Parse a previously signed token and initialize the Token representation
func Parse(token string) (*Token, error) {
	jwtToken, err := jwt.Parse(token, func(_jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := _jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("failed to resolve a valid JWT signing key; unsupported signing alg specified in header: %s", _jwtToken.Method.Alg())
		}

		var kid *string
		if kidhdr, ok := _jwtToken.Header["kid"].(string); ok {
			kid = &kidhdr
		}

		publicKey, _, _ := prvdcommon.ResolveJWTKeypair(kid)
		if publicKey == nil {
			msg := "failed to resolve a valid JWT verification key"
			if kid != nil {
				msg = fmt.Sprintf("%s; invalid kid specified in header: %s", msg, *kid)
			} else {
				msg = fmt.Sprintf("%s; no default verification key configured", msg)
			}
			return nil, fmt.Errorf(msg)
		}

		return publicKey, nil
	})

	var tkn *Token

	if err != nil {
		tkn = FindLegacyToken(token)
		if tkn != nil {
			common.Log.Debugf("legacy API token authorized: %s", tkn.ID) // this is the id in the DB, not the token itself so it's safe to log
			return tkn, nil
		}
		return nil, fmt.Errorf("failed to parse given bearer token as valid JWT; %s", err.Error())
	}

	claims, claimsOk := jwtToken.Claims.(jwt.MapClaims)
	if !claimsOk {
		return nil, errors.New("failed to parse claims in given bearer token")
	}

	appclaims, appclaimsOk := claims[prvdcommon.JWTApplicationClaimsKey].(map[string]interface{})

	var appID *uuid.UUID
	var orgID *uuid.UUID
	var userID *uuid.UUID

	var sub string
	if subclaim, subclaimOk := claims["sub"].(string); subclaimOk {
		sub = subclaim
	}

	subprts := strings.Split(sub, ":")
	if len(subprts) != 2 {
		return nil, fmt.Errorf("valid bearer authorization contained invalid sub claim: %s", sub)
	}

	subUUID, err := uuid.FromString(subprts[1])
	if err != nil {
		if subprts[0] == authorizationSubjectInvite {
			err := checkmail.ValidateFormat(subprts[1])
			if err != nil {
				return nil, fmt.Errorf("valid bearer authorization contained invalid sub claim: %s; %s", sub, err.Error())
			}
		} else {
			return nil, fmt.Errorf("valid bearer authorization contained invalid sub claim: %s; %s", sub, err.Error())
		}
	}

	switch subprts[0] {
	case authorizationSubjectApplication:
		appID = &subUUID
	case authorizationSubjectInvite:
		// this is an invitation token and can only authorize certain actions within a user creation or authentication transaction;
		// such actions may be made on behalf of an application_id and/or organization_id specified in the invitation application claims
		common.Log.Debugf("parsed valid bearer authorization containing invitation subject: %s", sub)
	case authorizationSubjectOrganization:
		orgID = &subUUID
	case authorizationSubjectToken:
		// this is a refresh token and can only authorize new access tokens on behalf of a user_id specified in the application claims
		if appclaimsOk {
			if claimedUserID, claimedUserIDOk := appclaims["user_id"].(string); claimedUserIDOk {
				subUUID, err := uuid.FromString(claimedUserID)
				if err != nil {
					return nil, fmt.Errorf("valid bearer authorization contained invalid sub claim: %s; %s", sub, err.Error())
				}

				userID = &subUUID
				common.Log.Debugf("authorized refresh token for creation of new access token on behalf of user: %s", userID)
			}
		}
	case authorizationSubjectUser:
		userID = &subUUID
	}

	var iat *time.Time
	if claims["iat"] != nil {
		iat = parseJWTTimestampClaim(claims, "iat")
	}

	var exp *time.Time
	if claims["exp"] != nil {
		exp = parseJWTTimestampClaim(claims, "exp")
	}

	var nbf *time.Time
	if claims["nbf"] != nil {
		nbf = parseJWTTimestampClaim(claims, "nbf")
	}

	tkn = &Token{
		Token:          &jwtToken.Raw,
		IssuedAt:       iat,
		ExpiresAt:      exp,
		NotBefore:      nbf,
		Subject:        common.StringOrNil(sub),
		UserID:         userID,
		ApplicationID:  appID,
		OrganizationID: orgID,
	}

	if kid, kidOk := jwtToken.Header["kid"].(string); kidOk {
		tkn.Kid = &kid
	}

	if aud, audOk := claims["aud"].(string); audOk {
		tkn.Audience = &aud
	}

	if iss, issOk := claims["iss"].(string); issOk {
		tkn.Issuer = &iss
	}

	if appclaimsOk {
		if appIDClaim, appIDClaimOk := appclaims["application_id"].(string); appIDClaimOk && tkn.ApplicationID == nil {
			appUUID, err := uuid.FromString(appIDClaim)
			if err != nil {
				return nil, fmt.Errorf("valid bearer authorization contained invalid application_id app claim: %s; %s", sub, err.Error())
			}
			tkn.ApplicationID = &appUUID
		}

		if orgIDClaim, orgIDClaimOk := appclaims["organization_id"].(string); orgIDClaimOk && tkn.OrganizationID == nil {
			orgUUID, err := uuid.FromString(orgIDClaim)
			if err != nil {
				return nil, fmt.Errorf("valid bearer authorization contained invalid org_id app claim: %s; %s", sub, err.Error())
			}
			tkn.OrganizationID = &orgUUID
		}

		if userIDClaim, userIDClaimOk := appclaims["user_id"].(string); userIDClaimOk && tkn.UserID == nil {
			userUUID, err := uuid.FromString(userIDClaim)
			if err != nil {
				return nil, fmt.Errorf("valid bearer authorization contained invalid user_id app claim: %s; %s", sub, err.Error())
			}
			tkn.UserID = &userUUID
		}

		if permissions, permissionsOk := appclaims["permissions"].(float64); permissionsOk {
			tkn.Permissions = common.Permission(permissions)
		} else {
			common.Log.Warningf("valid bearer authorization was permissionless")
		}

		if extendedClaims, extendedClaimsOk := appclaims[extendedApplicationClaimsKey].(map[string]interface{}); extendedClaimsOk {
			if extendedPermissions, extendedPermissionsOk := extendedClaims["permissions"].(map[string]interface{}); extendedPermissionsOk {
				rawExtPermissions, _ := json.Marshal(extendedPermissions)
				extPermissionsJSON := json.RawMessage(rawExtPermissions)
				tkn.ExtendedPermissions = &extPermissionsJSON
			} else {
				common.Log.Warningf("extended bearer authorization was permissionless")
			}
		}

		if dataClaim, dataClaimOk := appclaims["data"].(map[string]interface{}); dataClaimOk {
			dataJSON, _ := json.Marshal(dataClaim)
			dataJSONRaw := json.RawMessage(dataJSON)
			tkn.Data = &dataJSONRaw
		}
	}

	return tkn, nil
}

// CalculateHash calculates and sets the hash on the token instance; this method exists for convenience
// as the hash is not set by default when a token is parsed, for performance reasons
func (t *Token) CalculateHash() {
	if t.Token != nil {
		t.Hash = common.StringOrNil(common.SHA256(*t.Token))
	} else {
		common.Log.Warningf("unable to calculate hash for nil token")
	}
}

// FindLegacyToken - lookup a legacy token
func FindLegacyToken(token string) *Token {
	db := dbconf.DatabaseConnection()
	tkn := &Token{}
	if db.HasTable(&tkn) {
		db.Where("hash = ?", common.SHA256(token)).Find(&tkn)
		if tkn != nil && tkn.ID != uuid.Nil {
			return tkn
		}
	}

	return nil
}

// GetApplicationTokens - retrieve the tokens associated with the given application
func GetApplicationTokens(applicationID *uuid.UUID) []*Token {
	var tokens []*Token
	dbconf.DatabaseConnection().Where("application_id = ?", applicationID).Find(&tokens)
	return tokens
}

// GetOrganizationTokens - retrieve the tokens associated with the given organization
func GetOrganizationTokens(organizationID *uuid.UUID) []*Token {
	var tokens []*Token
	dbconf.DatabaseConnection().Where("organization_id = ?", organizationID).Find(&tokens)
	return tokens
}

// IsRevoked returns true if the token has been revoked
func (t *Token) IsRevoked() bool {
	return IsRevoked(t)
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
func (t *Token) ParseExtendedPermissions() map[string]common.Permission {
	var extendedPermissions map[string]common.Permission
	if t.ExtendedPermissions != nil {
		extendedPermissions = map[string]common.Permission{}
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
		ID:          &t.ID,
		TokenType:   t.TokenType,
		ExpiresIn:   expiresIn,
		Scope:       t.Scope,
		Permissions: &permissions,
	}

	if t.RefreshToken != nil {
		resp.RefreshToken = t.RefreshToken
	}

	if resp.RefreshToken == nil && t.Token != nil {
		resp.Token = t.Token // deprecated
	} else if t.AccessToken != nil {
		resp.AccessToken = t.AccessToken
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

// HasExtendedPermission returns true if the named resource contains the given extended permission
func (t *Token) HasExtendedPermission(resource string, permission common.Permission) bool {
	extendedPermissions := t.ParseExtendedPermissions()
	if resourcePermissions, resourcePermissionsOk := extendedPermissions[resource]; resourcePermissionsOk {
		return resourcePermissions.Has(permission)
	}
	return false
}

// HasAnyExtendedPermission returns true if the named resource contains any of the given extended permissions
func (t *Token) HasAnyExtendedPermission(resource string, permissions ...common.Permission) bool {
	for _, p := range permissions {
		if t.HasExtendedPermission(resource, p) || t.HasExtendedPermission(wildcardApplicationResource, p) {
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

	ttl := int(defaultRefreshTokenTTL.Seconds())
	refreshToken := &Token{
		TokenType:           common.StringOrNil(defaultTokenType),
		UserID:              t.UserID,
		ApplicationID:       t.ApplicationID,
		OrganizationID:      t.OrganizationID,
		Kid:                 t.Kid,
		Audience:            t.Audience,
		Issuer:              t.Issuer,
		Subject:             common.StringOrNil(fmt.Sprintf("token:%s", t.ID.String())),
		Permissions:         t.Permissions,
		ExtendedPermissions: t.ExtendedPermissions,
		TTL:                 &ttl,
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
func VendApplicationToken(
	tx *gorm.DB,
	applicationID, organizationID, userID *uuid.UUID,
	extPermissions map[string]common.Permission,
	audience *string,
) (*Token, error) {
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
		OrganizationID:      organizationID,
		UserID:              userID,
		Permissions:         common.DefaultApplicationResourcePermission,
		ExtendedPermissions: &extPermissionsJSON,
		Audience:            audience,
	}

	if !t.validate() {
		return nil, fmt.Errorf("failed to vend token for application: %s; %s", applicationID.String(), *t.Errors[0].Message)
	}

	if db.NewRecord(t) {
		// this token is hashed and persisted, in contrast with signed bearer tokens created using t.Vend()
		common.Log.Debugf("vending API token for application; subject: %s", *t.Subject)

		jti, _ := uuid.NewV4()
		t.ID = jti

		err := t.encodeJWT()
		if err != nil {
			common.Log.Debugf("vending legacy API token for subject: %s", *t.Subject)
			t.Errors = append(t.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
			return nil, fmt.Errorf("failed to vend token for application: %s; %s", applicationID.String(), *t.Errors[0].Message)
		}

		t.CalculateHash()

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
	if (t.ApplicationID != nil && t.UserID != nil) || (t.OrganizationID != nil && t.UserID != nil) {
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
			exp = t.IssuedAt.Add(prvdcommon.JWTAuthorizationTTL)
		}
		t.ExpiresAt = &exp

		if t.ExpiresAt != nil && t.ExpiresAt.Before(*t.IssuedAt) {
			t.Errors = append(t.Errors, &provide.Error{
				Message: common.StringOrNil("token expiration must not preceed issuance"),
			})
		}

		if t.Kid == nil {
			_, privateKey, fingerprint := prvdcommon.ResolveJWTKeypair(nil) // FIXME-- resolve subject-specific kid when applicable
			if privateKey != nil {
				t.Kid = fingerprint
			} else {
				common.Log.Warning("no JWT signing key resolved")
			}
		}

		if t.Audience == nil {
			t.Audience = common.StringOrNil(prvdcommon.JWTAuthorizationAudience)
		}

		if t.Issuer == nil {
			t.Issuer = common.StringOrNil(prvdcommon.JWTAuthorizationIssuer)
		}

		if t.Subject == nil {
			var sub *string
			if t.UserID != nil {
				sub = common.StringOrNil(fmt.Sprintf("user:%s", t.UserID.String()))
			} else if t.ApplicationID != nil {
				sub = common.StringOrNil(fmt.Sprintf("application:%s", t.ApplicationID.String()))
			} else if t.OrganizationID != nil {
				sub = common.StringOrNil(fmt.Sprintf("organization:%s", t.OrganizationID.String()))
			}
			t.Subject = sub
		}
	}

	if t.Subject == nil {
		t.Errors = append(t.Errors, &provide.Error{
			Message: common.StringOrNil("token must have a sub claim"),
		})
	}

	return len(t.Errors) == 0
}

// Delete a legacy API token; effectively revokes the legacy token by permanently removing it from
// persistent storage; subsequent attempts to authorize requests with this token will fail after
// calling this method
func (t *Token) Delete(tx *gorm.DB) bool {
	if t.ID == uuid.Nil {
		common.Log.Warning("attempted to delete ephemeral token instance")
		return false
	}

	var db *gorm.DB
	if tx != nil {
		db = tx
	} else {
		db = dbconf.DatabaseConnection()
		db = db.Begin()
		defer db.RollbackUnlessCommitted()
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
	if success {
		success = t.Revoke(db)
		if success && tx == nil {
			db.Commit()
		}
	}
	return success
}

// Revoke the token; persist a revocation
func (t *Token) Revoke(tx *gorm.DB) bool {
	var db *gorm.DB
	if tx != nil {
		db = tx
	} else {
		db = dbconf.DatabaseConnection()
		db = db.Begin()
		defer db.RollbackUnlessCommitted()
	}

	if t.Hash == nil {
		t.CalculateHash()
	}

	revokedAt := time.Now()
	revocation := &Revocation{
		Hash:      t.Hash,
		ExpiresAt: t.ExpiresAt,
		RevokedAt: &revokedAt,
	}

	result := db.Create(&revocation)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			t.Errors = append(t.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}

	success := len(t.Errors) == 0
	if success {
		common.Log.Debugf("revoked token with subject: %s; hash: %s", *t.Subject, *t.Hash)
		db.Commit()
	} else {
		common.Log.Warningf("failed to revoke token with subject: %s; hash: %s", *t.Subject, *t.Hash)
	}
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

	if t.ApplicationID != nil {
		// drop exp claim from revocable application token
		delete(claims, "exp")
	}

	appClaimsKey := prvdcommon.JWTApplicationClaimsKey
	if t.ApplicationClaimsKey != nil {
		appClaimsKey = *t.ApplicationClaimsKey
	}
	claims[appClaimsKey] = t.encodeJWTAppClaims()

	natsClaims, err := t.encodeJWTNatsClaims()
	if err != nil {
		common.Log.Warningf("failed to encode NATS claims in JWT; %s", err.Error())
		return nil
	}
	if natsClaims != nil {
		claims[prvdcommon.JWTNatsClaimsKey] = natsClaims
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	jwtToken.Header["kid"] = t.Kid

	_, privateKey, _ := prvdcommon.ResolveJWTKeypair(t.Kid)
	token, err := jwtToken.SignedString(privateKey)
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

	if t.OrganizationID != nil {
		appClaims["organization_id"] = t.OrganizationID
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

func (t *Token) encodeJWTNatsClaims() (map[string]interface{}, error) {
	publishAllow := make([]string, 0)
	publishDeny := make([]string, 0)

	subscribeAllow := make([]string, 0)
	subscribeDeny := make([]string, 0)

	var responsesMax *int
	var responsesTTL *time.Duration

	if t.ApplicationID != nil {
		subscribeAllow = append(subscribeAllow, fmt.Sprintf("application.%s", t.ApplicationID.String()))
	}

	if t.UserID != nil {
		subscribeAllow = append(subscribeAllow, fmt.Sprintf("user.%s", t.UserID.String()))
	}

	if t.OrganizationID != nil {
		subscribeAllow = append(subscribeAllow, fmt.Sprintf("organization.%s", t.OrganizationID.String()))
	}

	if t.NatsClaims != nil && len(t.NatsClaims) > 0 {
		if permissions, permissionsOk := t.NatsClaims["permissions"].(map[string]interface{}); permissionsOk {
			if pub, pubOk := permissions["publish"].(map[string]interface{}); pubOk {
				if allow, allowOk := pub["allow"].([]string); allowOk {
					for _, subject := range allow {
						publishAllow = append(publishAllow, subject)
					}
				}

				if deny, denyOk := pub["deny"].([]string); denyOk {
					for _, subject := range deny {
						publishDeny = append(publishDeny, subject)
					}
				}
			}

			if sub, subOk := permissions["subscribe"].(map[string]interface{}); subOk {
				if allow, allowOk := sub["allow"].([]string); allowOk {
					for _, subject := range allow {
						subscribeAllow = append(subscribeAllow, subject)
					}
				}

				if deny, denyOk := sub["deny"].([]string); denyOk {
					for _, subject := range deny {
						subscribeDeny = append(subscribeDeny, subject)
					}
				}
			}

			if resp, respOk := permissions["responses"].(map[string]interface{}); respOk {
				if max, maxOk := resp["max"].(float64); maxOk {
					respMax := int(max)
					responsesMax = &respMax
				}

				if ttl, ttlOk := resp["ttl"].(float64); ttlOk {
					respTTL := time.Duration(ttl)
					responsesTTL = &respTTL
				}
			}
		}
	} else {
		// FIXME-- put these defaults in configuration and read them from there...
		subscribeAllow = append(subscribeAllow, "network.*.connector.*")
		subscribeAllow = append(subscribeAllow, "network.*.status")
		subscribeAllow = append(subscribeAllow, "platform.>")
	}

	var publishPermissions map[string]interface{}
	if len(publishAllow) > 0 || len(publishDeny) > 0 {
		publishPermissions = map[string]interface{}{}
		if len(publishAllow) > 0 {
			publishPermissions["allow"] = publishAllow
		}
		if len(publishDeny) > 0 {
			publishPermissions["deny"] = publishDeny
		}
	}

	var subscribePermissions map[string]interface{}
	if len(subscribeAllow) > 0 || len(subscribeDeny) > 0 {
		subscribePermissions = map[string]interface{}{}
		if len(subscribeAllow) > 0 {
			subscribePermissions["allow"] = subscribeAllow
		}
		if len(subscribeDeny) > 0 {
			subscribePermissions["deny"] = subscribeDeny
		}
	}

	var responsesPermissions map[string]interface{}
	if responsesMax != nil || responsesTTL != nil {
		responsesPermissions = map[string]interface{}{}
		if responsesMax != nil {
			responsesPermissions["max"] = responsesMax
		}
		if responsesTTL != nil {
			responsesPermissions["ttl"] = responsesTTL
		}
	}

	var permissions map[string]interface{}
	if publishPermissions != nil || subscribePermissions != nil || responsesPermissions != nil {
		permissions = map[string]interface{}{}
		if publishPermissions != nil {
			permissions["publish"] = publishPermissions
		}
		if subscribePermissions != nil {
			permissions["subscribe"] = subscribePermissions
		}
		if responsesPermissions != nil {
			permissions["responses"] = responsesPermissions
		}
	}

	var natsClaims map[string]interface{}
	if permissions != nil {
		natsClaims = map[string]interface{}{
			"permissions": permissions,
		}
	}

	return natsClaims, nil
}
