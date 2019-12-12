package user

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
	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	trumail "github.com/kthomas/trumail/verifier"
	"github.com/provideapp/ident/common"
	"github.com/provideapp/ident/token"
	provide "github.com/provideservices/provide-go"
	"golang.org/x/crypto/bcrypt"
)

const defaultResetPasswordTokenTimeout = time.Hour * 1
const identUserIDKey = "ident_user_id"
const natsSiaUserNotificationSubject = "sia.user.notification"

// User model
type User struct {
	provide.Model
	ApplicationID          *uuid.UUID             `sql:"type:uuid" json:"application_id,omitempty"`
	Name                   *string                `sql:"not null" json:"name"`
	Email                  *string                `sql:"not null" json:"email"`
	Permissions            common.Permission      `sql:"not null" json:"permissions,omitempty"`
	EphemeralMetadata      *EphemeralUserMetadata `sql:"-" json:"metadata,omitempty"`
	Password               *string                `json:"-"`
	PrivacyPolicyAgreedAt  *time.Time             `json:"privacy_policy_agreed_at"`
	TermsOfServiceAgreedAt *time.Time             `json:"terms_of_service_agreed_at"`
	ResetPasswordToken     *string                `json:"-"`
}

// AuthenticationResponse is returned upon successful authentication using an email address
type AuthenticationResponse struct {
	User  *Response       `json:"user"`
	Token *token.Response `json:"token"`
}

// CreateResponse model
type CreateResponse struct {
	User  *Response    `json:"user"`
	Token *token.Token `json:"token"`
}

// Response is preferred over writing an entire User instance as JSON
type Response struct {
	ID        uuid.UUID              `json:"id"`
	CreatedAt time.Time              `json:"created_at"`
	Name      string                 `json:"name"`
	Email     string                 `json:"email"`
	Metadata  *EphemeralUserMetadata `json:"metadata,omitempty"`
}

// Find returns a user for the given id
func Find(userID *uuid.UUID) *User {
	db := dbconf.DatabaseConnection()
	user := &User{}
	db.Where("id = ?", userID).Find(&user)
	if user == nil || user.ID == uuid.Nil {
		return nil
	}
	return user
}

// FindByEmail returns a user for the given email address and application id
func FindByEmail(email string, applicationID *uuid.UUID) *User {
	db := dbconf.DatabaseConnection()
	user := &User{}
	query := db.Where("email = ?", email)
	if applicationID != nil && *applicationID != uuid.Nil {
		query = query.Where("application_id = ?", applicationID)
	} else {
		query = query.Where("application_id IS NULL")
	}
	query.Find(&user)
	if user == nil || user.ID == uuid.Nil {
		return nil
	}
	return user
}

// Exists returns true if a user exists for the given email address and app id
func Exists(email string, applicationID *uuid.UUID) bool {
	return FindByEmail(email, applicationID) != nil
}

// AuthenticateUser attempts to authenticate by email address and password;
// i.e., this is equivalent to grant_type=password under the OAuth 2 spec
func AuthenticateUser(email, password string, applicationID *uuid.UUID, scope *string) (*AuthenticationResponse, error) {
	var user = &User{}
	db := dbconf.DatabaseConnection()
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
	token := &token.Token{
		UserID: &user.ID,
		Scope:  scope,
	}
	if !token.Vend() {
		var err error
		if len(token.Errors) > 0 {
			err = fmt.Errorf("failed to create token for authenticated user: %s; %s", *user.Email, *token.Errors[0].Message)
			common.Log.Warningf(err.Error())
		}
		return &AuthenticationResponse{
			User:  user.AsResponse(),
			Token: nil,
		}, err
	}
	return &AuthenticationResponse{
		User:  user.AsResponse(),
		Token: token.AsResponse(),
	}, nil
}

// AuthenticateApplicationUser vends a user token on behalf of the owning application
func AuthenticateApplicationUser(email string, applicationID uuid.UUID) (*AuthenticationResponse, error) {
	var user = &User{}
	db := dbconf.DatabaseConnection()
	query := db.Where("application_id = ? AND email = ?", applicationID, strings.ToLower(email))
	query.First(&user)
	if user != nil && user.ID != uuid.Nil {
		if user.Password != nil {
			return nil, errors.New("application user authentication not currently supported if user password is set")
		}
	} else {
		return nil, errors.New("application user authentication failed with given credentials")
	}
	token := &token.Token{
		UserID: &user.ID,
	}
	if !token.Vend() {
		var err error
		if len(token.Errors) > 0 {
			err = fmt.Errorf("failed to create token for application-authenticated user: %s; %s", *user.Email, *token.Errors[0].Message)
			common.Log.Warningf(err.Error())
		}
		return &AuthenticationResponse{
			User:  user.AsResponse(),
			Token: nil,
		}, err
	}
	return &AuthenticationResponse{
		User:  user.AsResponse(),
		Token: token.AsResponse(),
	}, nil
}

func (u *User) authenticate(password string) bool {
	if u.Password == nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(*u.Password), []byte(password)) == nil
}

// Create and persist a user
func (u *User) Create(createAuth0User bool) (bool, interface{}) {
	db := dbconf.DatabaseConnection()

	if !u.validate() {
		return false, nil
	}

	if db.NewRecord(u) {
		tx := db.Begin()
		result := tx.Create(&u)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				u.Errors = append(u.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
		if !db.NewRecord(u) {
			success := rowsAffected > 0
			if success {
				common.Log.Debugf("created user: %s", *u.Email)

				if createAuth0User {
					err := u.createAuth0User()
					if err != nil {
						u.Errors = append(u.Errors, &provide.Error{
							Message: common.StringOrNil(err.Error()),
						})
						tx.Rollback()
						return false, nil
					}
				}

				tx.Commit()
				if success && (u.ApplicationID == nil || *u.ApplicationID == uuid.Nil) {
					payload, _ := json.Marshal(u)
					natsutil.NatsPublish(natsSiaUserNotificationSubject, payload)
				}

				return success, &CreateResponse{
					User:  u.AsResponse(),
					Token: nil,
				}
			}
		}

		tx.Rollback()
	}

	return false, nil
}

// Update an existing user
func (u *User) Update() bool {
	db := dbconf.DatabaseConnection()

	if !u.validate() {
		return false
	}

	tx := db.Begin()
	result := tx.Save(&u)
	success := result.RowsAffected > 0
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			u.Errors = append(u.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}

	if success {
		err := u.updateAuth0User()
		if err != nil {
			u.Errors = append(u.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
			tx.Rollback()
			return false
		}
	}

	tx.Commit()
	return success
}

// createAuth0User attempts to create an associated auth0 user, passing through any ephemeral params
func (u *User) createAuth0User() error {
	params := u.EphemeralMetadata
	if params == nil {
		params = &EphemeralUserMetadata{
			Name:  u.Email,
			Email: *u.Email,
		}
	}

	if params.Email == "" {
		params.Email = *u.Email
	}

	if params.Password == nil {
		params.Password = common.StringOrNil(common.RandomString(20)) // require password reset
	}

	if params.AppMetadata == nil {
		params.AppMetadata = map[string]interface{}{}
	}
	params.AppMetadata[identUserIDKey] = u.ID

	err := createAuth0User(params)
	if err != nil {
		return fmt.Errorf("failed to create auth0 user: %s; %s", *u.Email, err.Error())
	}

	return nil
}

// updateAuth0User attempts to update the associated auth0 user, passing through any ephemeral params
func (u *User) updateAuth0User() error {
	params := u.EphemeralMetadata
	if params == nil {
		err := errors.New("not updating auth0 user without ephemeral params")
		common.Log.Debug(err.Error())
		return err
	}

	if params.AppMetadata == nil {
		params.AppMetadata = map[string]interface{}{}
	}
	params.AppMetadata[identUserIDKey] = u.ID

	// deep copy the params
	auth0Params := &EphemeralUserMetadata{}
	rawparams, _ := json.Marshal(params)
	json.Unmarshal(rawparams, &auth0Params)

	// enrich the user to make sure the proper auth0 id is used
	err := u.enrich()
	if err != nil {
		err := fmt.Errorf("failed to update auth0 user: %s; %s", *u.Email, err.Error())
		common.Log.Warning(err.Error())
		return err
	}

	err = updateAuth0User(*u.EphemeralMetadata.ID, auth0Params)
	if err != nil {
		err := fmt.Errorf("failed to update auth0 user: %s; %s", *u.Email, err.Error())
		common.Log.Warning(err.Error())
		return err
	}

	return nil
}

// deleteAuth0User attempts to delete the associated auth0 user
func (u *User) deleteAuth0User() error {
	err := deleteAuth0User(*u.Email)
	if err != nil {
		err := fmt.Errorf("failed to delete auth0 user: %s; %s", *u.Email, err.Error())
		common.Log.Warning(err.Error())
		return err
	}

	return nil
}

// enrich attempts to enrich the user with its associated auth0 user, enriching `u.EphemeralMetadata`
func (u *User) enrich() error {
	ephemeralParams, err := fetchAuth0User(*u.Email)
	if err != nil {
		common.Log.Warningf("failed to enrich auth0 user: %s; %s", *u.Email, err.Error())
		return err
	}
	if ephemeralParams.ID == nil {
		return fmt.Errorf("failed to enrich auth0 user: %s", *u.Email)
	}
	if ephemeralParams.AppMetadata != nil && ephemeralParams.AppMetadata[identUserIDKey] == nil {
		ephemeralParams.AppMetadata[identUserIDKey] = u.ID
	}
	u.EphemeralMetadata = ephemeralParams
	return nil
}

func (u *User) verifyEmailAddress() bool {
	var validEmailAddress bool
	if u.Email != nil {
		u.Email = common.StringOrNil(strings.ToLower(*u.Email))
		err := checkmail.ValidateFormat(*u.Email)
		validEmailAddress = err == nil
		if err != nil {
			u.Errors = append(u.Errors, &provide.Error{
				Message: common.StringOrNil(fmt.Sprintf("invalid email address: %s; %s", *u.Email, err.Error())),
			})
		}

		if common.PerformEmailVerification {
			common.Log.Debugf("attempting to verify deliverability for email address: %s", *u.Email)

			var emailVerificationErr error
			emailVerifier := trumail.NewVerifier(common.EmailVerificationFromDomain, common.EmailVerificationFromAddress, common.EmailVerificationTimeout, common.EmailVerificationAttempts)
			lookup, err := emailVerifier.Verify(*u.Email)
			if err != nil {
				validEmailAddress = false
				emailVerificationErr = fmt.Errorf("email address verification failed: %s; %s", *u.Email, err.Error())
			} else if !lookup.Deliverable && !lookup.CatchAll {
				validEmailAddress = false
				emailVerificationErr = fmt.Errorf("email address verification failed: %s; undeliverable", *u.Email)
			} else if lookup.CatchAll {
				validEmailAddress = false
				emailVerificationErr = fmt.Errorf("email address verification failed: %s; mail server exists but inbox is invalid", *u.Email)
			} else {
				validEmailAddress = lookup.Deliverable
				if !validEmailAddress {
					emailVerificationErr = fmt.Errorf("email address verification failed: %s; undeliverable", *u.Email)
				}
			}

			if emailVerificationErr != nil {
				u.Errors = append(u.Errors, &provide.Error{
					Message: common.StringOrNil(emailVerificationErr.Error()),
				})
			}
		}
	}
	return validEmailAddress
}

// validate a user for persistence
func (u *User) validate() bool {
	u.Errors = make([]*provide.Error, 0)
	db := dbconf.DatabaseConnection()
	if db.NewRecord(u) {
		if u.Password != nil || u.ApplicationID == nil {
			u.verifyEmailAddress()
			u.rehashPassword()
		}
		if u.Permissions == 0 {
			u.Permissions = common.DefaultUserPermission
		}
	}
	return len(u.Errors) == 0
}

func (u *User) rehashPassword() {
	if u.Password != nil {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*u.Password), bcrypt.DefaultCost)
		if err != nil {
			u.Password = nil
			u.Errors = append(u.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		} else {
			u.Password = common.StringOrNil(string(hashedPassword))
			u.ResetPasswordToken = nil
		}
	} else {
		u.Errors = append(u.Errors, &provide.Error{
			Message: common.StringOrNil("invalid password"),
		})
	}
}

// Delete a user
func (u *User) Delete() bool {
	db := dbconf.DatabaseConnection()
	tx := db.Begin()
	result := tx.Delete(&u)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			u.Errors = append(u.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}
	success := len(u.Errors) == 0
	if success {
		common.Log.Debugf("deleted user: %s", *u.Email)
		err := u.deleteAuth0User()
		if err != nil {
			u.Errors = append(u.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
			tx.Rollback()
			return false
		}
	}
	tx.Commit()
	return success
}

// AsResponse marshals a user into a user response
func (u *User) AsResponse() *Response {
	return &Response{
		ID:        u.ID,
		CreatedAt: u.CreatedAt,
		Name:      *u.Name,
		Email:     *u.Email,
		Metadata:  u.EphemeralMetadata,
	}
}

// CreateResetPasswordToken creates a reset password token
func (u *User) CreateResetPasswordToken(db *gorm.DB) bool {
	issuedAt := time.Now()
	tokenID, err := uuid.NewV4()
	if err != nil {
		common.Log.Warningf("failed to generate reset password JWT token; %s", err.Error())
		return false
	}
	claims := map[string]interface{}{
		"jti": tokenID,
		"exp": issuedAt.Add(defaultResetPasswordTokenTimeout).Unix(),
		"iat": issuedAt.Unix(),
		"sub": fmt.Sprintf("user:%s", u.ID.String()),
		"data": map[string]interface{}{
			"name": u.Name,
		},
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	token, err := jwtToken.SignedString([]byte{})
	if err != nil {
		common.Log.Warningf("failed to sign reset password JWT token; %s", err.Error())
		return false
	}

	u.ResetPasswordToken = common.StringOrNil(token)

	result := db.Save(u)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			u.Errors = append(u.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
		return false
	}
	return true
}

// ResetPasswordTokenResponse marshals a reset password token response
func (u *User) ResetPasswordTokenResponse() map[string]interface{} {
	return map[string]interface{}{
		"reset_password_token": u.ResetPasswordToken,
	}
}
