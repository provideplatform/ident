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
	uuid "github.com/kthomas/go.uuid"
	trumail "github.com/kthomas/trumail/verifier"
	"github.com/provideapp/ident/common"
	"github.com/provideapp/ident/token"
	provide "github.com/provideservices/provide-go"
	"golang.org/x/crypto/bcrypt"
)

const defaultResetPasswordTokenTimeout = time.Hour * 1
const natsSiaUserNotificationSubject = "sia.user.notification"

func init() {
	db := dbconf.DatabaseConnection()

	db.AutoMigrate(&User{})
	db.Model(&User{}).AddIndex("idx_users_application_id", "application_id")
	db.Model(&User{}).AddIndex("idx_users_email", "email")
	db.Model(&User{}).AddUniqueIndex("idx_users_application_id_email", "application_id", "email")
	db.Model(&User{}).AddForeignKey("application_id", "applications(id)", "SET NULL", "CASCADE")
}

// User model
type User struct {
	provide.Model
	ApplicationID          *uuid.UUID `sql:"type:uuid" json:"-"`
	Name                   *string    `sql:"not null" json:"name"`
	Email                  *string    `sql:"not null" json:"email"`
	Password               *string    `json:"-"`
	PrivacyPolicyAgreedAt  *time.Time `json:"privacy_policy_agreed_at"`
	TermsOfServiceAgreedAt *time.Time `json:"terms_of_service_agreed_at"`
	ResetPasswordToken     *string    `json:"-"`
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
	User  *UserResponse        `json:"user"`
	Token *token.TokenResponse `json:"token"`
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

// AuthenticateUser attempts to authenticate by email address and password
func AuthenticateUser(email, password string, applicationID *uuid.UUID) (*UserAuthenticationResponse, error) {
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
	}
	if !token.Create() {
		var err error
		if len(token.Errors) > 0 {
			err = fmt.Errorf("Failed to create token for authenticated user: %s; %s", *user.Email, *token.Errors[0].Message)
			common.Log.Warningf(err.Error())
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

// AuthenticateApplicationUser creates a user token on behalf of the owning application
func AuthenticateApplicationUser(email string, applicationID uuid.UUID) (*UserAuthenticationResponse, error) {
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
	if !token.Create() {
		var err error
		if len(token.Errors) > 0 {
			err = fmt.Errorf("Failed to create token for application-authenticated user: %s; %s", *user.Email, *token.Errors[0].Message)
			common.Log.Warningf(err.Error())
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
	if u.Password == nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(*u.Password), []byte(password)) == nil
}

// Create and persist a user
func (u *User) Create() bool {
	db := dbconf.DatabaseConnection()

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
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
		if !db.NewRecord(u) {
			success := rowsAffected > 0
			if success && (u.ApplicationID == nil || *u.ApplicationID == uuid.Nil) {
				payload, _ := json.Marshal(u)
				common.NATSPublish(natsSiaUserNotificationSubject, payload)
			}
			return success
		}
	}
	return false
}

// Update an existing user
func (u *User) Update() bool {
	db := dbconf.DatabaseConnection()

	if !u.Validate() {
		return false
	}

	result := db.Save(&u)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			u.Errors = append(u.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}

	return len(u.Errors) == 0
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
			common.Log.Debugf("Attempting to verify deliverability for email address: %s", *u.Email)

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

// Validate a user for persistence
func (u *User) Validate() bool {
	u.Errors = make([]*provide.Error, 0)
	db := dbconf.DatabaseConnection()
	if db.NewRecord(u) {
		if u.Password != nil || u.ApplicationID == nil {
			u.verifyEmailAddress()
			u.rehashPassword()
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
	result := db.Delete(u)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			u.Errors = append(u.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
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

// CreateResetPasswordToken creates a reset password token
func (u *User) CreateResetPasswordToken(db *gorm.DB) bool {
	issuedAt := time.Now()
	tokenID, err := uuid.NewV4()
	if err != nil {
		common.Log.Warningf("Failed to generate reset password JWT token; %s", err.Error())
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
		common.Log.Warningf("Failed to sign reset password JWT token; %s", err.Error())
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
