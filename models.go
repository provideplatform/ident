package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/badoux/checkmail"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

type Model struct {
	Id        uuid.UUID `sql:"primary_key;type:uuid;default:uuid_generate_v4()" json:"id"`
	CreatedAt time.Time `sql:"not null" json:"created_at"`
	Errors    []*Error  `gorm:"-" json:"-"`
}

type Error struct {
	Message *string `json:"message"`
	Status  *int    `json:"status"`
}

type Application struct {
	Model
	UserId      uuid.UUID        `sql:"type:uuid not null" json:"user_id"`
	Name        *string          `sql:"not null" json:"name"`
	Description *string          `json:"description"`
	Config      *json.RawMessage `sql:"type:json" json:"config"`
}

type Token struct {
	Model
	IssuedAt      *time.Time       `sql:"not null" json:"issued_at"`
	ExpiresAt     *time.Time       `json:"expires_at"`
	Secret        *string          `sql:"not null" json:"secret"`
	Token         *string          `json:"token"` // JWT https://tools.ietf.org/html/rfc7519
	ApplicationId *uuid.UUID       `sql:"type:uuid" json:"-"`
	UserId        *uuid.UUID       `sql:"type:uuid" json:"-"`
	Data          *json.RawMessage `sql:"-" json:"data"`
}

type User struct {
	Model
	ApplicationId *uuid.UUID `sql:"type:uuid" json:"-"`
	Name          *string    `sql:"not null" json:"name"`
	Email         *string    `sql:"not null" json:"email"`
	Password      *string    `sql:"not null" json:"password"`
}

type TokenResponse struct {
	Id     uuid.UUID `json:"id"`
	Secret string    `json:"secret"`
	Token  string    `json:"token"`
}

type UserResponse struct {
	Id        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
}

type UserAuthenticationResponse struct {
	User  *UserResponse  `json:"user"`
	Token *TokenResponse `json:"token"`
}

// application

func (app *Application) CreateToken() (*Token, error) {
	token := &Token{
		ApplicationId: &app.Id,
	}
	if !token.Create() {
		if len(token.Errors) > 0 {
			return nil, fmt.Errorf("Failed to create token for application: %s; %s", app.Id.String(), *token.Errors[0].Message)
		}
	}
	return token, nil
}

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
				app.Errors = append(app.Errors, &Error{
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

func (app *Application) Validate() bool {
	app.Errors = make([]*Error, 0)
	return len(app.Errors) == 0
}

func (app *Application) Delete() bool {
	db := DatabaseConnection()
	result := db.Delete(app)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			app.Errors = append(app.Errors, &Error{
				Message: stringOrNil(err.Error()),
			})
		}
	}
	return len(app.Errors) == 0
}

// token

func (t *Token) GetApplication() *Application {
	var app = &Application{}
	DatabaseConnection().Model(t).Related(&app)
	if app.Id == uuid.Nil {
		return nil
	}
	return app
}

func (t *Token) GetUser() *User {
	var user = &User{}
	DatabaseConnection().Model(t).Related(&user)
	if user.Id == uuid.Nil {
		return nil
	}
	return user
}

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
				t.Errors = append(t.Errors, &Error{
					Message: stringOrNil(err.Error()),
				})
			}
		}
		if !db.NewRecord(t) {
			if rowsAffected > 0 {
				var err error
				t.Token, err = t.encodeJWT()
				if err != nil {
					t.Errors = append(t.Errors, &Error{
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
	if t.ApplicationId != nil {
		sub = fmt.Sprintf("application:%s", t.ApplicationId.String())
	} else if t.UserId != nil {
		sub = fmt.Sprintf("user:%s", t.UserId.String())
	}

	var exp *int64
	if t.ExpiresAt != nil {
		expAt := t.ExpiresAt.Unix()
		exp = &expAt
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.MapClaims{
		"jti":  t.Id.String(),
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

func (t *Token) Validate() bool {
	t.Errors = make([]*Error, 0)
	db := DatabaseConnection()
	if db.NewRecord(t) {
		if t.ApplicationId != nil && t.UserId != nil {
			t.Errors = append(t.Errors, &Error{
				Message: stringOrNil("ambiguous token subject"),
			})
		}
		if t.IssuedAt != nil {
			t.Errors = append(t.Errors, &Error{
				Message: stringOrNil("token must not attempt assert iat JWT claim"),
			})
		} else {
			iat := time.Now()
			t.IssuedAt = &iat
			if t.ExpiresAt != nil && t.ExpiresAt.Before(*t.IssuedAt) {
				t.Errors = append(t.Errors, &Error{
					Message: stringOrNil("token expiration must not preceed issuance"),
				})
			}
		}
		if t.Secret != nil {
			t.Errors = append(t.Errors, &Error{
				Message: stringOrNil("token secret must not be supplied; it must be generated at this time"),
			})
		} else {
			uuidV4, err := uuid.NewV4()
			if err == nil {
				t.Secret = stringOrNil(uuidV4.String())
			} else {
				t.Errors = append(t.Errors, &Error{
					Message: stringOrNil(fmt.Sprintf("token secret generation failed; %s", err.Error())),
				})
			}
		}
	}
	return len(t.Errors) == 0
}

func (t *Token) Delete() bool {
	db := DatabaseConnection()
	result := db.Delete(t)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			t.Errors = append(t.Errors, &Error{
				Message: stringOrNil(err.Error()),
			})
		}
	}
	return len(t.Errors) == 0
}

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

func (t *Token) AsResponse() *TokenResponse {
	return &TokenResponse{
		Id:     t.Id,
		Secret: string(*t.Secret),
		Token:  string(*t.Token),
	}
}

// user

func AuthenticateUser(email string, password string) (*UserAuthenticationResponse, error) {
	var user = &User{}
	db := DatabaseConnection()
	db.Where("email = ?", strings.ToLower(email)).First(&user)
	if user != nil && user.Id != uuid.Nil {
		if !user.authenticate(password) {
			return nil, errors.New("authentication failed with given credentials")
		}
	} else {
		return nil, fmt.Errorf("invalid email")
	}
	token := &Token{
		UserId: &user.Id,
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

func (u *User) Applications() []Application {
	var apps []Application
	DatabaseConnection().Where("user_id = ?", u.Id).Find(&apps)
	return apps
}

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
				u.Errors = append(u.Errors, &Error{
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

func (u *User) Validate() bool {
	u.Errors = make([]*Error, 0)
	db := DatabaseConnection()
	if db.NewRecord(u) {
		if u.Email != nil {
			u.Email = stringOrNil(strings.ToLower(*u.Email))
			err := checkmail.ValidateFormat(*u.Email)
			if err != nil {
				u.Errors = append(u.Errors, &Error{
					Message: stringOrNil(err.Error()),
				})
			}
		}
		if u.Password != nil {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*u.Password), bcrypt.DefaultCost)
			if err != nil {
				u.Password = nil
				u.Errors = append(u.Errors, &Error{
					Message: stringOrNil(err.Error()),
				})
			} else {
				u.Password = stringOrNil(string(hashedPassword))
			}
		} else {
			u.Errors = append(u.Errors, &Error{
				Message: stringOrNil("invalid password"),
			})
		}
	}
	return len(u.Errors) == 0
}

func (u *User) Delete() bool {
	db := DatabaseConnection()
	result := db.Delete(u)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			u.Errors = append(u.Errors, &Error{
				Message: stringOrNil(err.Error()),
			})
		}
	}
	return len(u.Errors) == 0
}

func (u *User) AsResponse() *UserResponse {
	return &UserResponse{
		Id:        u.Id,
		CreatedAt: u.CreatedAt,
		Name:      *u.Name,
		Email:     *u.Email,
	}
}
