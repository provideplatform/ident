// +build integration

package test

import (
	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideservices/provide-go/api/ident"
)

func userFactory(firstName, lastName, email, password string) (*provide.User, error) {
	user, err := provide.CreateUser("", map[string]interface{}{
		"first_name": firstName,
		"last_name":  lastName,
		"email":      email,
		"password":   password,
	})

	return user, err
}

func orgTokenFactory(auth string, organizationID uuid.UUID) (*provide.Token, error) {

	token, err := provide.CreateToken(auth, map[string]interface{}{
		"organization_id": organizationID,
	})
	return token, err
}

func appTokenFactory(auth string, applicationID uuid.UUID) (*provide.Token, error) {

	token, err := provide.CreateToken(auth, map[string]interface{}{
		"application_id": applicationID,
	})
	return token, err
}
