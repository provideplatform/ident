// +build integration

package integration

import (
	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideservices/provide-go/api/ident"
)

type User struct {
	firstName string
	lastName  string
	email     string
	password  string
}

type Application struct {
	name        string
	description string
}

type Organization struct {
	name        string
	description string
}

func userFactory(firstName, lastName, email, password string) (*provide.User, error) {
	return provide.CreateUser("", map[string]interface{}{
		"first_name": firstName,
		"last_name":  lastName,
		"email":      email,
		"password":   password,
	})
}

func orgTokenFactory(auth string, organizationID uuid.UUID) (*provide.Token, error) {
	return provide.CreateToken(auth, map[string]interface{}{
		"organization_id": organizationID,
	})
}

func appTokenFactory(auth string, applicationID uuid.UUID) (*provide.Token, error) {
	return provide.CreateToken(auth, map[string]interface{}{
		"application_id": applicationID,
	})
}
