package main

import provide "github.com/provideservices/provide-go"

// Sia client
type Sia struct {
	provide.APIClient
}

// InitSia convenience method
func InitSia(token string) *Sia {
	return &Sia{
		provide.APIClient{
			Host:   "sia.provide.services",
			Path:   "api",
			Scheme: "https",
			Token:  stringOrNil(token),
		},
	}
}

// CreateSiaAccount creates an account in sia for the platform user
func CreateSiaAccount(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitSia(token).Post("accounts", params)
}
