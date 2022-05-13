/*
 * Copyright 2017-2022 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package common

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/provideplatform/provide-go/api/ident"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

// IsAuth0 returns true if the given request is from an auth0-whitelisted IP address
func IsAuth0(c *gin.Context) bool {
	ip := c.ClientIP()
	for _, whitelistedIP := range Auth0WhitelistedIPs {
		if ip == whitelistedIP {
			return true
		}
	}
	return false
}

// IsBanned returns true if the given request is from a banned IP address
func IsBanned(c *gin.Context) bool {
	ip := c.ClientIP()
	for _, bannedIP := range BannedIPs {
		if ip == bannedIP {
			return true
		}
	}
	return false
}

// PanicIfEmpty panics if the given string is empty
func PanicIfEmpty(val string, msg string) {
	if val == "" {
		panic(msg)
	}
}

// StringOrNil returns the given string or nil when empty
func StringOrNil(str string) *string {
	if str == "" {
		return nil
	}
	return &str
}

// RandomString generates a random string of the given length
func RandomString(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

// ResolveJWKs resolves the configured JWKs for the environment
func ResolveJWKs() ([]*ident.JSONWebKey, error) {
	jwks := make([]*ident.JSONWebKey, 0)
	for kid := range JWTKeypairs {
		keypair := JWTKeypairs[kid]

		var publicKey string
		if keypair.VaultKey != nil && keypair.VaultKey.PublicKey != nil {
			publicKey = *keypair.VaultKey.PublicKey
		} else if keypair.PublicKeyPEM != nil {
			publicKey = *keypair.PublicKeyPEM
		}

		jwks = append(jwks, &ident.JSONWebKey{
			E:           fmt.Sprintf("%X", keypair.PublicKey.E),
			Fingerprint: keypair.Fingerprint,
			Kid:         kid,
			N:           keypair.PublicKey.N.String(),
			PublicKey:   publicKey,
		})
	}

	return jwks, nil
}

// SHA256 is a convenience method to return the sha256 hash of the given input
func SHA256(str string) string {
	digest := sha256.New()
	digest.Write([]byte(str))
	return hex.EncodeToString(digest.Sum(nil))
}
