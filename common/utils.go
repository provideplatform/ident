package common

import (
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"time"

	"github.com/gin-gonic/gin"
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

// SHA256 is a convenience method to return the sha256 hash of the given input
func SHA256(str string) string {
	digest := sha256.New()
	digest.Write([]byte(str))
	return hex.EncodeToString(digest.Sum(nil))
}
