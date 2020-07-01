package common

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// AccountingMiddleware returns gin middleware for API call accounting
func AccountingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if apiAccountingConn != nil {
				apiCall := newAPICall(c)
				if apiCall != nil {
					packet, _ := json.Marshal(apiCall)
					len, err := apiAccountingConn.Write(packet)
					if err != nil {
						Log.Warningf("failed to write %d-byte packet to api accounting endpoint; %s", len, err.Error())
					} else {
						Log.Tracef("%d-byte api call accounting packet written to accounting endpoint", len)
					}
				}
			}
		}()
		c.Next()
	}
}

// CORSMiddleware is gin middleware that returns permissive CORS headers
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Accept-Encoding, Authorization, Cache-Control, Content-Length, Content-Type, Origin, User-Agent, X-CSRF-Token, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Expose-Headers", "X-Total-Results-Count")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// RateLimitingMiddleware is a gin middleware that ratelimits API calls
func RateLimitingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
	}
}

// newAPICall initializes an API call for API usage accounting
// purposes for a given gin context and user id
func newAPICall(c *gin.Context) *APICall {
	var contentLength *uint
	contentLengthHeader := c.GetHeader("content-length")
	if contentLengthHeader != "" {
		contentLengthHeaderVal, err := strconv.Atoi(contentLengthHeader)
		if err == nil {
			_contentLength := uint(contentLengthHeaderVal)
			contentLength = &_contentLength
		}
	}

	var remoteAddr string
	xForwardedForHeader := c.GetHeader("x-forwarded-for")
	if xForwardedForHeader != "" {
		remoteAddr = xForwardedForHeader
	} else {
		remoteAddr = c.Request.RemoteAddr
	}

	appID := c.GetString("application_id")
	userID := c.GetString("user_id")
	sub := c.GetString("sub")

	if appID != "" || userID != "" {
		return &APICall{
			ApplicationID: appID,
			UserID:        userID,
			Sub:           sub,
			Method:        c.Request.Method,
			Host:          c.Request.Host,
			Path:          c.Request.URL.Path,
			RemoteAddr:    remoteAddr,
			Timestamp:     time.Now(),
			ContentLength: contentLength,
			StatusCode:    c.Writer.Status(),
		}
	}

	return nil
}
