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
	"encoding/json"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

const defaultAccessControlAllowCredentials = "true"
const defaultAccessControlAllowOrigin = "*"
const defaultAccessControlAllowHeaders = "Accept, Accept-Encoding, Authorization, Cache-Control, Content-Length, Content-Type, Origin, User-Agent, X-CSRF-Token, X-Requested-With"
const defaultAccessControlAllowMethods = "GET, POST, PUT, DELETE, OPTIONS"
const defaultAccessControlExposeHeaders = "X-Total-Results-Count"

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
		c.Writer.Header().Set("Access-Control-Allow-Origin", defaultAccessControlAllowOrigin)
		c.Writer.Header().Set("Access-Control-Allow-Credentials", defaultAccessControlAllowCredentials)
		c.Writer.Header().Set("Access-Control-Allow-Headers", defaultAccessControlAllowHeaders)
		c.Writer.Header().Set("Access-Control-Allow-Methods", defaultAccessControlAllowMethods)
		c.Writer.Header().Set("Access-Control-Expose-Headers", defaultAccessControlExposeHeaders)

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

	var userAgent string
	userAgentHeader := c.GetHeader("user-agent")
	if userAgentHeader != "" {
		userAgent = userAgentHeader
	}

	appID := c.GetString("application_id")
	userID := c.GetString("user_id")
	orgID := c.GetString("organization_id")

	if appID != "" || userID != "" || orgID != "" {
		return &APICall{
			ApplicationID:  appID,
			UserID:         userID,
			OrganizationID: orgID,
			Method:         c.Request.Method,
			Host:           c.Request.Host,
			Path:           c.Request.URL.Path,
			RemoteAddr:     remoteAddr,
			Timestamp:      time.Now(),
			ContentLength:  contentLength,
			StatusCode:     c.Writer.Status(),
			UserAgent:      StringOrNil(userAgent),
		}
	}

	return nil
}
