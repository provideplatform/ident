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

package token

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/provideplatform/ident/common"
	provide "github.com/provideplatform/provide-go/common"
)

const contextApplicationIDKey = "application_id"
const contextOrganizationIDKey = "organization_id"
const contextPermissionsKey = "permissions"
const contextSubjectKey = "sub"
const contextTokenKey = "token"
const contextUserIDKey = "user_id"

// AuthMiddleware returns gin middleware for API call authentication and authorization
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := authorize(c)
		if common.IsAuth0(c) {
			common.Log.Debugf("authorizing request by whitelisted auth0 IP address")
			if token == nil {
				token = &Token{}
			}
			token.Permissions = common.DefaultAuth0RequestPermission
		}

		if common.IsBanned(c) {
			provide.RenderError(common.BannedErrorMessage, 429, c)
			return
		} else if token != nil && (token.UserID != nil || token.ApplicationID != nil || token.OrganizationID != nil || token.HasPermission(common.DefaultAuth0RequestPermission)) {
			c.Set(contextSubjectKey, token.Subject)
			c.Set(contextTokenKey, token)
			c.Set(contextPermissionsKey, token.Permissions)

			if token.ApplicationID != nil {
				c.Set(contextApplicationIDKey, token.ApplicationID.String())
			}
			if token.OrganizationID != nil {
				c.Set(contextOrganizationIDKey, token.OrganizationID.String())
			}
			if token.UserID != nil {
				c.Set(contextUserIDKey, token.UserID.String())
			}
		} else {
			provide.RenderError("unauthorized", 401, c)
			c.Abort()
			return
		}
		c.Next()
	}
}

// authorize is a convenience method to parse the presented bearer authorization
// header from the provided context and resolve it to a token instance; if the
// given bearer token is a valid, non-expired JWT, the returned Token instance
// is ephemeral. If the authorization attempt fails, nil is returned.
func authorize(c *gin.Context) *Token {
	authorization := strings.Split(c.GetHeader("authorization"), "Bearer ")
	if len(authorization) < 2 {
		authorization = strings.Split(c.GetHeader("authorization"), "bearer ")
	}
	token, err := Parse(authorization[len(authorization)-1])
	if err != nil {
		common.Log.Tracef("bearer token authorization failed; %s", err.Error())
		return nil
	}
	if token.UserID == nil && token.ApplicationID == nil && token.OrganizationID == nil && !token.IsRefreshToken {
		subject := "< not provided >"
		if token.Subject != nil {
			subject = fmt.Sprintf("%s", *token.Subject)
		}
		common.Log.Tracef("bearer token authorization failed; invalid authorization subject: %s", subject)
		return nil
	}
	return token
}
