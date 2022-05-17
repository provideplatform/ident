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
	"encoding/json"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/provideplatform/ident/common"
)

// InContext returns the previously authorized token instance in
// the given gin context, if one exists; this me`thod does not
// attempt to re-authorize the context
func InContext(c *gin.Context) *Token {
	if tok, exists := c.Get(contextTokenKey); exists {
		if token, tokenOk := tok.(*Token); tokenOk {
			return token
		}
	}
	return nil
}

func parseJWTTimestampClaim(claims jwt.MapClaims, claim string) *time.Time {
	var retval *time.Time
	switch timeclaim := claims[claim].(type) {
	case float64:
		timeval := time.Unix(int64(timeclaim), 0)
		retval = &timeval
	case json.Number:
		val, _ := timeclaim.Int64()
		timeval := time.Unix(val, 0)
		retval = &timeval
	default:
		common.Log.Warningf("failed to parse bearer authorization timestamp claim: %s", claim)
		return nil
	}
	return retval
}
