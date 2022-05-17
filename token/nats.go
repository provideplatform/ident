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

	prvdcommon "github.com/provideplatform/provide-go/common"
	util "github.com/provideplatform/provide-go/common/util"
)

// VendNatsBearerAuthorization vends a signed NATS authorization on behalf of the caller
func VendNatsBearerAuthorization(
	subject string,
	publishAllow,
	publishDeny,
	subscribeAllow,
	subscribeDeny []string,
	responsesMax,
	responsesTTL *int,
) (*Token, error) {
	token := &Token{
		Audience: &util.JWTNatsAuthorizationAudience,
		Subject:  &subject,
		NatsClaims: map[string]interface{}{
			"permissions": map[string]interface{}{
				"publish": map[string]interface{}{
					"allow": publishAllow,
					"deny":  publishDeny,
				},
				"subscribe": map[string]interface{}{
					"allow": subscribeAllow,
					"deny":  subscribeDeny,
				},
				"responses": map[string]interface{}{
					"max": responsesMax,
					"ttl": responsesTTL,
				},
			},
		},
	}
	if !token.Vend() {
		var err error
		if len(token.Errors) > 0 {
			err = fmt.Errorf("failed to vend NATS bearer JWT token; %s", *token.Errors[0].Message)
			prvdcommon.Log.Warningf(err.Error())
		}
		return nil, err
	}
	return token, nil
}
