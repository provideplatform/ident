package token

import (
	"fmt"

	prvdcommon "github.com/provideservices/provide-go/common"
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
		Audience: &prvdcommon.JWTNatsAuthorizationAudience,
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
