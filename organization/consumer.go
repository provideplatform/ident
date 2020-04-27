package organization

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/provideservices/provide-go"

	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	stan "github.com/nats-io/stan.go"
	"github.com/provideapp/ident/common"
	"github.com/provideapp/ident/token"
	"github.com/provideapp/ident/vault"
)

const natsCreatedOrganizationCreatedSubject = "ident.organization.created"
const natsCreatedOrganizationCreatedMaxInFlight = 2048
const createOrganizationAckWait = time.Second * 5
const createOrganizationTimeout = int64(time.Second * 20)

const natsOrganizationImplicitKeyExchangeCompleteSubject = "ident.organization.keys.exchange.complete"
const natsOrganizationImplicitKeyExchangeCompleteMaxInFlight = 2048
const natsOrganizationImplicitKeyExchangeCompleteAckWait = time.Second * 5
const organizationImplicitKeyExchangeCompleteTimeout = int64(time.Second * 20)

const natsOrganizationImplicitKeyExchangeInitSubject = "ident.organization.keys.exchange.init"
const natsOrganizationImplicitKeyExchangeMaxInFlight = 2048
const natsOrganizationImplicitKeyExchangeInitAckWait = time.Second * 5
const organizationImplicitKeyExchangeInitTimeout = int64(time.Second * 20)

const natsOrganizationRegistrationSubject = "ident.organization.registration"
const natsOrganizationRegistrationMaxInFlight = 2048
const natsOrganizationRegistrationAckWait = time.Second * 30
const organizationRegistrationTimeout = int64(natsOrganizationRegistrationAckWait * 3)
const organizationRegistrationMethod = "registerOrg"

const natsSiaOrganizationNotificationSubject = "sia.organization.notification"

func init() {
	if !common.ConsumeNATSStreamingSubscriptions {
		common.Log.Debug("organization package consumer configured to skip NATS streaming subscription setup")
		return
	}

	natsutil.EstablishSharedNatsStreamingConnection(nil)

	var waitGroup sync.WaitGroup

	createNatsOrganizationCreatedSubscriptions(&waitGroup)
	createNatsOrganizationImplicitKeyExchangeCompleteSubscriptions(&waitGroup)
	createNatsOrganizationImplicitKeyExchangeSubscriptions(&waitGroup)
	createNatsOrganizationRegistrationSubscriptions(&waitGroup)
}

func createNatsOrganizationCreatedSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			createOrganizationAckWait,
			natsCreatedOrganizationCreatedSubject,
			natsCreatedOrganizationCreatedSubject,
			consumeCreatedOrganizationMsg,
			createOrganizationAckWait,
			natsCreatedOrganizationCreatedMaxInFlight,
			nil,
		)
	}
}

func createNatsOrganizationImplicitKeyExchangeCompleteSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			natsOrganizationImplicitKeyExchangeCompleteAckWait,
			natsOrganizationImplicitKeyExchangeCompleteSubject,
			natsOrganizationImplicitKeyExchangeCompleteSubject,
			consumeOrganizationImplicitKeyExchangeCompleteMsg,
			natsOrganizationImplicitKeyExchangeCompleteAckWait,
			natsOrganizationImplicitKeyExchangeCompleteMaxInFlight,
			nil,
		)
	}
}

func createNatsOrganizationImplicitKeyExchangeSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			natsOrganizationImplicitKeyExchangeInitAckWait,
			natsOrganizationImplicitKeyExchangeInitSubject,
			natsOrganizationImplicitKeyExchangeInitSubject,
			consumeOrganizationImplicitKeyExchangeInitMsg,
			natsOrganizationImplicitKeyExchangeInitAckWait,
			natsOrganizationImplicitKeyExchangeMaxInFlight,
			nil,
		)
	}
}

func createNatsOrganizationRegistrationSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			natsOrganizationRegistrationAckWait,
			natsOrganizationRegistrationSubject,
			natsOrganizationRegistrationSubject,
			consumeOrganizationRegistrationMsg,
			natsOrganizationRegistrationAckWait,
			natsOrganizationRegistrationMaxInFlight,
			nil,
		)
	}
}

func consumeCreatedOrganizationMsg(msg *stan.Msg) {
	defer func() {
		if r := recover(); r != nil {
			natsutil.AttemptNack(msg, createOrganizationTimeout)
		}
	}()

	common.Log.Debugf("consuming %d-byte NATS created organization message on subject: %s", msg.Size(), msg.Subject)

	params := map[string]interface{}{}
	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to unmarshal organization created message; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	organizationID, organizationIDOk := params["organization_id"].(string)
	if !organizationIDOk {
		common.Log.Warning("failed to unmarshal organization_id during created message handler")
		natsutil.Nack(msg)
		return
	}

	db := dbconf.DatabaseConnection()

	organization := &Organization{}
	db.Where("id = ?", organizationID).Find(&organization)

	if organization == nil || organization.ID == uuid.Nil {
		common.Log.Warningf("failed to resolve organization during created message handler; organization id: %s", organizationID)
		natsutil.AttemptNack(msg, createOrganizationTimeout)
		return
	}

	vault, err := organization.createVault(db)
	if err == nil {
		common.Log.Debugf("Created default vault for organization: %s", *organization.Name)
		msg.Ack()
	} else {
		common.Log.Warningf("Failed to create default vault for organization: %s; %s", *organization.Name, *vault.Errors[0].Message)
		natsutil.AttemptNack(msg, createOrganizationTimeout)
	}
}

func consumeOrganizationImplicitKeyExchangeInitMsg(msg *stan.Msg) {
	defer func() {
		if r := recover(); r != nil {
			natsutil.AttemptNack(msg, organizationImplicitKeyExchangeInitTimeout)
		}
	}()

	common.Log.Debugf("consuming %d-byte NATS organization implicit key exchange message on subject: %s", msg.Size(), msg.Subject)

	params := map[string]interface{}{}
	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to unmarshal organization implicit key exchange message; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	organizationID, organizationIDOk := params["organization_id"].(string)
	if !organizationIDOk {
		common.Log.Warning("failed to parse organization_id during implicit key exchange message handler")
		natsutil.Nack(msg)
		return
	}

	peerOrganizationID, peerOrganizationIDOk := params["peer_organization_id"].(string)
	if !peerOrganizationIDOk {
		common.Log.Warning("failed to parse peer_organization_id during implicit key exchange message handler")
		natsutil.Nack(msg)
		return
	}

	db := dbconf.DatabaseConnection()

	organization := &Organization{}
	db.Where("id = ?", organizationID).Find(&organization)

	if organization == nil || organization.ID == uuid.Nil {
		common.Log.Warningf("failed to resolve organization during implicit key exchange message handler; organization id: %s", organizationID)
		natsutil.AttemptNack(msg, organizationImplicitKeyExchangeInitTimeout)
		return
	}

	var vaults []*vault.Vault
	db.Where("vaults.organization_id = ?", organization.ID).Find(&vaults)

	if len(vaults) == 1 {
		orgVault := vaults[0]
		var signingKeys []*vault.Key
		var signingKey *vault.Key

		orgVault.ListKeysQuery(db).Find(&signingKeys)
		for _, key := range signingKeys {
			if key.Name != nil && strings.ToLower(*key.Name) == "ekho signing" { // FIXME
				signingKey = key
				break
			}
		}

		if signingKey != nil {
			c25519Key, err := orgVault.CreateC25519Keypair(
				"ekho single-use c25519 key exchange",
				fmt.Sprintf("ekho - single-use c25519 key exchange with peer organization: %s", peerOrganizationID),
				true,
			)
			if err != nil {
				common.Log.Warningf("failed to generate single-use c25519 public key for implicit key exchange; organization id: %s; %s", organizationID, err.Error())
				natsutil.AttemptNack(msg, organizationImplicitKeyExchangeInitTimeout)
			}

			c25519PublicKeyRaw, err := hex.DecodeString(*c25519Key.PublicKey)
			c25519PublicKeySigned, err := signingKey.Sign(c25519PublicKeyRaw)
			if err != nil {
				common.Log.Warningf("failed to sign single-use c25519 public key for implicit key exchange; organization id: %s; %s", organizationID, err.Error())
				natsutil.AttemptNack(msg, organizationImplicitKeyExchangeInitTimeout)
			}
			common.Log.Debugf("generated %d-byte signature using Ed25519 signing key", len(c25519PublicKeySigned))

			payload, _ := json.Marshal(map[string]interface{}{
				"organization_id":      organizationID,
				"peer_organization_id": peerOrganizationID,
				"public_key":           *c25519Key.PublicKey,
				"signature":            hex.EncodeToString(c25519PublicKeySigned),
				"signing_key":          *signingKey.PublicKey,
				"signing_spec":         *signingKey.Spec,
			})
			natsutil.NatsStreamingPublish(natsOrganizationImplicitKeyExchangeCompleteSubject, payload)

			common.Log.Debugf("published %s implicit key exchange message for peer organization id: %s", natsOrganizationImplicitKeyExchangeCompleteSubject, peerOrganizationID)
			msg.Ack()
		} else {
			common.Log.Warningf("failed to resolve signing key during implicit key exchange message handler; organization id: %s", organizationID)
			natsutil.AttemptNack(msg, organizationImplicitKeyExchangeInitTimeout)
		}
	} else {
		common.Log.Warningf("failed to resolve signing key during implicit key exchange message handler; organization id: %s; %d associated vaults", organizationID, len(vaults))
		natsutil.AttemptNack(msg, organizationImplicitKeyExchangeInitTimeout)
	}
}

func consumeOrganizationImplicitKeyExchangeCompleteMsg(msg *stan.Msg) {
	defer func() {
		if r := recover(); r != nil {
			natsutil.AttemptNack(msg, organizationImplicitKeyExchangeInitTimeout)
		}
	}()

	common.Log.Debugf("consuming %d-byte NATS organization implicit key exchange message on subject: %s", msg.Size(), msg.Subject)

	params := map[string]interface{}{}
	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to unmarshal organization implicit key exchange message; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	organizationID, organizationIDOk := params["organization_id"].(string)
	if !organizationIDOk {
		common.Log.Warning("failed to parse organization_id during implicit key exchange message handler")
		natsutil.Nack(msg)
		return
	}

	peerOrganizationID, peerOrganizationIDOk := params["peer_organization_id"].(string)
	if !peerOrganizationIDOk {
		common.Log.Warning("failed to parse peer_organization_id during implicit key exchange message handler")
		natsutil.Nack(msg)
		return
	}

	peerPublicKey, peerPublicKeyOk := params["public_key"].(string)
	if !peerPublicKeyOk {
		common.Log.Warning("failed to parse peer public key during implicit key exchange message handler")
		natsutil.Nack(msg)
		return
	}

	peerSigningKey, peerSigningKeyOk := params["signing_key"].(string)
	if !peerSigningKeyOk {
		common.Log.Warning("failed to parse peer signing key during implicit key exchange message handler")
		natsutil.Nack(msg)
		return
	}

	// peerSigningSpec, peerSigningSpecOk := params["signing_spec"].(string)
	// if !peerSigningKeyOk {
	// 	common.Log.Warning("failed to parse peer signing key spec during implicit key exchange message handler")
	// 	natsutil.Nack(msg)
	// 	return
	// }

	signature, signatureOk := params["signature"].(string)
	if !signatureOk {
		common.Log.Warning("failed to parse signature during implicit key exchange message handler")
		natsutil.Nack(msg)
		return
	}

	db := dbconf.DatabaseConnection()

	organization := &Organization{}
	db.Where("id = ?", organizationID).Find(&organization)

	if organization == nil || organization.ID == uuid.Nil {
		common.Log.Warningf("failed to resolve organization during implicit key exchange message handler; organization id: %s", organizationID)
		natsutil.AttemptNack(msg, organizationImplicitKeyExchangeInitTimeout)
		return
	}

	var vaults []*vault.Vault
	db.Where("vaults.organization_id = ?", organization.ID).Find(&vaults)

	if len(vaults) == 1 {
		orgVault := vaults[0]
		var signingKeys []*vault.Key
		var signingKey *vault.Key

		orgVault.ListKeysQuery(db).Find(&signingKeys)
		for _, key := range signingKeys {
			if key.Name != nil && strings.ToLower(*key.Name) == "ekho signing" { // FIXME
				signingKey = key
				break
			}
		}

		peerPubKey, err := hex.DecodeString(peerPublicKey)
		if err != nil {
			common.Log.Warningf("failed to decode peer public key as hex during implicit key exchange message handler; organization id: %s; %s", organizationID, err.Error())
			natsutil.AttemptNack(msg, organizationImplicitKeyExchangeInitTimeout)
		}

		sig, err := hex.DecodeString(signature)
		if err != nil {
			common.Log.Warningf("failed to decode signature as hex during implicit key exchange message handler; organization id: %s; %s", organizationID, err.Error())
			natsutil.AttemptNack(msg, organizationImplicitKeyExchangeInitTimeout)
		}

		if signingKey != nil {
			ecdhSecret, err := signingKey.CreateDiffieHellmanSharedSecret(
				[]byte(peerPubKey),
				[]byte(peerSigningKey),
				[]byte(sig),
				"ekho shared secret",
				fmt.Sprintf("shared secret with organization: %s", peerOrganizationID),
			)

			if err == nil {
				common.Log.Debugf("calculated %d-byte shared secret during implicit key exchange message handler; organization id: %s", len(*ecdhSecret.PrivateKey), organizationID)
				// TODO: publish (or POST) to Ekho API (address books sync'd) -- store channel id and use in subsequent message POST
				// POST /users
				msg.Ack()
			} else {
				common.Log.Warningf("failed to encrypt shared secret during implicit key exchange message handler; organization id: %s; %s", organizationID, err.Error())
				natsutil.AttemptNack(msg, organizationImplicitKeyExchangeInitTimeout)
			}
		} else {
			common.Log.Warningf("failed to resolve signing key during implicit key exchange message handler; organization id: %s", organizationID)
			natsutil.AttemptNack(msg, organizationImplicitKeyExchangeInitTimeout)
		}
	} else {
		common.Log.Warningf("failed to resolve signing key during implicit key exchange message handler; organization id: %s; %d associated vaults", organizationID, len(vaults))
		natsutil.AttemptNack(msg, organizationImplicitKeyExchangeInitTimeout)
	}
}

func consumeOrganizationRegistrationMsg(msg *stan.Msg) {
	defer func() {
		if r := recover(); r != nil {
			natsutil.AttemptNack(msg, organizationRegistrationTimeout)
		}
	}()

	common.Log.Debugf("consuming %d-byte NATS organization registration message on subject: %s", msg.Size(), msg.Subject)

	params := map[string]interface{}{}
	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to unmarshal organization registration message; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	organizationID, organizationIDOk := params["organization_id"].(string)
	if !organizationIDOk {
		common.Log.Warning("failed to parse organization_id during organization registration message handler")
		natsutil.Nack(msg)
		return
	}

	applicationID, applicationIDOk := params["application_id"].(string)
	if !applicationIDOk {
		common.Log.Warning("failed to parse application_id during organization registration message handler")
		natsutil.Nack(msg)
		return
	}

	db := dbconf.DatabaseConnection()

	organization := &Organization{}
	db.Where("id = ?", organizationID).Find(&organization)

	if organization == nil || organization.ID == uuid.Nil {
		common.Log.Warningf("failed to resolve organization during registration message handler; organization id: %s", organizationID)
		natsutil.AttemptNack(msg, organizationRegistrationTimeout)
		return
	}

	var orgAddress *string
	var orgMessagingEndpoint *string

	organization.Enrich(db, nil)
	for _, key := range organization.Keys {
		if key.Spec != nil && *key.Spec == "secp256k1" && key.Address != nil {
			orgAddress = common.StringOrNil(*key.Address)
			orgMessagingEndpoint = common.StringOrNil(fmt.Sprintf("0x%s", common.SHA256(*orgAddress))) // FIXME-- this derivation can be removed as we don't need to store it in the blockchain
		}
	}

	if orgAddress == nil || orgMessagingEndpoint == nil {
		common.Log.Warningf("failed to resolve organization public address for storage in the public org registry; organization id: %s", organizationID)
		natsutil.AttemptNack(msg, organizationRegistrationTimeout)
		return
	}

	var tokens []*token.Token
	db.Where("tokens.application_id = ?", applicationID).Find(&tokens) // FIXME-- if the org registry contract moves away from onlyOwner, this needs to be resolved to the organization instead of the application

	if len(tokens) > 0 {
		jwtToken := tokens[0].Token

		status, resp, err := provide.ListContracts(*jwtToken, map[string]interface{}{
			"type": "registry", // FIXME -- should type be "orgregistry" here? probably...
		})
		if err != nil || status != 200 {
			common.Log.Warningf("failed to resolve organization registry contract to which the organization registration tx should be sent; organization id: %s", organizationID)
			natsutil.AttemptNack(msg, organizationRegistrationTimeout)
			return
		}

		var contractID *string
		var walletID *string
		var hdDerivationPath *string

		if cntrcts, contractsOk := resp.([]interface{}); contractsOk {
			for _, c := range cntrcts {
				if cntrct, contractOk := c.(map[string]interface{}); contractOk {
					if cntrctID, contractIDOk := cntrct["id"].(string); contractIDOk {
						contractID = common.StringOrNil(cntrctID)

						if contractParams, contractParamsOk := cntrct["params"].(map[string]interface{}); contractParamsOk {
							if wlltID, wlltIDOk := contractParams["wallet_id"].(string); wlltIDOk {
								walletID = common.StringOrNil(wlltID)
							}

							if wlltHDDerivationPath, wlltHDDerivationPathOk := contractParams["hd_derivation_path"].(string); wlltHDDerivationPathOk {
								hdDerivationPath = common.StringOrNil(wlltHDDerivationPath)
							}
						}
					}
				}
			}
		}

		// status, resp, err = provide.ListWallets(*jwtToken, map[string]interface{}{})
		// if err != nil || status != 200 {
		// 	common.Log.Warningf("failed to resolve HD wallet for signing organization registry transaction; organization id: %s", organizationID)
		// 	natsutil.AttemptNack(msg, organizationRegistrationTimeout)
		// 	return
		// }

		// if status == 200 {
		// 	if wllt, walletOk := resp.(map[string]interface{}); walletOk {
		// 		if wlltID, wlltIDOk := wllt["id"].(string); wlltIDOk {
		// 			status, resp, err := provide.ListWallets(*jwtToken, map[string]interface{}{})
		// 			if err != nil || status != 200 {
		// 				common.Log.Warningf("failed to resolve HD derivation path for signing organization registry transaction; organization id: %s", organizationID)
		// 				natsutil.AttemptNack(msg, organizationRegistrationTimeout)
		// 				return
		// 			}

		// 			if acct, accountOk := resp.(map[string]interface{}); accountOk {
		// 				if acctHDDerivationPath, acctHDDerivationPathOk := acct["hd_derivation_path"].(string); acctHDDerivationPathOk {
		// 					walletID = common.StringOrNil(wlltID)
		// 					hdDerivationPath = common.StringOrNil(acctHDDerivationPath)
		// 				}
		// 			}
		// 		}
		// 	}
		// }

		if contractID == nil {
			common.Log.Warningf("failed to resolve organization registry contract; application id: %s", applicationID)
			natsutil.AttemptNack(msg, organizationRegistrationTimeout)
			return
		}

		if walletID == nil || hdDerivationPath == nil {
			common.Log.Warningf("failed to resolve HD wallet for signing organization registry transaction; organization id: %s", organizationID)
			natsutil.AttemptNack(msg, organizationRegistrationTimeout)
			return
		}

		status, _, err = provide.ExecuteContract(*jwtToken, *contractID, map[string]interface{}{
			"wallet_id":          walletID,
			"hd_derivation_path": hdDerivationPath,
			"method":             organizationRegistrationMethod,
			"params": []interface{}{
				orgAddress,
				*organization.Name,
				0,
				*orgAddress,
				*orgMessagingEndpoint,
			},
			"value": 0,
		})

		if err == nil && status == 202 {
			common.Log.Debugf("broadcast registry transaction on behalf of organization: %s", organizationID)
			msg.Ack()
		} else {
			common.Log.Warningf("failed broadcast registry transaction on behalf of organization: %s; %s", organizationID, err.Error())
			natsutil.AttemptNack(msg, organizationRegistrationTimeout)
		}

	} else {
		common.Log.Warningf("failed to resolve API token during registration message handler; organization id: %s", organizationID)
		natsutil.AttemptNack(msg, organizationImplicitKeyExchangeInitTimeout)
	}
}
