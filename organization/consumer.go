package organization

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/nats-io/nats.go"
	"github.com/provideplatform/ident/common"
	"github.com/provideplatform/ident/token"
	vault "github.com/provideplatform/provide-go/api/vault"
)

const defaultNatsStream = "ident"

const natsCreatedOrganizationCreatedSubject = "ident.organization.created"
const natsCreatedOrganizationCreatedMaxInFlight = 2048
const createOrganizationAckWait = time.Second * 5
const createOrganizationMaxDeliveries = 10

const natsOrganizationImplicitKeyExchangeCompleteSubject = "ident.organization.keys.exchange.complete"
const natsOrganizationImplicitKeyExchangeCompleteMaxInFlight = 2048
const natsOrganizationImplicitKeyExchangeCompleteAckWait = time.Second * 5
const natsOrganizationImplicitKeyExchangeCompleteMaxDeliveries = 10

const natsOrganizationImplicitKeyExchangeInitSubject = "ident.organization.keys.exchange.init"
const natsOrganizationImplicitKeyExchangeMaxInFlight = 2048
const natsOrganizationImplicitKeyExchangeInitAckWait = time.Second * 5
const natsOrganizationImplicitKeyExchangeInitMaxDeliveries = 10

const natsOrganizationRegistrationSubject = "ident.organization.registration"
const natsOrganizationRegistrationMaxInFlight = 2048
const natsOrganizationRegistrationAckWait = time.Second * 60
const natsOrganizationRegistrationMaxDeliveries = 10

func init() {
	if !common.ConsumeNATSStreamingSubscriptions {
		common.Log.Debug("organization package consumer configured to skip NATS streaming subscription setup")
		return
	}

	natsutil.EstablishSharedNatsConnection(nil)
	natsutil.NatsCreateStream(defaultNatsStream, []string{
		fmt.Sprintf("%s.>", defaultNatsStream),
	})

	var waitGroup sync.WaitGroup

	createNatsOrganizationCreatedSubscriptions(&waitGroup)
	createNatsOrganizationImplicitKeyExchangeCompleteSubscriptions(&waitGroup)
	createNatsOrganizationImplicitKeyExchangeSubscriptions(&waitGroup)
	createNatsOrganizationRegistrationSubscriptions(&waitGroup)
}

func createNatsOrganizationCreatedSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		_, err := natsutil.RequireNatsJetstreamSubscription(wg,
			createOrganizationAckWait,
			natsCreatedOrganizationCreatedSubject,
			natsCreatedOrganizationCreatedSubject,
			natsCreatedOrganizationCreatedSubject,
			consumeCreatedOrganizationMsg,
			createOrganizationAckWait,
			natsCreatedOrganizationCreatedMaxInFlight,
			createOrganizationMaxDeliveries,
			nil,
		)

		if err != nil {
			common.Log.Panicf("failed to subscribe to NATS stream via subject: %s; %s", natsCreatedOrganizationCreatedSubject, err.Error())
		}
	}
}

func createNatsOrganizationImplicitKeyExchangeCompleteSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		_, err := natsutil.RequireNatsJetstreamSubscription(wg,
			natsOrganizationImplicitKeyExchangeCompleteAckWait,
			natsOrganizationImplicitKeyExchangeCompleteSubject,
			natsOrganizationImplicitKeyExchangeCompleteSubject,
			natsOrganizationImplicitKeyExchangeCompleteSubject,
			consumeOrganizationImplicitKeyExchangeCompleteMsg,
			natsOrganizationImplicitKeyExchangeCompleteAckWait,
			natsOrganizationImplicitKeyExchangeCompleteMaxInFlight,
			natsOrganizationImplicitKeyExchangeCompleteMaxDeliveries,
			nil,
		)

		if err != nil {
			common.Log.Panicf("failed to subscribe to NATS stream via subject: %s; %s", natsOrganizationImplicitKeyExchangeCompleteSubject, err.Error())
		}
	}
}

func createNatsOrganizationImplicitKeyExchangeSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		_, err := natsutil.RequireNatsJetstreamSubscription(wg,
			natsOrganizationImplicitKeyExchangeInitAckWait,
			natsOrganizationImplicitKeyExchangeInitSubject,
			natsOrganizationImplicitKeyExchangeInitSubject,
			natsOrganizationImplicitKeyExchangeInitSubject,
			consumeOrganizationImplicitKeyExchangeInitMsg,
			natsOrganizationImplicitKeyExchangeInitAckWait,
			natsOrganizationImplicitKeyExchangeMaxInFlight,
			natsOrganizationImplicitKeyExchangeInitMaxDeliveries,
			nil,
		)

		if err != nil {
			common.Log.Panicf("failed to subscribe to NATS stream via subject: %s; %s", natsOrganizationImplicitKeyExchangeInitSubject, err.Error())
		}
	}
}

func createNatsOrganizationRegistrationSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		_, err := natsutil.RequireNatsJetstreamSubscription(wg,
			natsOrganizationRegistrationAckWait,
			natsOrganizationRegistrationSubject,
			natsOrganizationRegistrationSubject,
			natsOrganizationRegistrationSubject,
			consumeOrganizationRegistrationMsg,
			natsOrganizationRegistrationAckWait,
			natsOrganizationRegistrationMaxInFlight,
			natsOrganizationRegistrationMaxDeliveries,
			nil,
		)

		if err != nil {
			common.Log.Panicf("failed to subscribe to NATS stream via subject: %s; %s", natsOrganizationRegistrationSubject, err.Error())
		}
	}
}

func consumeCreatedOrganizationMsg(msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			msg.Nak()
		}
	}()

	common.Log.Debugf("consuming %d-byte NATS created organization message on subject: %s", len(msg.Data), msg.Subject)

	params := map[string]interface{}{}
	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to unmarshal organization created message; %s", err.Error())
		msg.Nak()
		return
	}

	organizationID, organizationIDOk := params["organization_id"].(string)
	if !organizationIDOk {
		common.Log.Warning("failed to unmarshal organization_id during created message handler")
		msg.Nak()
		return
	}

	db := dbconf.DatabaseConnection()

	organization := &Organization{}
	db.Where("id = ?", organizationID).Find(&organization)

	if organization == nil || organization.ID == uuid.Nil {
		common.Log.Warningf("failed to resolve organization during created message handler; organization id: %s", organizationID)
		msg.Nak()
		return
	}

	orgToken := &token.Token{
		OrganizationID: &organization.ID,
	}
	if !orgToken.Vend() {
		common.Log.Warningf("failed to vend signed JWT for organization registration tx signing; organization id: %s", organizationID)
		msg.Nak()
		return
	}

	vlt, err := vault.CreateVault(*orgToken.Token, map[string]interface{}{
		"name":            fmt.Sprintf("%s vault", *organization.Name),
		"description":     "default organizational keystore",
		"organization_id": organizationID,
	})

	if err == nil {
		common.Log.Debugf("created default vault for organization: %s; vault id: %s", *organization.Name, vlt.ID.String())
		msg.Ack()
	} else {
		common.Log.Warningf("failed to create default vault for organization: %s; %s", *organization.Name, err.Error())
		msg.Nak()
	}
}

func consumeOrganizationImplicitKeyExchangeInitMsg(msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			msg.Nak()
		}
	}()

	common.Log.Debugf("consuming %d-byte NATS organization implicit key exchange message on subject: %s", len(msg.Data), msg.Subject)

	params := map[string]interface{}{}
	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to unmarshal organization implicit key exchange message; %s", err.Error())
		msg.Nak()
		return
	}

	organizationID, organizationIDOk := params["organization_id"].(string)
	if !organizationIDOk {
		common.Log.Warning("failed to parse organization_id during implicit key exchange message handler")
		msg.Nak()
		return
	}

	peerOrganizationID, peerOrganizationIDOk := params["peer_organization_id"].(string)
	if !peerOrganizationIDOk {
		common.Log.Warning("failed to parse peer_organization_id during implicit key exchange message handler")
		msg.Nak()
		return
	}

	db := dbconf.DatabaseConnection()

	organization := &Organization{}
	db.Where("id = ?", organizationID).Find(&organization)

	if organization == nil || organization.ID == uuid.Nil {
		common.Log.Warningf("failed to resolve organization during implicit key exchange message handler; organization id: %s", organizationID)
		msg.Nak()
		return
	}

	orgToken := &token.Token{
		OrganizationID: &organization.ID,
	}
	if !orgToken.Vend() {
		common.Log.Warningf("failed to vend signed JWT for organization implicit key exchange; organization id: %s", organizationID)
		msg.Nak()
		return
	}

	vaults, err := vault.ListVaults(*orgToken.Token, map[string]interface{}{})
	if err != nil {
		common.Log.Warningf("failed to fetch vaults during implicit key exchange message handler; organization id: %s", organizationID)
		msg.Nak()
		return
	}

	if len(vaults) > 0 {
		orgVault := vaults[0]
		keys, err := vault.ListKeys(*orgToken.Token, orgVault.ID.String(), map[string]interface{}{})
		if err != nil {
			common.Log.Warningf("failed to fetch keys from vault during implicit key exchange message handler; organization id: %s", organizationID)
			msg.Nak()
			return
		}

		var signingKey *vault.Key
		for _, key := range keys {
			if key.Name != nil && strings.ToLower(*key.Name) == "ekho signing" { // FIXME
				signingKey = key
				break
			}
		}

		if signingKey != nil {
			c25519Key, err := vault.CreateKey(*orgToken.Token, orgVault.ID.String(), map[string]interface{}{
				"type":        "asymmetric",
				"usage":       "sign/verify",
				"spec":        "C25519",
				"name":        "ekho single-use c25519 key exchange",
				"description": fmt.Sprintf("ekho - single-use c25519 key exchange with peer organization: %s", peerOrganizationID),
				"ephemeral":   "true",
			})
			if err != nil {
				common.Log.Warningf("failed to generate single-use c25519 public key for implicit key exchange; organization id: %s", organizationID)
				msg.Nak()
				return
			}

			c25519PublicKeyRaw, err := hex.DecodeString(*c25519Key.PublicKey)
			if err != nil {
				common.Log.Warningf("failed to decode single-use c25519 public key for implicit key exchange; organization id: %s", organizationID)
				msg.Nak()
				return
			}

			signingResponse, err := vault.SignMessage(
				*orgToken.Token,
				orgVault.ID.String(),
				c25519Key.ID.String(),
				string(c25519PublicKeyRaw),
				map[string]interface{}{},
			)

			if err != nil {
				common.Log.Warningf("failed to sign single-use c25519 public key for implicit key exchange; organization id: %s; %s", organizationID, err.Error())
				msg.Nak()
				return
			}

			c25519PublicKeySigned := signingResponse.Signature //.(map[string]interface{})["signature"].(string)
			common.Log.Debugf("generated %d-byte signature using Ed25519 signing key", len(*c25519PublicKeySigned))

			payload, _ := json.Marshal(map[string]interface{}{
				"organization_id":      organizationID,
				"peer_organization_id": peerOrganizationID,
				"public_key":           *c25519Key.PublicKey,
				"signature":            hex.EncodeToString([]byte(*c25519PublicKeySigned)),
				"signing_key":          *signingKey.PublicKey,
				"signing_spec":         *signingKey.Spec,
			})
			natsutil.NatsJetstreamPublish(natsOrganizationImplicitKeyExchangeCompleteSubject, payload)

			common.Log.Debugf("published %s implicit key exchange message for peer organization id: %s", natsOrganizationImplicitKeyExchangeCompleteSubject, peerOrganizationID)
			msg.Ack()
		} else {
			common.Log.Warningf("failed to resolve signing key during implicit key exchange message handler; organization id: %s", organizationID)
			msg.Nak()
		}
	} else {
		common.Log.Warningf("failed to resolve signing key during implicit key exchange message handler; organization id: %s; %d associated vaults", organizationID, len(vaults))
		msg.Nak()
	}
}

func consumeOrganizationImplicitKeyExchangeCompleteMsg(msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			msg.Nak()
		}
	}()

	common.Log.Debugf("consuming %d-byte NATS organization implicit key exchange message on subject: %s", len(msg.Data), msg.Subject)

	params := map[string]interface{}{}
	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to unmarshal organization implicit key exchange message; %s", err.Error())
		msg.Nak()
		return
	}

	organizationID, organizationIDOk := params["organization_id"].(string)
	if !organizationIDOk {
		common.Log.Warning("failed to parse organization_id during implicit key exchange message handler")
		msg.Nak()
		return
	}

	peerOrganizationID, peerOrganizationIDOk := params["peer_organization_id"].(string)
	if !peerOrganizationIDOk {
		common.Log.Warning("failed to parse peer_organization_id during implicit key exchange message handler")
		msg.Nak()
		return
	}

	peerPublicKey, peerPublicKeyOk := params["public_key"].(string)
	if !peerPublicKeyOk {
		common.Log.Warning("failed to parse peer public key during implicit key exchange message handler")
		msg.Nak()
		return
	}

	peerSigningKey, peerSigningKeyOk := params["signing_key"].(string)
	if !peerSigningKeyOk {
		common.Log.Warning("failed to parse peer signing key during implicit key exchange message handler")
		msg.Nak()
		return
	}

	// peerSigningSpec, peerSigningSpecOk := params["signing_spec"].(string)
	// if !peerSigningKeyOk {
	// 	common.Log.Warning("failed to parse peer signing key spec during implicit key exchange message handler")
	// 	msg.Nak()
	// 	return
	// }

	signature, signatureOk := params["signature"].(string)
	if !signatureOk {
		common.Log.Warning("failed to parse signature during implicit key exchange message handler")
		msg.Nak()
		return
	}

	db := dbconf.DatabaseConnection()

	organization := &Organization{}
	db.Where("id = ?", organizationID).Find(&organization)

	if organization == nil || organization.ID == uuid.Nil {
		common.Log.Warningf("failed to resolve organization during implicit key exchange message handler; organization id: %s", organizationID)
		msg.Nak()
		return
	}

	orgToken := &token.Token{
		OrganizationID: &organization.ID,
	}
	if !orgToken.Vend() {
		common.Log.Warningf("failed to vend signed JWT for organization implicit key exchange; organization id: %s", organizationID)
		msg.Nak()
		return
	}

	vaults, err := vault.ListVaults(*orgToken.Token, map[string]interface{}{})
	if err != nil {
		common.Log.Warningf("failed to fetch vaults during implicit key exchange message handler; organization id: %s", organizationID)
		msg.Nak()
		return
	}

	if len(vaults) > 0 {
		orgVault := vaults[0]

		keys, err := vault.ListKeys(*orgToken.Token, orgVault.ID.String(), map[string]interface{}{})
		if err != nil {
			common.Log.Warningf("failed to fetch keys from vault during implicit key exchange message handler; organization id: %s", organizationID)
			msg.Nak()
			return
		}

		var signingKey *vault.Key
		for _, key := range keys {
			if key.Name != nil && strings.ToLower(*key.Name) == "ekho signing" { // FIXME
				signingKey = key
				break
			}
		}

		peerPubKey, err := hex.DecodeString(peerPublicKey)
		if err != nil {
			common.Log.Warningf("failed to decode peer public key as hex during implicit key exchange message handler; organization id: %s; %s", organizationID, err.Error())
			msg.Nak()
			return
		}

		sig, err := hex.DecodeString(signature)
		if err != nil {
			common.Log.Warningf("failed to decode signature as hex during implicit key exchange message handler; organization id: %s; %s", organizationID, err.Error())
			msg.Nak()
			return
		}

		if signingKey != nil {
			common.Log.Debugf("peer org id: %s; peer public key: %s; peer signing key: %s; sig: %s", peerOrganizationID, peerPubKey, peerSigningKey, sig)
			err = errors.New("the CreateDiffieHellmanSharedSecret method is not exposed by the vault API yet")
			// FIXME! the CreateDiffieHellmanSharedSecret method is not exposed by the vault API... yet.
			// ecdhSecret, err := signingKey.CreateDiffieHellmanSharedSecret(
			// 	[]byte(peerPubKey),
			// 	[]byte(peerSigningKey),
			// 	[]byte(sig),
			// 	"ekho shared secret",
			// 	fmt.Sprintf("shared secret with organization: %s", peerOrganizationID),
			// )

			if err == nil {
				// FIXME -- uncomment common.Log.Debugf("calculated %d-byte shared secret during implicit key exchange message handler; organization id: %s", len(*ecdhSecret.PrivateKey), organizationID)
				// TODO: publish (or POST) to Ekho API (address books sync'd) -- store channel id and use in subsequent message POST
				// POST /users
				msg.Ack()
			} else {
				common.Log.Warningf("failed to encrypt shared secret during implicit key exchange message handler; organization id: %s; %s", organizationID, err.Error())
				msg.Nak()
			}
		} else {
			common.Log.Warningf("failed to resolve signing key during implicit key exchange message handler; organization id: %s", organizationID)
			msg.Nak()
		}
	} else {
		common.Log.Warningf("failed to resolve signing key during implicit key exchange message handler; organization id: %s; %d associated vaults", organizationID, len(vaults))
		msg.Nak()
	}
}

func consumeOrganizationRegistrationMsg(msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered in org registration message handler; %s", r)
			msg.Nak()
		}
	}()

	common.Log.Debugf("consumed %d-byte NOOP NATS organization registration message on subject: %s", len(msg.Data), msg.Subject)
	msg.Ack()
}
