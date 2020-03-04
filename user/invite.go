package user

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	natsutil "github.com/kthomas/go-natsutil"
	"github.com/kthomas/go-redisutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/ident/common"
	"github.com/provideapp/ident/token"
	provide "github.com/provideservices/provide-go"
)

const defaultInvitationTokenTimeout = time.Hour * 48

// Invite model
type Invite struct {
	// provide.Model
	ApplicationID    *uuid.UUID         `sql:"-" json:"application_id,omitempty"`
	UserID           *uuid.UUID         `sql:"-" json:"user_id,omitempty"`
	FirstName        *string            `sql:"-" json:"first_name,omitempty"`
	LastName         *string            `sql:"-" json:"last_name,omitempty"`
	Email            *string            `sql:"-" json:"email,omitempty"`
	InvitorID        *uuid.UUID         `sql:"-" json:"invitor_id,omitempty"`
	InvitorName      *string            `sql:"-" json:"invitor_name,omitempty"`
	OrganizationID   *uuid.UUID         `sql:"-" json:"organization_id,omitempty"`
	OrganizationName *string            `sql:"-" json:"organization_name,omitempty"`
	Permissions      *common.Permission `sql:"-" json:"permissions,omitempty"`
	Params           *json.RawMessage   `sql:"-" json:"params,omitempty"`

	Errors []*provide.Error `sql:"-" json:"-"`
	Token  *token.Token     `sql:"-" json:"-"`
}

// ParseInvite parses an invitation given the previously signed token; it doesn't actually
// accept the invitation by creating a user or associating the user with an application or
// organization at this time, rather it returns an Invite instance which has been verified
// as capable of being accepted by the caller; the strict argument, when set to true, will
// result in this method returning an error if the parsed invitation token has been revoked
func ParseInvite(signedToken string, strict bool) (*Invite, error) {
	token, err := token.Parse(signedToken)
	if err != nil {
		common.Log.Warningf("failed to parse invitation token; %s", err.Error())
		return nil, err
	}

	if strict && token.IsRevoked() {
		return nil, errors.New("invitation token revoked")
	}

	data := token.ParseData()
	common.Log.Debugf("parsed valid invitation token; subject: %s", *token.Subject)

	firstName, _ := data["first_name"].(string)
	lastName, _ := data["last_name"].(string)
	email, _ := data["email"].(string)
	var permissions *common.Permission
	if claimedPermissions, claimedPermissionsOk := data["permissions"].(float64); claimedPermissionsOk {
		perms := common.Permission(claimedPermissions)
		permissions = &perms
	}

	var invitorUUID *uuid.UUID
	if invitorID, invitorIDOk := data["invitor_id"].(string); invitorIDOk {
		senderUUID, err := uuid.FromString(invitorID)
		if err != nil {
			common.Log.Warningf("failed to parse invitation token; invalid invitor id; %s", err.Error())
			return nil, err
		}
		invitorUUID = &senderUUID
	}
	invitorName, _ := data["invitor_name"].(string)

	applicationUUID := token.ApplicationID
	if applicationUUID == nil {
		if applicationID, applicationIDOk := data["application_id"].(string); applicationIDOk {
			appUUID, err := uuid.FromString(applicationID)
			if err != nil {
				common.Log.Warningf("failed to parse invitation token; invalid application_id; %s", err.Error())
				return nil, err
			}
			applicationUUID = &appUUID
		}
	}

	var organizationUUID *uuid.UUID
	if organizationID, organizationIDOk := data["organization_id"].(string); organizationIDOk {
		orgUUID, err := uuid.FromString(organizationID)
		if err != nil {
			common.Log.Warningf("failed to parse invitation token; invalid organization_ id; %s", err.Error())
			return nil, err
		}
		organizationUUID = &orgUUID
	}

	var organizationName *string
	if orgName, orgNameOk := data["organization_name"].(string); orgNameOk {
		organizationName = &orgName
	}

	return &Invite{
		ApplicationID:    applicationUUID,
		UserID:           token.UserID,
		FirstName:        common.StringOrNil(firstName),
		LastName:         common.StringOrNil(lastName),
		Email:            common.StringOrNil(email),
		InvitorID:        invitorUUID,
		InvitorName:      common.StringOrNil(invitorName),
		OrganizationID:   organizationUUID,
		OrganizationName: organizationName,
		Permissions:      permissions,
		Token:            token,
	}, nil
}

func (i *Invite) cache(key string) error {
	common.Log.Debugf("attempting to cache invitation at key: %s", key)

	rawinvites, err := redisutil.Get(key)
	var invitations []*Invite

	if rawinvites != nil {
		err = json.Unmarshal([]byte(*rawinvites), &invitations)
		if err != nil {
			return fmt.Errorf("failed to unmarshal cached invitations from key: %s; %s", key, err.Error())
		}
	} else {
		invitations = make([]*Invite, 0)
	}

	invitations = append(invitations, &Invite{
		FirstName:   i.FirstName,
		LastName:    i.LastName,
		Email:       i.Email,
		Permissions: i.Permissions,
		Token: &token.Token{
			ExpiresAt: i.Token.ExpiresAt,
			Hash:      i.Token.Hash,
		},
	})

	rawinvitesJSON, err := json.Marshal(&invitations)
	if err != nil {
		msg := fmt.Sprintf("failed to cache invitations at key: %s; %s", key, err.Error())
		common.Log.Warning(msg)
		return errors.New(msg)
	}

	var ttl *time.Duration
	if i.Token != nil && i.Token.ExpiresAt != nil {
		ttlval := time.Until(*i.Token.ExpiresAt)
		ttl = &ttlval
	}

	err = redisutil.Set(key, string(rawinvitesJSON), ttl)
	if err != nil {
		common.Log.Warningf("failed to cache invitations at key: %s; %s", key, err.Error())
	}
	return err
}

func (i *Invite) invalidateCache(key string) error {
	common.Log.Debugf("attempting to purge cached invitation at key: %s", key)

	rawinvites, err := redisutil.Get(key)
	var cachedInvitations []*Invite

	if rawinvites != nil {
		err = json.Unmarshal([]byte(*rawinvites), &cachedInvitations)
		if err != nil {
			return fmt.Errorf("failed to unmarshal cached invitations from key: %s; %s", key, err.Error())
		}
	} else {
		common.Log.Debugf("cached invitations already purged from key: %s", key)
		return nil
	}

	var expiresAt *time.Time

	invitations := make([]*Invite, 0)
	for _, cachedInvitation := range cachedInvitations {
		if i.Token != nil && i.Token.Hash != nil && cachedInvitation.Token != nil && cachedInvitation.Token.Hash != nil && *cachedInvitation.Token.Hash != *i.Token.Hash {
			invitations = append(invitations, cachedInvitation)
		}

		if cachedInvitation.Token != nil && cachedInvitation.Token.ExpiresAt != nil {
			if expiresAt == nil {
				expiresAt = cachedInvitation.Token.ExpiresAt
			} else if expiresAt.Before(*cachedInvitation.Token.ExpiresAt) {
				expiresAt = cachedInvitation.Token.ExpiresAt
			}
		}
	}

	rawinvitesJSON, err := json.Marshal(&invitations)
	if err != nil {
		msg := fmt.Sprintf("failed to cache invitations at key: %s; %s", key, err.Error())
		common.Log.Warning(msg)
		return errors.New(msg)
	}

	var ttl *time.Duration
	if expiresAt != nil {
		ttlval := time.Until(*expiresAt)
		ttl = &ttlval
	}

	err = redisutil.Set(key, string(rawinvitesJSON), ttl)
	if err != nil {
		common.Log.Warningf("failed to cache invitations at key: %s; %s", key, err.Error())
	}
	return err
}

// InvalidateCache invalidates cached pending tokens
func (i *Invite) InvalidateCache() error {
	var err error

	if i.ApplicationID != nil {
		key := fmt.Sprintf("application.%s.invitations", i.ApplicationID.String())
		err = redisutil.WithRedlock(key, func() error { return i.invalidateCache(key) })
		if err != nil {
			common.Log.Warningf("failed to purge invitation from cache at key: %s; %s", key, err.Error())
			return err
		}
	}

	if i.OrganizationID != nil {
		key := fmt.Sprintf("organization.%s.invitations", i.OrganizationID.String())
		err = redisutil.WithRedlock(key, func() error { return i.invalidateCache(key) })
		if err != nil {
			common.Log.Warningf("failed to purge invitation from cache at key: %s; %s", key, err.Error())
			return err
		}
	}

	return nil
}

// Create the invite
func (i *Invite) Create() bool {
	token, err := i.vendToken()
	if err != nil {
		common.Log.Warningf("failed to vend invite token; %s", err.Error())
		return false
	}
	i.Token = token
	success := i.Token != nil
	if success {
		if i.ApplicationID != nil {
			key := fmt.Sprintf("application.%s.invitations", i.ApplicationID.String())
			redisutil.WithRedlock(key, func() error { return i.cache(key) })
		}
		if i.OrganizationID != nil {
			key := fmt.Sprintf("organization.%s.invitations", i.OrganizationID.String())
			redisutil.WithRedlock(key, func() error { return i.cache(key) })
		}
	}
	return success
}

func (i *Invite) authorizesNewApplicationOrganization() bool {
	return i.ApplicationID != nil && i.OrganizationName != nil
}

func (i *Invite) parseParams() map[string]interface{} {
	params := map[string]interface{}{}
	if i.Params != nil {
		err := json.Unmarshal(*i.Params, &params)
		if err != nil {
			common.Log.Warningf("failed to unmarshal invite params; %s", err.Error())
			return nil
		}
	}
	return params
}

func (i *Invite) vendToken() (*token.Token, error) {
	dataJSON, _ := json.Marshal(map[string]interface{}{
		"application_id":    i.ApplicationID,
		"user_id":           i.UserID,
		"first_name":        i.FirstName,
		"last_name":         i.LastName,
		"email":             i.Email,
		"invitor_id":        i.InvitorID,
		"invitor_name":      i.InvitorName,
		"organization_id":   i.OrganizationID,
		"organization_name": i.OrganizationName,
		"params":            i.parseParams(),
	})
	data := json.RawMessage(dataJSON)

	token := &token.Token{
		Data:    &data,
		Subject: common.StringOrNil(fmt.Sprintf("invite:%s", *i.Email)),
	}
	if i.Permissions != nil {
		token.Permissions = *i.Permissions
	}

	if !token.Vend() {
		if len(token.Errors) > 0 {
			err := fmt.Errorf("failed to vend token for inivtation; %s", *token.Errors[0].Message)
			common.Log.Warningf(err.Error())
			return nil, err
		}
	}

	payload, _ := json.Marshal(token)
	natsutil.NatsPublish(natsDispatchInvitationSubject, payload)

	return token, nil
}
