package user

import (
	"encoding/json"
	"fmt"
	"time"

	natsutil "github.com/kthomas/go-natsutil"
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
	Name             *string            `sql:"-" json:"name,omitempty"`
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

// AcceptInvite parses an invitation given the previously signed token; it doesn't actually
// accept the invitation by creating a user or associating the user with an application or
// organization at this time, rather it returns an Invite instance which has been verified
// as capable of being accepted by the caller
func AcceptInvite(signedToken string) (*Invite, error) {
	token, err := token.Parse(signedToken)
	if err != nil {
		common.Log.Warningf("failed accept invitation using given token; %s", err.Error())
		return nil, err
	}

	data := token.ParseData()
	common.Log.Debugf("parsed valid invitation token; subject: %s", *token.Subject)

	name, _ := data["name"].(string)
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
			common.Log.Warningf("failed to accept invitation using given token; invalid invitor id; %s", err.Error())
			return nil, err
		}
		invitorUUID = &senderUUID
	}
	invitorName, _ := data["invitor_name"].(string)

	var organizationUUID *uuid.UUID
	if organizationID, organizationIDOk := data["organization_id"].(string); organizationIDOk {
		orgUUID, err := uuid.FromString(organizationID)
		if err != nil {
			common.Log.Warningf("failed to accept invitation using given token; invalid organization_ id; %s", err.Error())
			return nil, err
		}
		organizationUUID = &orgUUID
	}

	return &Invite{
		ApplicationID:  token.ApplicationID,
		UserID:         token.UserID,
		Name:           common.StringOrNil(name),
		Email:          common.StringOrNil(email),
		InvitorID:      invitorUUID,
		InvitorName:    common.StringOrNil(invitorName),
		OrganizationID: organizationUUID,
		Permissions:    permissions,
	}, nil
}

// Create the invite
func (i *Invite) Create() bool {
	token, err := i.vendToken()
	if err != nil {
		common.Log.Warningf("failed to vend invite token; %s", err.Error())
		return false
	}
	i.Token = token
	return i.Token != nil
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
		"name":              i.Name,
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
