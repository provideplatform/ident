package user

import (
	"encoding/json"
	"fmt"
	"time"

	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/ident/common"
	"github.com/provideapp/ident/token"
	provide "github.com/provideservices/provide-go"
)

const defaultInvitationTokenTimeout = time.Hour * 48

// Invite model
type Invite struct {
	// provide.Model
	ApplicationID    *uuid.UUID        `sql:"-" json:"application_id,omitempty"`
	Name             *string           `sql:"-" json:"name,omitempty"`
	Email            *string           `sql:"-" json:"email,omitempty"`
	InvitorID        *uuid.UUID        `sql:"-" json:"invitor_id,omitempty"`
	OrganizationID   *uuid.UUID        `sql:"-" json:"organization_id,omitempty"`
	OrganizationName *string           `sql:"-" json:"organization_name,omitempty"`
	Permissions      common.Permission `sql:"-" json:"permissions,omitempty"`

	Errors []*provide.Error `sql:"-" json:"-"`
	Token  *token.Token     `sql:"-" json:"-"`
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

func (i *Invite) vendToken() (*token.Token, error) {
	dataJSON, _ := json.Marshal(map[string]interface{}{
		"application_id":    i.ApplicationID,
		"name":              i.Name,
		"email":             i.Email,
		"invitor_id":        i.InvitorID,
		"organization_id":   i.OrganizationID,
		"organization_name": i.OrganizationName,
	})
	data := json.RawMessage(dataJSON)

	token := &token.Token{
		Data:        &data,
		Permissions: i.Permissions,
		Subject:     common.StringOrNil(fmt.Sprintf("invite:%s", *i.Email)),
	}
	if !token.Vend() {
		if len(token.Errors) > 0 {
			err := fmt.Errorf("failed to vend token for inivtation; %s", *token.Errors[0].Message)
			common.Log.Warningf(err.Error())
			return nil, err
		}
	}

	return token, nil
}
