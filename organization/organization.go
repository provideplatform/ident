package organization

import (
	"encoding/json"
	"fmt"

	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	redisutil "github.com/kthomas/go-redisutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/ident/common"
	"github.com/provideplatform/ident/user"
	provide "github.com/provideplatform/provide-go/api"
)

const natsApplicationImplicitKeyExchangeInitSubject = "ident.application.keys.exchange.init"
const natsOrganizationUpdatedInitSubject = "ident.organization.updated"
const organizationResourceKey = "organization"

// Organization model
type Organization struct {
	provide.Model
	Name        *string           `sql:"not null" json:"name"`
	UserID      *uuid.UUID        `json:"user_id,omitempty"`
	Description *string           `json:"description"`
	Permissions common.Permission `sql:"not null" json:"permissions,omitempty"`
	Metadata    *json.RawMessage  `sql:"type:json" json:"metadata"`

	Users []*user.User `gorm:"many2many:organizations_users" json:"-"`
}

// hasPermission returns true if the permissioned Organization has the given permissions
func (o *Organization) hasPermission(permission common.Permission) bool {
	return o.Permissions.Has(permission)
}

// hasAnyPermission returns true if the permissioned Organization has any the given permissions
func (o *Organization) hasAnyPermission(permissions ...common.Permission) bool {
	for _, p := range permissions {
		if o.hasPermission(p) {
			return true
		}
	}
	return false
}

func (o *Organization) addApplicationAssociation(tx *gorm.DB, appID uuid.UUID, permissions common.Permission) bool {
	var db *gorm.DB
	if tx != nil {
		db = tx
	} else {
		db = dbconf.DatabaseConnection()
	}

	common.Log.Debugf("adding organization %s to application: %s", o.ID, appID)
	result := db.Exec("INSERT INTO applications_organizations (application_id, organization_id, permissions) VALUES (?, ?, ?)", appID, o.ID, permissions)
	success := result.RowsAffected == 1
	if success {
		common.Log.Debugf("added organization %s to application: %s", o.ID, appID)

		payload, _ := json.Marshal(map[string]interface{}{
			"application_id":  appID.String(),
			"organization_id": o.ID.String(),
		})
		natsutil.NatsStreamingPublish(natsApplicationImplicitKeyExchangeInitSubject, payload)
	} else {
		common.Log.Warningf("failed to add organization %s to application: %s", o.ID, appID)
	}
	return success
}

func (o *Organization) addUser(tx *gorm.DB, usr user.User, permissions common.Permission) bool {
	var db *gorm.DB
	if tx != nil {
		db = tx
	} else {
		db = dbconf.DatabaseConnection()
	}

	common.Log.Debugf("adding user %s to organization: %s", usr.ID, o.ID)
	result := db.Exec("INSERT INTO organizations_users (organization_id, user_id, permissions) VALUES (?, ?, ?)", o.ID, usr.ID, permissions)
	success := result.RowsAffected == 1
	if success {
		common.Log.Debugf("added user %s to organization: %s", usr.ID, o.ID)
	} else {
		common.Log.Warningf("failed to add user %s to organization: %s; %s", usr.ID, o.ID, result.Error.Error())
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				o.Errors = append(o.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
	}
	return success
}

func (o *Organization) removeUser(tx *gorm.DB, usr *user.User) bool {
	var db *gorm.DB
	if tx != nil {
		db = tx
	} else {
		db = dbconf.DatabaseConnection()
	}

	common.Log.Debugf("removing user %s from organization: %s", usr.ID, o.ID)
	result := db.Exec("DELETE FROM organizations_users WHERE organization_id = ? AND user_id = ?", o.ID, usr.ID)
	success := result.RowsAffected == 1
	if success {
		common.Log.Debugf("removed user %s from organization: %s", usr.ID, o.ID)
	} else {
		common.Log.Warningf("failed to remove user %s from organization: %s; %s", usr.ID, o.ID, result.Error.Error())
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				o.Errors = append(o.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
	}
	return success
}

func (o *Organization) updateUser(tx *gorm.DB, usr *user.User, permissions common.Permission) bool {
	var db *gorm.DB
	if tx != nil {
		db = tx
	} else {
		db = dbconf.DatabaseConnection()
	}

	common.Log.Debugf("updating user %s for organization: %s", usr.ID, o.ID)
	result := db.Exec("UPDATE organizations_users SET permissions = ? WHERE organization_id = ? AND user_id = ?", permissions, o.ID, usr.ID)
	success := result.RowsAffected == 1
	if success {
		common.Log.Debugf("updated user %s for organization: %s", usr.ID, o.ID)
	} else {
		common.Log.Warningf("failed to update user %s for organization: %s; %s", usr.ID, o.ID, result.Error.Error())
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				o.Errors = append(o.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
	}
	return success
}

// Create and persist a user
func (o *Organization) Create(tx *gorm.DB) bool {
	var db *gorm.DB
	if tx != nil {
		db = tx
	} else {
		db = dbconf.DatabaseConnection()
		db = db.Begin()
		defer db.RollbackUnlessCommitted()
	}

	if !o.validate() {
		return false
	}

	if db.NewRecord(o) {
		result := db.Create(&o)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				o.Errors = append(o.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
		if !db.NewRecord(o) {
			success := rowsAffected > 0
			if success {
				common.Log.Debugf("created organization: %s", *o.Name)

				if o.UserID != nil {
					usr := &user.User{}
					db.Where("id = ?", o.UserID).Find(&usr)
					if usr != nil && usr.ID != uuid.Nil {
						if o.addUser(db, *usr, common.DefaultApplicationResourcePermission) {
							common.Log.Debugf("associated user %s with organization: %s", *usr.FullName(), *o.Name)
							if tx == nil {
								db.Commit()
							}
						} else {
							common.Log.Warningf("failed to associate user %s with organization: %s", *usr.FullName(), *o.Name)
							return false
						}
					} else if tx == nil {
						db.Commit()
					}
				}

				if success {
					payload, _ := json.Marshal(map[string]interface{}{
						"organization_id": o.ID.String(),
					})
					natsutil.NatsStreamingPublish(natsCreatedOrganizationCreatedSubject, payload)
				}

				return success
			}
		}
	}

	return false
}

// pendingInvitations returns the pending invitations for the organization; these are ephemeral, in-memory only
func (o *Organization) pendingInvitations() []*user.Invite {
	var invitations []*user.Invite

	key := fmt.Sprintf("organization.%s.invitations", o.ID.String())
	rawinvites, err := redisutil.Get(key)
	if err != nil {
		common.Log.Debugf("failed to retrieve cached organization invitations from key: %s; %s", key, err.Error())
		return invitations
	}

	json.Unmarshal([]byte(*rawinvites), &invitations)
	return invitations
}

// Update an existing user
func (o *Organization) Update() bool {
	db := dbconf.DatabaseConnection()

	if !o.validate() {
		return false
	}

	tx := db.Begin()
	result := tx.Save(&o)
	success := result.RowsAffected > 0
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			o.Errors = append(o.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}

	if success {
		common.Log.Debugf("updated organization: %s", *o.Name)

		common.Log.Debugf("dispatching async organization update message for organization: %s", o.ID)
		payload, _ := json.Marshal(map[string]interface{}{
			"organization_id": o.ID.String(),
		})
		natsutil.NatsStreamingPublish(natsOrganizationUpdatedInitSubject, payload)

		if common.Auth0IntegrationEnabled {
		}
	}

	tx.Commit()
	return success
}

// FullName returns the organizations full name; see Invitor interface
func (o *Organization) FullName() *string {
	return o.Name
}

// Enrich an organization
func (o *Organization) Enrich(db *gorm.DB, keyType *string) {

}

// validate an organization for persistence
func (o *Organization) validate() bool {
	o.Errors = make([]*provide.Error, 0)
	return len(o.Errors) == 0
}

// Delete an organization
func (o *Organization) Delete() bool {
	db := dbconf.DatabaseConnection()
	tx := db.Begin()
	result := tx.Delete(&o)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			o.Errors = append(o.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}
	success := len(o.Errors) == 0
	if success && common.Auth0IntegrationEnabled {
		common.Log.Debugf("deleted organization: %s", *o.Name)
	}
	tx.Commit()
	return success
}

// ParseMetadata - parse the Organization JSON metadata
func (o *Organization) ParseMetadata() map[string]interface{} {
	metadata := map[string]interface{}{}
	if o.Metadata != nil {
		err := json.Unmarshal(*o.Metadata, &metadata)
		if err != nil {
			common.Log.Warningf("Failed to unmarshal organization metadata; %s", err.Error())
			return nil
		}
	}
	return metadata
}

func (o *Organization) setMetadata(metadata map[string]interface{}) {
	metadataJSON, _ := json.Marshal(metadata)
	_metadataJSON := json.RawMessage(metadataJSON)
	o.Metadata = &_metadataJSON
}
