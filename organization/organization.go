package organization

import (
	"encoding/json"

	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	"github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/ident/common"
	"github.com/provideapp/ident/user"
	provide "github.com/provideservices/provide-go"
)

const natsSiaOrganizationNotificationSubject = "sia.user.notification"
const organizationResourceKey = "organization"

// Organization model
type Organization struct {
	provide.Model
	Name        *string           `sql:"not null" json:"name"`
	UserID      *uuid.UUID        `json:"user_id,omitempty"`
	Description *string           `json:"description"`
	Permissions common.Permission `sql:"not null" json:"permissions,omitempty"`

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
	}

	if !o.validate() {
		return false
	}

	if db.NewRecord(o) {
		tx := db.Begin()
		result := tx.Create(&o)
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
						if o.addUser(tx, *usr, common.DefaultApplicationResourcePermission) {
							common.Log.Debugf("associated user %s with organization: %s", *usr.Name, *o.Name)
							tx.Commit()
						} else {
							common.Log.Warningf("failed to associate user %s with organization: %s", *usr.Name, *o.Name)
							tx.Rollback()
							return false
						}
					} else {
						tx.Commit()
					}
				}

				if success {
					payload, _ := json.Marshal(o)
					natsutil.NatsPublish(natsSiaOrganizationNotificationSubject, payload)
				}

				return success
			}
		}

		tx.Rollback()
	}

	return false
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

	if success && common.Auth0IntegrationEnabled {
		common.Log.Debugf("updated organization: %s", *o.Name)
	}

	tx.Commit()
	return success
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
