package vault

import (
	"fmt"

	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/ident/common"
	provide "github.com/provideservices/provide-go"
)

const keyTypeAsymmetric = "asymmetric"
const keyTypeSymmetric = "symmetric"

const keyUsageEncryptDecrypt = "encrypt/decrypt"
const keyUsageSignVerify = "sign/verify"

const keySpecECCSecp256r1 = "ECC_NIST_P256"
const keySpecECCSecp2048 = "ECC_NIST_P384"
const keySpecECCSecp521r1 = "ECC_NIST_P521"
const keySpecECCSecpP256k1 = "ECC_SECG_P256K1"
const keySpecRSA2048 = "RSA_2048"
const keySpecRSA3072 = "RSA_3072"
const keySpecRSA4096 = "RSA_4096"

// Key represents a symmetric or asymmetric signing key
type Key struct {
	provide.Model
	VaultID     *uuid.UUID `sql:"not null;type:uuid" json:"vault_id"`
	Type        *string    `sql:"not null" json:"type"`  // symmetric or asymmetric
	Usage       *string    `sql:"not null" json:"usage"` // encrypt/decrypt or sign/verify (sign/verify only valid for asymmetric keys)
	Name        *string    `sql:"not null" json:"name"`
	Description *string    `json:"description"`
	Seed        *string    `sql:"type:bytea" json:"-"`
	PublicKey   *string    `sql:"type:bytea" json:"public_key,omitempty"`
	PrivateKey  *string    `sql:"not null;type:bytea" json:"-"`
}

func (k *Key) validate() bool {
	k.Errors = make([]*provide.Error, 0)

	if k.Name == nil {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil("key name required"),
		})
	}

	if k.Type == nil {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil("key type required"),
		})
	} else if *k.Type != keyTypeAsymmetric && *k.Type != keyTypeSymmetric {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("key type must be one of %s or %s", keyTypeAsymmetric, keyTypeSymmetric)),
		})
	} else if *k.Type == keyTypeSymmetric && *k.Usage != keyUsageEncryptDecrypt {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("symmetric key requires %s usage mode", keyUsageEncryptDecrypt)),
		})
	} else if *k.Type == keyTypeAsymmetric && *k.Usage == keyUsageEncryptDecrypt {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("asymmetric key in %s usage mode must be one of %s, %s, %s", keyUsageEncryptDecrypt, keySpecRSA2048, keySpecRSA3072, keySpecRSA4096)),
		})
	}

	return len(k.Errors) == 0
}

// Vault provides secure key management
type Vault struct {
	provide.Model

	// Associations
	ApplicationID  *uuid.UUID `sql:"type:uuid" json:"-"`
	OrganizationID *uuid.UUID `sql:"type:uuid" json:"-"`
	UserID         *uuid.UUID `sql:"type:uuid" json:"-"`

	Name        *string `json:"name"`
	Description *string `json:"description"`

	MasterKey   *Key       `sql:"-" json:"master_key"`
	MasterKeyID *uuid.UUID `sql:"type:uuid" json:"master_key_id"`
}

func (v *Vault) listKeysQuery(db *gorm.DB) *gorm.DB {
	return db.Select("keys.id, keys.created_at, keys.name, keys.description, keys.type, keys.usage, keys.vault_id").Where("keys.vault_id = ?", v.ID)
}

func (v *Vault) resolveMasterKey(db *gorm.DB) (*Key, error) {
	masterKey := &Key{}
	db.Where("id = ?", v.MasterKeyID).Find(&masterKey)
	if masterKey == nil || masterKey.ID == uuid.Nil {
		return nil, fmt.Errorf("failed to resolve master key for vault: %s", v.ID)
	}
	v.MasterKey = masterKey
	return v.MasterKey, nil
}

func (v *Vault) validate() bool {
	v.Errors = make([]*provide.Error, 0)

	if v.ApplicationID == nil && v.OrganizationID == nil && v.UserID == nil {
		v.Errors = append(v.Errors, &provide.Error{
			Message: common.StringOrNil("must be associated with an application, organization or user"),
		})
	}

	if v.MasterKey == nil {
		v.Errors = append(v.Errors, &provide.Error{
			Message: common.StringOrNil("master key required"),
		})
	}

	return len(v.Errors) == 0
}

// Create and persist a vault
func (v *Vault) Create(tx *gorm.DB) bool {
	var db *gorm.DB
	if tx != nil {
		db = tx
	} else {
		db = dbconf.DatabaseConnection()
		db = db.Begin()
		defer db.RollbackUnlessCommitted()
	}

	if !v.validate() {
		return false
	}

	if db.NewRecord(v) {
		result := db.Create(&v)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				v.Errors = append(v.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
		if !db.NewRecord(v) {
			success := rowsAffected > 0
			if success {
				common.Log.Debugf("created vault %s", v.ID.String())
				if tx == nil {
					db.Commit()
				}

				return success
			}
		}
	}

	return false
}

// Delete a vault
func (v *Vault) Delete(tx *gorm.DB) bool {
	if v.ID == uuid.Nil {
		common.Log.Warning("attempted to delete vault instance")
		return false
	}

	var db *gorm.DB
	if tx != nil {
		db = tx
	} else {
		db = dbconf.DatabaseConnection()
		db = db.Begin()
		defer db.RollbackUnlessCommitted()
	}

	result := db.Delete(&v)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			v.Errors = append(v.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}
	success := len(v.Errors) == 0
	return success
}

// GetApplicationVaults - retrieve the vaults associated with the given application
func GetApplicationVaults(applicationID *uuid.UUID) []*Vault {
	var vaults []*Vault
	dbconf.DatabaseConnection().Where("application_id = ?", applicationID).Find(&vaults)
	return vaults
}

// GetOrganizationVaults - retrieve the vaults associated with the given organization
func GetOrganizationVaults(organizationID *uuid.UUID) []*Vault {
	var vaults []*Vault
	dbconf.DatabaseConnection().Where("organization_id = ?", organizationID).Find(&vaults)
	return vaults
}
