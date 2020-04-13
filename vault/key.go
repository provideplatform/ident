package vault

import (
	"fmt"

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
