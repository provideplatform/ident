package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"sync"

	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	"github.com/kthomas/go-pgputil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/ident/common"
	provide "github.com/provideservices/provide-go"
)

const keyTypeAsymmetric = "asymmetric"
const keyTypeSymmetric = "symmetric"

const keyUsageEncryptDecrypt = "encrypt/decrypt"
const keyUsageSignVerify = "sign/verify"

const keySpecAES256GCM = "AES-256-GCM"
const keySpecECCEd25519 = "Ed25519"
const keySpecECCSecp256r1 = "ECC-NIST-P256"
const keySpecECCSecp2048 = "ECC-NIST-P384"
const keySpecECCSecp521r1 = "ECC-NIST-P521"
const keySpecECCSecpP256k1 = "ECC-SECG-P256K1"
const keySpecRSA2048 = "RSA-2048"
const keySpecRSA3072 = "RSA-3072"
const keySpecRSA4096 = "RSA-4096"

// Key represents a symmetric or asymmetric signing key
type Key struct {
	provide.Model
	VaultID     *uuid.UUID `sql:"not null;type:uuid" json:"vault_id"`
	Type        *string    `sql:"not null" json:"type"`  // symmetric or asymmetric
	Usage       *string    `sql:"not null" json:"usage"` // encrypt/decrypt or sign/verify (sign/verify only valid for asymmetric keys)
	Spec        *string    `sql:"not null" json:"spec"`
	Name        *string    `sql:"not null" json:"name"`
	Description *string    `json:"description"`
	Seed        *string    `sql:"type:bytea" json:"-"`
	PublicKey   *string    `sql:"type:bytea" json:"public_key,omitempty"`
	PrivateKey  *string    `sql:"type:bytea" json:"-"`

	encrypted bool       `sql:"-"`
	mutex     sync.Mutex `sql:"-"`
}

func (k *Key) createEd25519Keypair(name, description string) (*Key, error) {
	keypair, err := CreatePair(PrefixByteSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to create Ed25519 keypair; %s", err.Error())
	}

	seed, err := keypair.Seed()
	if err != nil {
		return nil, fmt.Errorf("failed to read encoded seed of Ed25519 keypair; %s", err.Error())
	}

	publicKey, err := keypair.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to read public key of Ed25519 keypair; %s", err.Error())
	}

	ed25519Key := &Key{
		VaultID:     k.VaultID,
		Type:        common.StringOrNil(keyTypeAsymmetric),
		Usage:       common.StringOrNil(keyUsageSignVerify),
		Spec:        common.StringOrNil(keySpecECCEd25519),
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		PublicKey:   common.StringOrNil(publicKey),
		Seed:        common.StringOrNil(string(seed)),
	}

	db := dbconf.DatabaseConnection()
	if !ed25519Key.Create(db) {
		return nil, fmt.Errorf("failed to create Ed25519 key in vault: %s; %s", k.VaultID, *ed25519Key.Errors[0].Message)
	}

	common.Log.Debugf("created Ed25519 key %s with %d-byte seed in vault: %s; public key: %s", ed25519Key.ID, len(seed), k.VaultID, *ed25519Key.PublicKey)
	return ed25519Key, nil
}

func (k *Key) resolveMasterKey() (*Key, error) {
	var masterKey *Key
	var err error

	vault := &Vault{}
	if k.VaultID == nil {
		return nil, fmt.Errorf("unable to resolve master key without vault id for key: %s", k.ID)
	}

	db := dbconf.DatabaseConnection()
	db.Where("id = ?", k.VaultID).Find(&vault)
	if vault == nil || vault.ID == uuid.Nil {
		return nil, fmt.Errorf("failed to resolve master key; no vault found for key: %s; vault id: %s", k.ID, k.VaultID)
	}

	if vault.MasterKeyID != nil && vault.MasterKeyID.String() == k.ID.String() {
		return nil, fmt.Errorf("unable to resolve master key: %s; current key is master; vault id: %s", k.ID, k.VaultID)
	}

	masterKey, err = vault.resolveMasterKey(db)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve master key for key: %s; %s", k.ID, err.Error())
	}

	return masterKey, err
}

func (k *Key) decryptFields() error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	if !k.encrypted {
		return fmt.Errorf("fields already decrypted for key: %s", k.ID)
	}

	masterKey, err := k.resolveMasterKey()
	if err != nil {
		common.Log.Debugf("decrypting master key fields for vault: %s", k.VaultID)

		if k.Seed != nil {
			seed, err := pgputil.PGPPubDecrypt([]byte(*k.Seed))
			if err != nil {
				return err
			}
			k.Seed = common.StringOrNil(string(seed))
		}

		if k.PrivateKey != nil {
			privateKey, err := pgputil.PGPPubDecrypt([]byte(*k.PrivateKey))
			if err != nil {
				return err
			}
			k.PrivateKey = common.StringOrNil(string(privateKey))
		}
	} else {
		common.Log.Debugf("decrypting key fields with master key %s for vault: %s", masterKey.ID, k.VaultID)

		masterKey.decryptFields()
		defer masterKey.encryptFields()

		if k.Seed != nil {
			seed, err := masterKey.Decrypt([]byte(*k.Seed))
			if err != nil {
				return err
			}
			k.Seed = common.StringOrNil(string(seed))
		}

		if k.PrivateKey != nil {
			privateKey, err := masterKey.Decrypt([]byte(*k.PrivateKey))
			if err != nil {
				return err
			}
			k.PrivateKey = common.StringOrNil(string(privateKey))
		}
	}

	k.encrypted = false
	return nil
}

func (k *Key) encryptFields() error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	if k.encrypted {
		return fmt.Errorf("fields already encrypted for key: %s", k.ID)
	}

	masterKey, err := k.resolveMasterKey()
	if err != nil {
		common.Log.Debugf("encrypting master key fields for vault: %s", k.VaultID)

		if k.Seed != nil {
			seed, err := pgputil.PGPPubEncrypt([]byte(*k.Seed))
			if err != nil {
				return err
			}
			k.Seed = common.StringOrNil(string(seed))
		}

		if k.PrivateKey != nil {
			privateKey, err := pgputil.PGPPubEncrypt([]byte(*k.PrivateKey))
			if err != nil {
				return err
			}
			k.PrivateKey = common.StringOrNil(string(privateKey))
		}
	} else {
		common.Log.Debugf("encrypting key fields with master key %s for vault: %s", masterKey.ID, k.VaultID)

		masterKey.decryptFields()
		defer masterKey.encryptFields()

		if k.Seed != nil {
			seed, err := masterKey.Encrypt([]byte(*k.Seed))
			if err != nil {
				return err
			}
			k.Seed = common.StringOrNil(string(seed))
		}

		if k.PrivateKey != nil {
			privateKey, err := masterKey.Encrypt([]byte(*k.PrivateKey))
			if err != nil {
				return err
			}
			k.PrivateKey = common.StringOrNil(string(privateKey))
		}
	}

	k.encrypted = true
	return nil
}

// Create and persist a key
func (k *Key) Create(db *gorm.DB) bool {
	if !k.validate() {
		return false
	}

	if db.NewRecord(k) {
		result := db.Create(&k)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				k.Errors = append(k.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
		if !db.NewRecord(k) {
			success := rowsAffected > 0
			if success {
				common.Log.Debugf("created key %s (%s) in vault %s", *k.Name, k.ID.String(), k.VaultID.String())
				return success
			}
		}
	}

	return false
}

// Decrypt a ciphertext using the key according to its spec
func (k *Key) Decrypt(ciphertext []byte) ([]byte, error) {
	if k.Usage == nil || *k.Usage != keyUsageEncryptDecrypt {
		return nil, fmt.Errorf("failed to decrypt %d-byte ciphertext using key: %s; nil or invalid key usage", len(ciphertext), k.ID)
	}

	if k.Type != nil && *k.Type == keyTypeSymmetric {
		return k.decryptSymmetric(ciphertext[12:], ciphertext[0:11])
	}

	if k.Type != nil && *k.Type == keyTypeAsymmetric {
		return k.decryptAsymmetric(ciphertext)
	}

	return nil, fmt.Errorf("failed to decrypt %d-byte ciphertext using key: %s; nil or invalid key type", len(ciphertext), k.ID)
}

// decryptAsymmetric attempts asymmetric decryption using the key;
// returns the plaintext and any error
func (k *Key) decryptAsymmetric(ciphertext []byte) ([]byte, error) {
	// k.mutex.Lock()
	// defer k.mutex.Unlock()

	k.decryptFields()
	defer k.encryptFields()

	return nil, nil
}

// decryptSymmetric attempts symmetric AES-256 GCM decryption using the key;
// returns the plaintext and any error
func (k *Key) decryptSymmetric(ciphertext, nonce []byte) ([]byte, error) {
	// k.mutex.Lock()
	// defer k.mutex.Unlock()

	// k.decryptFields()
	// defer k.encryptFields()

	if k.PrivateKey == nil {
		return nil, fmt.Errorf("failed to decrypt using key: %s; nil private key", k.ID)
	}

	k.decryptFields()
	defer k.encryptFields()

	key := []byte(*k.PrivateKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt using key: %s; %s", k.ID, err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt using key: %s; %s", k.ID, err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return plaintext, nil
}

// Encrypt the given plaintext with the key, according to its spec
func (k *Key) Encrypt(plaintext []byte) ([]byte, error) {
	if k.Usage == nil || *k.Usage != keyUsageEncryptDecrypt {
		return nil, fmt.Errorf("failed to encrypt %d-byte plaintext using key: %s; nil or invalid key usage", len(plaintext), k.ID)
	}

	if k.Type != nil && *k.Type == keyTypeSymmetric {
		return k.encryptSymmetric(plaintext)
	}

	if k.Type != nil && *k.Type == keyTypeAsymmetric {
		return k.encryptAsymmetric(plaintext)
	}

	return nil, fmt.Errorf("failed to encrypt %d-byte plaintext using key: %s; nil or invalid key type", len(plaintext), k.ID)
}

// encryptAsymmetric attempts asymmetric encryption using the public/private keypair;
// returns the ciphertext any error
func (k *Key) encryptAsymmetric(plaintext []byte) ([]byte, error) {
	if k.Type == nil || *k.Type != keyTypeAsymmetric {
		return nil, fmt.Errorf("failed to asymmetrically encrypt using key: %s; nil or invalid key type", k.ID)
	}

	k.decryptFields()
	defer k.encryptFields()

	return nil, nil
}

// encryptSymmetric attempts symmetric AES-256 GCM encryption using the key;
// returns the ciphertext-- with 12-byte nonce prepended-- and any error
func (k *Key) encryptSymmetric(plaintext []byte) ([]byte, error) {
	if k.Type == nil || *k.Type != keyTypeSymmetric {
		return nil, fmt.Errorf("failed to symmetrically encrypt using key: %s; nil or invalid key type", k.ID)
	}

	if k.PrivateKey == nil {
		return nil, fmt.Errorf("failed to encrypt using key: %s; nil private key", k.ID)
	}

	k.decryptFields()
	defer k.encryptFields()

	key := []byte(*k.PrivateKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt using key: %s; %s", k.ID, err.Error())
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to encrypt using key: %s; %s", k.ID, err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt using key: %s; %s", k.ID, err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce[:], ciphertext[:]...), nil
}

// Sign the input with the private key
func (k *Key) Sign(payload []byte) ([]byte, error) {
	if k.Type == nil && *k.Type != keyTypeAsymmetric {
		return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil or invalid key type", len(payload), k.ID)
	}

	if k.Usage == nil || *k.Usage != keyUsageSignVerify {
		return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil or invalid key usage", len(payload), k.ID)
	}

	if k.Spec == nil || *k.Spec != keySpecECCEd25519 {
		return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil or invalid key spec", len(payload), k.ID)
	}

	k.decryptFields()
	defer k.encryptFields()

	switch *k.Spec {
	case keySpecECCEd25519:
		if k.Seed == nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil Ed25519 seed", len(payload), k.ID)
		}
		ec25519Key, err := FromSeed([]byte(*k.Seed))
		if err != nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; %s", len(payload), k.ID, err.Error())
		}
		return ec25519Key.Sign(payload)
	}

	return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; sign() not yet implemented", len(payload), k.ID)
}

// Verify the given payload against a signature using the public key
func (k *Key) Verify(payload, sig []byte) error {
	if k.Type == nil && *k.Type != keyTypeAsymmetric {
		return fmt.Errorf("failed to verify %d-byte payload using key: %s; nil or invalid key type", len(payload), k.ID)
	}

	if k.Usage == nil || *k.Usage != keyUsageSignVerify {
		return fmt.Errorf("failed to verify %d-byte payload using key: %s; nil or invalid key usage", len(payload), k.ID)
	}

	if k.Spec == nil || *k.Spec != keySpecECCEd25519 {
		return fmt.Errorf("failed to verify %d-byte payload using key: %s; nil or invalid key spec", len(payload), k.ID)
	}

	if k.PublicKey == nil {
		return fmt.Errorf("failed to verify %d-byte payload using key: %s; nil public key", len(payload), k.ID)
	}

	k.decryptFields()
	defer k.encryptFields()

	switch *k.Spec {
	case keySpecECCEd25519:
		ec25519Key, err := FromPublicKey(*k.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to verify %d-byte payload using key: %s; %s", len(payload), k.ID, err.Error())
		}
		return ec25519Key.Verify(payload, sig)
	}

	return fmt.Errorf("failed to verify %d-byte payload using key: %s; sign() not yet implemented", len(payload), k.ID)
}

func (k *Key) validate() bool {
	k.Errors = make([]*provide.Error, 0)

	if k.Name == nil {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil("key name required"),
		})
	}

	if k.Spec == nil {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil("key spec required"),
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
	} else if *k.Type == keyTypeSymmetric && *k.Usage == keyUsageEncryptDecrypt && (k.Spec == nil || *k.Spec != keySpecAES256GCM) {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("symmetric key in %s usage mode must be %s", keyUsageEncryptDecrypt, keySpecAES256GCM)), // TODO: support keySpecRSA2048, keySpecRSA3072, keySpecRSA4096
		})
	} else if *k.Type == keyTypeAsymmetric && *k.Usage == keyUsageSignVerify && (k.Spec == nil || *k.Spec != keySpecECCEd25519) {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("assymmetric key in %s usage mode must be %s", keyUsageSignVerify, keySpecECCEd25519)), // TODO: support keySpecRSA2048, keySpecRSA3072, keySpecRSA4096
		})
	}

	if !k.encrypted {
		err := k.encryptFields()
		if err != nil {
			k.Errors = append(k.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}

	return len(k.Errors) == 0
}
