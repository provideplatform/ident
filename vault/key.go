package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common/math"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	"github.com/kthomas/go-pgputil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/ident/common"
	identcrypto "github.com/provideapp/ident/vault/crypto"
	provide "github.com/provideservices/provide-go"
)

const keyTypeAsymmetric = "asymmetric"
const keyTypeSymmetric = "symmetric"

const keyUsageEncryptDecrypt = "encrypt/decrypt"
const keyUsageSignVerify = "sign/verify"

const keySpecAES256GCM = "AES-256-GCM"
const keySpecECCBabyJubJub = "babyJubJub"
const keySpecECCC25519 = "C25519"
const keySpecECCEd25519 = "Ed25519"
const keySpecECCSecp256k1 = "secp256k1"

// const keySpecECCSecp256r1 = "ECC-NIST-P256"
// const keySpecECCSecp2048 = "ECC-NIST-P384"
// const keySpecECCSecp521r1 = "ECC-NIST-P521"
// const keySpecECCSecpP256k1 = "ECC-SECG-P256K1"
// const keySpecRSA2048 = "RSA-2048"
// const keySpecRSA3072 = "RSA-3072"
// const keySpecRSA4096 = "RSA-4096"

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

	Address   *string    `sql:"-" json:"address,omitempty"`
	encrypted *bool      `sql:"-"`
	mutex     sync.Mutex `sql:"-"`
}

// KeyExchangeRequestResponse represents the API request/response parameters
// // needed to initiate or reciprocate a Diffie-Hellman key exchange
// type KeyExchangeRequestResponse struct {
// 	PublicKey  *string `json:"public_key,omitempty"`
// 	SigningKey *string `json:"signing_key,omitempty"`
// 	Signature  *string `json:"signature,omitempty"`
// }

// KeySignVerifyRequestResponse represents the API request/response parameters
// needed to sign or verify an arbitrary message
type KeySignVerifyRequestResponse struct {
	Message   *string `json:"message,omitempty"`
	Signature *string `json:"signature,omitempty"`
	Verified  *bool   `json:"verified,omitempty"`
}

// CreateBabyJubJubKeypair creates a keypair on the twisted edwards babyJubJub curve
func (k *Key) CreateBabyJubJubKeypair(name, description string) (*Key, error) {
	publicKey, privateKey, err := provide.TECGenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to create babyJubJub keypair; %s", err.Error())
	}

	babyJubJubKey := &Key{
		VaultID:     k.VaultID,
		Type:        common.StringOrNil(keyTypeAsymmetric),
		Usage:       common.StringOrNil(keyUsageSignVerify),
		Spec:        common.StringOrNil(keySpecECCBabyJubJub),
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		PublicKey:   common.StringOrNil(string(publicKey)),
		PrivateKey:  common.StringOrNil(string(privateKey)),
	}

	db := dbconf.DatabaseConnection()
	if !babyJubJubKey.Create(db) {
		return nil, fmt.Errorf("failed to create babyJubJub key in vault: %s; %s", k.VaultID, *babyJubJubKey.Errors[0].Message)
	}

	common.Log.Debugf("created babyJubJub key %s in vault: %s; public key: %s", babyJubJubKey.ID, k.VaultID, *babyJubJubKey.PublicKey)
	return babyJubJubKey, nil
}

// CreateDiffieHellmanSharedSecret creates a shared secret given a peer public key and signature
func (k *Key) CreateDiffieHellmanSharedSecret(peerPublicKey, peerSigningKey, peerSignature []byte, name, description string) (*Key, error) {
	k.decryptFields()
	defer k.encryptFields()

	if k.PrivateKey == nil {
		err := errors.New("failed to calculate Diffie-Hellman shared secret; nil private key")
		common.Log.Warning(err.Error())
		return nil, err
	}

	ec25519Key, err := identcrypto.FromPublicKey(string(peerSigningKey))
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret; failed to unmarshal %d-byte Ed22519 public key: %s", len(peerPublicKey), string(peerPublicKey))
	}
	err = ec25519Key.Verify(peerPublicKey, peerSignature)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret; failed to verify %d-byte Ed22519 signature using public key: %s; %s", len(peerSignature), string(peerPublicKey), err.Error())
	}

	sharedSecret := provide.C25519ComputeSecret([]byte(*k.PrivateKey), peerPublicKey)

	dhSecret := &Key{
		VaultID:     k.VaultID,
		Type:        common.StringOrNil(keyTypeAsymmetric),
		Usage:       common.StringOrNil(keyUsageSignVerify),
		Spec:        common.StringOrNil(keySpecECCC25519),
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Seed:        common.StringOrNil(string(sharedSecret)),
	}

	db := dbconf.DatabaseConnection()
	if !dhSecret.Create(db) {
		return nil, fmt.Errorf("failed to create Diffie-Hellman shared secret in vault: %s; %s", k.VaultID, *dhSecret.Errors[0].Message)
	}

	common.Log.Debugf("created Diffie-Hellman shared secret %s in vault: %s; public key: %s", dhSecret.ID, k.VaultID, *dhSecret.PublicKey)
	return dhSecret, nil
}

// CreateEd25519Keypair creates an Ed25519 keypair
func (k *Key) CreateEd25519Keypair(name, description string) (*Key, error) {
	keypair, err := identcrypto.CreatePair(identcrypto.PrefixByteSeed)
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

// CreateSecp256k1Keypair creates a keypair on the secp256k1 curve
func (k *Key) CreateSecp256k1Keypair(name, description string) (*Key, error) {
	address, privkey, err := provide.EVMGenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to create babyJubJub keypair; %s", err.Error())
	}

	publicKey := elliptic.Marshal(secp256k1.S256(), privkey.PublicKey.X, privkey.PublicKey.Y)
	privateKey := math.PaddedBigBytes(privkey.D, privkey.Params().BitSize/8)
	desc := fmt.Sprintf("%s; address: %s", description, *address)

	secp256k1Key := &Key{
		VaultID:     k.VaultID,
		Type:        common.StringOrNil(keyTypeAsymmetric),
		Usage:       common.StringOrNil(keyUsageSignVerify),
		Spec:        common.StringOrNil(keySpecECCSecp256k1),
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(desc),
		PublicKey:   common.StringOrNil(string(publicKey)),
		PrivateKey:  common.StringOrNil(string(privateKey)),
	}

	db := dbconf.DatabaseConnection()
	if !secp256k1Key.Create(db) {
		return nil, fmt.Errorf("failed to create secp256k1 key in vault: %s; %s", k.VaultID, *secp256k1Key.Errors[0].Message)
	}

	common.Log.Debugf("created secp256k1 key %s in vault: %s; public key: %s", secp256k1Key.ID, k.VaultID, *secp256k1Key.PublicKey)
	return secp256k1Key, nil
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

func (k *Key) setEncrypted(encrypted bool) {
	k.encrypted = &encrypted
}

func (k *Key) decryptFields() error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	if k.encrypted == nil {
		k.setEncrypted(k.ID != uuid.Nil)
	}

	if !*k.encrypted {
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

	k.setEncrypted(false)
	return nil
}

func (k *Key) encryptFields() error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	if k.encrypted == nil {
		k.setEncrypted(k.ID != uuid.Nil)
	}

	if *k.encrypted {
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

	k.setEncrypted(true)
	return nil
}

// Enrich the key; typically a no-op; useful for public keys which
// have a compressed representation (i.e., crypto address)
func (k *Key) Enrich() {
	if k.Spec != nil && *k.Spec == keySpecECCSecp256k1 {
		if k.PublicKey != nil {
			x, y := elliptic.Unmarshal(secp256k1.S256(), []byte(*k.PublicKey))
			if x != nil {
				publicKey := &ecdsa.PublicKey{Curve: secp256k1.S256(), X: x, Y: y}
				addr := ethcrypto.PubkeyToAddress(*publicKey)
				k.Address = common.StringOrNil(addr.Hex())
			}
		}
	}
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
		return k.decryptSymmetric(ciphertext[12:], ciphertext[0:12])
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

	if k.Spec == nil || (*k.Spec != keySpecECCBabyJubJub && *k.Spec != keySpecECCEd25519 && *k.Spec != keySpecECCSecp256k1) {
		return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil or invalid key spec", len(payload), k.ID)
	}

	k.decryptFields()
	defer k.encryptFields()

	var sig []byte
	var sigerr error

	switch *k.Spec {
	case keySpecECCBabyJubJub:
		if k.PrivateKey == nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil private key", len(payload), k.ID)
		}
		sig, sigerr = provide.TECSign([]byte(*k.PrivateKey), payload)
	case keySpecECCEd25519:
		if k.Seed == nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil Ed25519 seed", len(payload), k.ID)
		}
		ec25519Key, err := identcrypto.FromSeed([]byte(*k.Seed))
		if err != nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; %s", len(payload), k.ID, err.Error())
		}
		sig, sigerr = ec25519Key.Sign(payload)
	case keySpecECCSecp256k1:
		if k.PrivateKey == nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil secp256k1 private key", len(payload), k.ID)
		}
		secp256k1Key, err := ethcrypto.ToECDSA([]byte(*k.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; %s", len(payload), k.ID, err.Error())
		}
		return secp256k1Key.Sign(rand.Reader, payload, nil)
	default:
		sigerr = fmt.Errorf("failed to sign %d-byte payload using key: %s; %s key spec not yet implemented", len(payload), k.ID, *k.Spec)
	}

	if sigerr != nil {
		return nil, sigerr
	}

	return sig, nil
}

// Verify the given payload against a signature using the public key
func (k *Key) Verify(payload, sig []byte) error {
	if k.Type == nil && *k.Type != keyTypeAsymmetric {
		return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil or invalid key type", len(payload), k.ID)
	}

	if k.Usage == nil || *k.Usage != keyUsageSignVerify {
		return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil or invalid key usage", len(payload), k.ID)
	}

	if k.Spec == nil || (*k.Spec != keySpecECCBabyJubJub && *k.Spec != keySpecECCEd25519 && *k.Spec != keySpecECCSecp256k1) {
		return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil or invalid key spec", len(payload), k.ID)
	}

	if k.PublicKey == nil {
		return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil public key", len(payload), k.ID)
	}

	k.decryptFields()
	defer k.encryptFields()

	switch *k.Spec {
	case keySpecECCBabyJubJub:
		if k.PublicKey == nil {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil public key", len(payload), k.ID)
		}
		return provide.TECVerify([]byte(*k.PublicKey), payload, sig)
	case keySpecECCEd25519:
		if k.PublicKey == nil {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil public key", len(payload), k.ID)
		}
		ec25519Key, err := identcrypto.FromPublicKey(*k.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; %s", len(payload), k.ID, err.Error())
		}
		return ec25519Key.Verify(payload, sig)
	case keySpecECCSecp256k1:
		if k.PublicKey == nil {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil public key", len(payload), k.ID)
		}
		x, y := elliptic.Unmarshal(secp256k1.S256(), []byte(*k.PublicKey))
		if x == nil {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; failed to unmarshal public key", len(payload), k.ID)
		}
		secp256k1Key := &ecdsa.PublicKey{Curve: secp256k1.S256(), X: x, Y: y}
		// TODO: unmarshal sig into r and s vals
		var r *big.Int
		var s *big.Int
		if !ecdsa.Verify(secp256k1Key, payload, r, s) {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s", len(payload), k.ID)
		}
		return nil
	}

	return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; %s key spec not yet implemented", len(payload), k.ID, *k.Spec)
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
	} else if *k.Type == keyTypeAsymmetric && *k.Usage == keyUsageSignVerify && (k.Spec == nil || (*k.Spec != keySpecECCBabyJubJub && *k.Spec != keySpecECCC25519 && *k.Spec != keySpecECCEd25519 && *k.Spec != keySpecECCSecp256k1)) {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("asymmetric key in %s usage mode must be %s, %s, %s or %s", keyUsageSignVerify, keySpecECCBabyJubJub, keySpecECCC25519, keySpecECCEd25519, keySpecECCSecp256k1)), // TODO: support keySpecRSA2048, keySpecRSA3072, keySpecRSA4096
		})
	}

	if k.encrypted == nil || !*k.encrypted {
		err := k.encryptFields()
		if err != nil {
			k.Errors = append(k.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}

	return len(k.Errors) == 0
}
