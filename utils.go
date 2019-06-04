package main

import (
	"errors"

	dbconf "github.com/kthomas/go-db-config"
)

// PGPPubDecrypt decrypts data previously encrypted using pgp_pub_encrypt
func PGPPubDecrypt(encryptedVal, gpgPrivateKey, gpgPassword string) ([]byte, error) {
	results := make([]byte, 1)
	db := dbconf.DatabaseConnection()
	rows, err := db.Raw("SELECT pgp_pub_decrypt(?, dearmor(?), ?) as val", encryptedVal, gpgPrivateKey, gpgPassword).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if err != nil {
		return nil, err
	}
	if rows.Next() {
		rows.Scan(&results)
		return results, nil
	}
	return nil, errors.New("Failed to decrypt record from encrypted storage")
}

// PGPPubEncrypt encrypts data using using pgp_pub_encrypt
func PGPPubEncrypt(unencryptedVal, gpgPublicKey string) (*string, error) {
	out := []string{}
	db := dbconf.DatabaseConnection()
	db.Raw("SELECT pgp_pub_encrypt(?, dearmor(?))", unencryptedVal, gpgPublicKey).Pluck("val", &out)
	return stringOrNil(out[0]), nil
}
