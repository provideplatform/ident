package main

import (
	"errors"
	"sync"
	"time"

	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	stan "github.com/nats-io/stan.go"
)

var natsStreamingConnectionMutex sync.Mutex

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

// EstablishNATSStreamingConnection establishes (if conn is nil) or reestablishes the given NATS streaming connection
func EstablishNATSStreamingConnection() error {
	natsStreamingConnectionMutex.Lock()
	defer natsStreamingConnectionMutex.Unlock()

	natsConnection, err := natsutil.GetNatsStreamingConnection(30*time.Second, func(conn stan.Conn, err error) {
		EstablishNATSStreamingConnection()
	})
	if err != nil {
		log.Warningf("Failed to establish NATS connection; %s", err.Error())
		return err
	}
	SharedNatsConnection = natsConnection
	return nil
}

// GetSharedNatsStreamingConnection retrieves the NATS streaming connection
func GetSharedNatsStreamingConnection() (*stan.Conn, error) {
	if SharedNatsConnection != nil {
		conn := (*SharedNatsConnection).NatsConn()
		if conn != nil && !conn.IsClosed() && !conn.IsDraining() && !conn.IsReconnecting() {
			return SharedNatsConnection, nil
		}
	}

	err := EstablishNATSStreamingConnection()
	if err != nil {
		log.Warningf("Failed to establish NATS connection; %s", err.Error())
		return SharedNatsConnection, err
	}
	return SharedNatsConnection, nil
}

// NATSPublish a NATS message to the configured NATS streaming environment
func NATSPublish(subject string, msg []byte) error {
	natsConnection, err := GetSharedNatsStreamingConnection()
	if err != nil {
		log.Warningf("Failed to retrieve shared NATS streaming connection for Publish; %s", err.Error())
		return err
	}
	return (*natsConnection).Publish(subject, msg)
}
