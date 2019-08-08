package main

import (
	"sync"
	"time"

	natsutil "github.com/kthomas/go-natsutil"
	stan "github.com/nats-io/stan.go"
)

var natsStreamingConnectionMutex sync.Mutex

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
