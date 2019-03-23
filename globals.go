package main

import (
	"fmt"
	"os"
	"sync"

	logger "github.com/kthomas/go-logger"
	selfsignedcert "github.com/kthomas/go-self-signed-cert"
	nats "github.com/nats-io/go-nats"
	"github.com/nats-io/go-nats-streaming"
)

var (
	log        *logger.Logger
	listenAddr string

	certificatePath string
	privateKeyPath  string
	requireTLS      bool

	natsConsumerConcurrency uint64
	natsConnection          *nats.Conn
	natsStreamingConnection *stan.Conn
	natsToken               string
	natsURL                 string
	natsStreamingURL        string

	siaAPIKey string

	bootstrapOnce sync.Once
)

func bootstrap() {
	bootstrapOnce.Do(func() {
		listenAddr = os.Getenv("LISTEN_ADDR")
		if listenAddr == "" {
			listenAddr = buildlistenAddr()
		}

		requireTLS = os.Getenv("REQUIRE_TLS") == "true"

		if os.Getenv("SIA_API_KEY") != "" {
			siaAPIKey = os.Getenv("SIA_API_KEY")
		}

		lvl := os.Getenv("LOG_LEVEL")
		if lvl == "" {
			lvl = "INFO"
		}
		log = logger.NewLogger("ident", lvl, true)
	})
}

func buildlistenAddr() string {
	listenPort := os.Getenv("PORT")
	if listenPort == "" {
		listenPort = "8080"
	}
	return fmt.Sprintf("0.0.0.0:%s", listenPort)
}

func shouldServeTLS() bool {
	if requireTLS {
		privKeyPath, certPath, err := selfsignedcert.GenerateToDisk()
		if err != nil {
			log.Panicf("Failed to generate self-signed certificate; %s", err.Error())
		}
		privateKeyPath = *privKeyPath
		certificatePath = *certPath
		return true
	}
	return false
}

func panicIfEmpty(val string, msg string) {
	if val == "" {
		panic(msg)
	}
}

func stringOrNil(str string) *string {
	if str == "" {
		return nil
	}
	return &str
}
