package main

import (
	"fmt"
	"os"
	"sync"

	logger "github.com/kthomas/go-logger"
)

var (
	// Log is the logger instancee to use within ident.
	Log *logger.Logger
	// ListenAddr is the constructed IP and port that is listening as configured.
	ListenAddr string
	// CertificatePath is the path to the certificate as configured in the environment.
	CertificatePath string
	// PrivateKeyPath is the path to the private key as configured in the environment.
	PrivateKeyPath string

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
		ListenAddr = os.Getenv("LISTEN_ADDR")
		if ListenAddr == "" {
			ListenAddr = buildListenAddr()
		}

		if os.Getenv("CERTIFICATE_PATH") != "" {
			CertificatePath = os.Getenv("CERTIFICATE_PATH")
		}

		if os.Getenv("PRIVATE_KEY_PATH") != "" {
			PrivateKeyPath = os.Getenv("PRIVATE_KEY_PATH")
		}

		if os.Getenv("SIA_API_KEY") != "" {
			siaAPIKey = os.Getenv("SIA_API_KEY")
		}

		lvl := os.Getenv("LOG_LEVEL")
		if lvl == "" {
			lvl = "INFO"
		}
		Log = logger.NewLogger("ident", lvl, true)
	})
}

func buildListenAddr() string {
	listenPort := os.Getenv("PORT")
	if listenPort == "" {
		listenPort = "8080"
	}
	return fmt.Sprintf("0.0.0.0:%s", listenPort)
}

func shouldServeTLS() bool {
	var tls = false
	if _, err := os.Stat(CertificatePath); err == nil {
		if _, err := os.Stat(PrivateKeyPath); err == nil {
			tls = true
		}
	}
	return tls
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
