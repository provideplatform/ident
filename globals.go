package main

import (
	"fmt"
	"os"
	"sync"

	logger "github.com/kthomas/go-logger"
)

var (
	Log *logger.Logger

	ListenAddr      string
	CertificatePath string
	PrivateKeyPath  string

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
