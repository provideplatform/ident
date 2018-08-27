package main

import (
	"fmt"
	"os"
	"sync"

	"github.com/gin-gonic/gin"
	logger "github.com/kthomas/go-logger"
	newrelic "github.com/newrelic/go-agent"
)

var (
	Log *logger.Logger

	ListenAddr      string
	CertificatePath string
	PrivateKeyPath  string

	newrelicLicenseKey string

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

		if os.Getenv("NEW_RELIC_LICENSE_KEY") != "" {
			newrelicLicenseKey = os.Getenv("NEW_RELIC_LICENSE_KEY")
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

func configureNewRelicTransactionMiddleware(r *gin.Engine) {
	newrelicApp := configureNewRelic("ident")
	if newrelicApp == nil {
		return
	}

	app := *newrelicApp
	r.Use(func(c *gin.Context) {
		app.StartTransaction(c.HandlerName(), c.Writer, c.Request)
	})

	Log.Debug("Configured newrelic transaction middleware")
}

// ConfigureNewRelic returns an initialized newrelic application instance,
// or nil if it was unable to be initialized
func configureNewRelic(appName string) *newrelic.Application {
	if newrelicLicenseKey == "" {
		return nil
	}
	config := newrelic.NewConfig(appName, newrelicLicenseKey)
	app, err := newrelic.NewApplication(config)
	if err != nil {
		return nil
	}
	return &app
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
