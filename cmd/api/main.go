package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/provideapp/ident/application"
	"github.com/provideapp/ident/common"
	"github.com/provideapp/ident/consumer"
	"github.com/provideapp/ident/kyc"
	"github.com/provideapp/ident/token"
	"github.com/provideapp/ident/user"

	provide "github.com/provideservices/provide-go"
)

const privacyPolicyUpdatedAt = "2018-10-19T00:00:00.000000"
const termsOfServiceUpdatedAt = "2018-10-19T00:00:00.000000"

const runloopSleepInterval = 250 * time.Millisecond
const runloopTickInterval = 5000 * time.Millisecond

var (
	cancelF     context.CancelFunc
	closing     uint32
	shutdownCtx context.Context
	sigs        chan os.Signal

	srv *http.Server
)

func init() {
	if common.ConsumeNATSStreamingSubscriptions {
		common.Log.Panicf("Dedicated API instance started with CONSUME_NATS_STREAMING_SUBSCRIPTIONS=true")
		return
	}

	common.RequireJWT()
	consumer.RunAPIUsageDaemon()
}

func main() {
	common.Log.Debugf("starting ident API...")
	installSignalHandlers()

	go runAPI()

	timer := time.NewTicker(runloopTickInterval)
	defer timer.Stop()

	for !shuttingDown() {
		select {
		case <-timer.C:
			// tick... no-op
		case sig := <-sigs:
			common.Log.Debugf("received signal: %s", sig)
			srv.Shutdown(shutdownCtx)
			shutdown()
		case <-shutdownCtx.Done():
			close(sigs)
		default:
			time.Sleep(runloopSleepInterval)
		}
	}

	common.Log.Debug("exiting ident API")
	cancelF()
}

func installSignalHandlers() {
	common.Log.Debug("installing signal handlers for ident API")
	sigs = make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	shutdownCtx, cancelF = context.WithCancel(context.Background())
}

func shutdown() {
	if atomic.AddUint32(&closing, 1) == 1 {
		common.Log.Debug("shutting down ident API")
		cancelF()
	}
}

func runAPI() {
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.Use(provide.CORSMiddleware())
	r.Use(provide.TrackAPICalls())

	application.InstallApplicationAPI(r)
	token.InstallTokenAPI(r)
	user.InstallUserAPI(r)
	kyc.InstallKYCAPI(r)

	r.GET("/status", statusHandler)

	srv = &http.Server{
		Addr:    common.ListenAddr,
		Handler: r,
	}

	if common.ShouldServeTLS() {
		srv.ListenAndServeTLS(common.CertificatePath, common.PrivateKeyPath)
	} else {
		srv.ListenAndServe()
	}
}

func statusHandler(c *gin.Context) {
	status := map[string]interface{}{
		"privacy_policy_updated_at":   privacyPolicyUpdatedAt,
		"terms_of_service_updated_at": termsOfServiceUpdatedAt,
	}
	provide.Render(status, 200, c)
}

func shuttingDown() bool {
	return (atomic.LoadUint32(&closing) > 0)
}
