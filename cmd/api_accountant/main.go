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

	dbconf "github.com/kthomas/go-db-config"
	"github.com/provideplatform/ident/common"
	provide "github.com/provideplatform/provide-go/common"
	util "github.com/provideplatform/provide-go/common/util"
)

const runloopSleepInterval = 100 * time.Millisecond
const runloopTickInterval = 1000 * time.Millisecond

const apiAccountantBufferSize = 512
const apiAccountantFlushIntervalMillis = 60000

var (
	cancelF     context.CancelFunc
	closing     uint32
	shutdownCtx context.Context
	sigs        chan os.Signal

	srv *http.Server
)

func main() {
	installSignalHandlers()

	runAPI()
	err := runAPIAccountant(
		dbconf.DatabaseConnection(),
		apiAccountantBufferSize,
		apiAccountantFlushIntervalMillis,
	)

	if err != nil {
		common.Log.Panicf("failed to run API accounting daemon; %s", err.Error())
	}

	timer := time.NewTicker(runloopTickInterval)
	defer timer.Stop()

	for !shuttingDown() {
		select {
		case <-timer.C:
			go daemon.read()
		case sig := <-sigs:
			common.Log.Infof("received signal: %s", sig)
			srv.Shutdown(shutdownCtx)
			shutdown()
		case <-shutdownCtx.Done():
			close(sigs)
		default:
			time.Sleep(runloopSleepInterval)
		}
	}

	common.Log.Debug("exiting API accounting daemon")
	cancelF()
}

func runAPI() {
	util.RequireGin()

	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	r.GET("/status", statusHandler)

	srv := &http.Server{
		Addr:    util.ListenAddr,
		Handler: r,
	}

	if util.ServeTLS {
		go srv.ListenAndServeTLS(util.CertificatePath, util.PrivateKeyPath)
	} else {
		go srv.ListenAndServe()
	}

	common.Log.Debugf("listening on %s", util.ListenAddr)
}

func statusHandler(c *gin.Context) {
	provide.Render(nil, 204, c)
}

func installSignalHandlers() {
	common.Log.Debug("installing signal handlers for API accounting daemon")
	sigs = make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	shutdownCtx, cancelF = context.WithCancel(context.Background())
}

func shutdown() {
	if atomic.AddUint32(&closing, 1) == 1 {
		common.Log.Debug("shutting down API accounting daemon")
		cancelF()
	}
}

func shuttingDown() bool {
	return (atomic.LoadUint32(&closing) > 0)
}
