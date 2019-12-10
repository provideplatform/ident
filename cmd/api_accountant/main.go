package main

import (
	"context"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	dbconf "github.com/kthomas/go-db-config"
	"github.com/provideapp/ident/common"
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
)

func main() {
	installSignalHandlers()

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
