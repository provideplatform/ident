package main

import (
	"context"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kthomas/go-pgputil"
	"github.com/kthomas/go-redisutil"
	_ "github.com/provideplatform/ident/application" // Application package
	"github.com/provideplatform/ident/common"
	_ "github.com/provideplatform/ident/organization" // Organization package
	_ "github.com/provideplatform/ident/user"         // User package
	util "github.com/provideplatform/provide-go/common/util"
)

const natsStreamingSubscriptionStatusTickerInterval = 5 * time.Second
const natsStreamingSubscriptionStatusSleepInterval = 250 * time.Millisecond

var (
	cancelF     context.CancelFunc
	closing     uint32
	shutdownCtx context.Context
)

func init() {
	if !common.ConsumeNATSStreamingSubscriptions {
		common.Log.Panicf("dedicated NATS streaming subscription consumer started without CONSUME_NATS_STREAMING_SUBSCRIPTIONS=true")
		return
	}

	util.RequireJWT()
	pgputil.RequirePGP()
	redisutil.RequireRedis()
}

func main() {
	common.Log.Debug("installing signal handlers for dedicated NATS streaming subscription consumer")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	shutdownCtx, cancelF = context.WithCancel(context.Background())

	common.Log.Debugf("running dedicated NATS streaming subscription consumer main()")
	timer := time.NewTicker(natsStreamingSubscriptionStatusTickerInterval)
	defer timer.Stop()

	for !shuttingDown() {
		select {
		case <-timer.C:
			// TODO: check NATS subscription statuses
		case sig := <-sigs:
			common.Log.Infof("received signal: %s", sig)
			common.Log.Warningf("NATS streaming connection subscriptions are not yet being drained...")
			shutdown()
		case <-shutdownCtx.Done():
			close(sigs)
		default:
			time.Sleep(natsStreamingSubscriptionStatusSleepInterval)
		}
	}

	common.Log.Debug("exiting dedicated NATS streaming subscription consumer main()")
	cancelF()
}

func shutdown() {
	if atomic.AddUint32(&closing, 1) == 1 {
		common.Log.Debug("shutting down dedicated NATS streaming subscription consumer")
		cancelF()
	}
}

func shuttingDown() bool {
	return (atomic.LoadUint32(&closing) > 0)
}
