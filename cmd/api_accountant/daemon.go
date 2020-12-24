package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/provideapp/ident/common"
	gormbulk "github.com/t-tiger/gorm-bulk-insert"
)

const identAPIAccountingListenAddressEnvVar = "API_ACCOUNTING_LISTEN_ADDRESS"
const identAPIAccountingInsertBatchSize = 2500

var (
	daemon    *accountant
	waitGroup sync.WaitGroup
)

type accountant struct {
	apiAccountingListenAddress *net.UDPAddr
	apiAccountingConn          *net.UDPConn

	db                  *gorm.DB
	flushIntervalMillis uint
	q                   chan []byte

	shutdown context.Context
	cancelF  context.CancelFunc
}

// runAPIAccountant initializes and starts a new API accountant daemon (goroutine); returns an
// error if there is already an API accounting daemon running as it is currently treated as a singleton
func runAPIAccountant(db *gorm.DB, bufferSize int, flushIntervalMillis uint) error {
	if daemon != nil {
		msg := "attempted to run api accounting daemon after singleton instance started"
		common.Log.Warning(msg)
		return fmt.Errorf(msg)
	}

	daemon = new(accountant)
	daemon.shutdown, daemon.cancelF = context.WithCancel(context.Background())
	daemon.db = db
	daemon.q = make(chan []byte, bufferSize)
	daemon.flushIntervalMillis = flushIntervalMillis
	go daemon.run()

	return nil
}

func (a *accountant) establishAPIAccountingConn() error {
	if os.Getenv(identAPIAccountingListenAddressEnvVar) != "" {
		addr := os.Getenv(identAPIAccountingListenAddressEnvVar)
		udpaddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			msg := fmt.Sprintf("failed to parse %s; %s is not valid <ip>:<port>", identAPIAccountingListenAddressEnvVar, addr)
			common.Log.Warning(msg)
			return errors.New(msg)
		}
		daemon.apiAccountingListenAddress = udpaddr
	} else {
		return fmt.Errorf("failed to parse %s; no api accounting listener configured", identAPIAccountingListenAddressEnvVar)
	}

	if a.apiAccountingListenAddress != nil {
		conn, err := net.ListenUDP("udp", a.apiAccountingListenAddress)
		if err != nil {
			common.Log.Warningf("failed to establish connection for api accounting packets; %s", err.Error())
			return err
		}
		a.apiAccountingConn = conn
	}
	return nil
}

func (a *accountant) read() {
	i := 0
	for {
		var pkt [512]byte
		len, err := a.apiAccountingConn.Read(pkt[0:])
		if err != nil {
			common.Log.Warningf("api accounting daemon failed to read from UDP connection; %s", err.Error())
			continue
		}
		if len > 0 {
			common.Log.Debugf("api accounting daemon read %d-byte UDP packet", len)
			common.Log.Debugf("udp packet: %s", string(pkt[0:]))
			a.q <- pkt[0:len]
			i++
			continue
		}
		common.Log.Debugf("api accounting daemon read %d api call accounting packets during read()", i)
		break
	}
}

func (a *accountant) run() error {
	common.Log.Debugf("running api accounting daemon...")
	err := daemon.establishAPIAccountingConn()
	if err != nil {
		common.Log.Panicf("api accounting daemon failed to run; %s", err.Error())
	}

	defer a.apiAccountingConn.Close()

	ticker := time.NewTicker(time.Duration(a.flushIntervalMillis) * time.Millisecond)
	for {
		select {
		case <-ticker.C:
			if len(a.q) > 0 {
				a.flush()
			}
		case <-a.shutdown.Done():
			common.Log.Debugf("flushing api accounting daemon on shutdown")
			ticker.Stop()
			return a.flush()
		}
	}
}

func (a *accountant) flush() error {
	packets := make([]interface{}, 0)
	for {
		select {
		case packet, ok := <-a.q:
			if ok {
				common.Log.Debugf("handling %d-byte api call accounting packet: %s: ", len(packet), string(packet))
				var apiCall *siaAPICall
				err := json.Unmarshal(packet, &apiCall)
				if err != nil {
					common.Log.Warningf("failed to resolve %d-byte api call accounting packet to accountable user; %s: ", len(packet), err.Error())
				} else if apiCall != nil {
					common.Log.Debugf("resolved %d-byte api call accounting packet to accountable user: %s: ", len(packet), apiCall.IdentUserID)
					apiCall.CalculateHash(&packet)
					apiCall.Raw = json.RawMessage(packet)
					apiCall.Hash = apiCall.Sha256 // HACK
					apiCall.enrich(a.db)
					packets = append(packets, *apiCall)
				}
			} else {
				common.Log.Warningf("failed to receive api call accounting packet from usage daemon")
			}
		default:
			if len(a.q) == 0 {
				// common.Log.Debugf("batching insert of %d flushed api call accounting packets", len(packets))
				//err := gormbulk.BulkInsert(a.db, packets, identAPIAccountingInsertBatchSize)
				// if err != nil {
				// 	common.Log.Warningf("failed to execute batch insert of %d flushed api call accounting packets; %s", len(packets), err.Error())
				// 	return err
				// }

				common.Log.Debugf("successfully flushed %d api call accounting packets", len(packets))
				return nil
			}
		}
	}
}
