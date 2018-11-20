package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	natsutil "github.com/kthomas/go-natsutil"
	"github.com/nats-io/go-nats-streaming"
)

const natsAPIUsageIdentSubject = "api.usage.events.ident"

// Nats docs suggest the client libraries buffer for performance, so maybe this is premature.
// https://nats.io/documentation/writing_applications/publishing/
const bufferSize = 2 // TODO: 32

var (
	// TODO: waitGroup    sync.WaitGroup
	usageChannel = make(chan apiUse, bufferSize)
)

// TODO: here and goldmine, or in provide-go or...?
// TODO: Done / shutdown handling.

// apiUse is a container for details of an occurence of invocation of a Provide API endpoint.
type apiUse struct { // TODO: rename to APIEvent?
	AccountID  string
	Method     string
	Path       string
	RemoteAddr string
	StatusCode int
	Timestamp  time.Time
	// Errored    bool
}

// initAPIUse convenience method
func initAPIUse(c *gin.Context) apiUse {
	// fmt.Printf("MUNC: +++++ in render with %+v\n", c.Request)
	// curl -v -XPOST -H 'content-type: application/json' http://muncmac.local:8081/api/v1/authenticate -d '{"email": "provide@munc.com", "password": "provide"}'
	// c = &{writermem:{ResponseWriter:0xc00023e0e0 size:-1 status:200} Request:0xc00016e700 Writer:0xc0003668f0 Params:[] handlers:[0x460d0a0 0x460e370 0x460e370 0x47ffe90 0x4805220] index:4 engine:0xc0001097a0 Keys:map[] Errors: Accepted:[]}
	// c.Request = &{Method:POST URL:/api/v1/authenticate Proto:HTTP/1.1 ProtoMajor:1 ProtoMinor:1 Header:map[Accept:[*/*] Content-Type:[application/json] Content-Length:[52] User-Agent:[curl/7.54.0]] Body:0xc0000b8680 GetBody:<nil> ContentLength:52 TransferEncoding:[] Close:false Host:muncmac.local:8080 Form:map[] PostForm:map[] MultipartForm:<nil> Trailer:map[] RemoteAddr:24.210.56.22:53141 RequestURI:/api/v1/authenticate TLS:<nil> Cancel:<nil> Response:<nil> ctx:0xc0000b86c0}
	// /api/v1/applications...
	// c.Request = &{Method:GET URL:/api/v1/applications Proto:HTTP/1.1 ProtoMajor:1 ProtoMinor:1 Header:map[User-Agent:[curl/7.54.0] Accept:[*/*] Authorization:[bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7fSwiZXhwIjpudWxsLCJpYXQiOjE1NDIzMTA0MjMsImp0aSI6IjM2MjI4ZGVkLWFiY2QtNDE3ZS1hY2YyLTNlM2M0MWNhMjU2OCIsInN1YiI6InVzZXI6MTdjZTYyYmYtNWM0Ni00NDgyLWIwMGEtMDk2Yjk2MDM1NWFiIn0.06N0-fw794Fj_oGsKXDk3p90oZMFRPrPTVuxPvhp-3U]] Body:{} GetBody:<nil> ContentLength:0 TransferEncoding:[] Close:false Host:muncmac.local:8080 Form:map[] PostForm:map[] MultipartForm:<nil> Trailer:map[] RemoteAddr:24.210.56.22:53270 RequestURI:/api/v1/applications TLS:<nil> Cancel:<nil> Response:<nil> ctx:0xc0001882c0}
	loc, _ := time.LoadLocation("UTC")
	now := time.Now().In(loc)
	fmt.Println("ZONE : ", loc, " Time : ", now) // UTC
	return apiUse{
		AccountID:  "FIXME", // c.Request.Header.Get("Authorization"), // TODO: map from token to ID!
		Method:     c.Request.Method,
		Path:       c.Request.URL.Path,
		RemoteAddr: c.Request.RemoteAddr,
		StatusCode: c.Writer.Status(),
		Timestamp:  now,
		// Errored:    len(c.Errors) > 0,
		// TODO: more potential items => “usageDate”, “price”, ”price_unit”, "category” or ”description” (lookup table?)…
	}
}

// SendAPIUsage queues a usage event for publishing.
func SendAPIUsage(c *gin.Context) {
	event := initAPIUse(c)
	fmt.Printf("MUNC: +++++ sending API usage for %+v\n", event) // c.Request.Header)
	usageChannel <- event                                        // initAPIUse(c)
	if isBufferFull(usageChannel) {
		fmt.Println("MUNC: buffer is full!")
		go sendBufferedEvents()
	} else {
		// else wait until full (or shutdown)
		fmt.Println("MUNC: buffer not yet full")
	}
}

// isBufferFull is a utility method for testing if the given channel is at capacity.
func isBufferFull(ch chan apiUse) bool {
	return len(ch) == cap(ch)
}

// sendBufferedEvents sends all unsent events from the buffered channel to nats.
func sendBufferedEvents() {
	// TODO: block here??
	if len(usageChannel) != bufferSize {
		fmt.Println("MUNC: different sizes?!") // TODO: more handling here...
	}
	bufferedEvents := make([]interface{}, len(usageChannel)) // [len(usageChannel)]apiUse
	// for event := range usageChannel {
	// 	bufferedEvents = append(bufferedEvents, event)
	// }
	for i := 0; i < bufferSize; i++ {
		event := <-usageChannel
		bufferedEvents = append(bufferedEvents, event)
	}
	// getNatsConnectionForAPIUsage().Publish()
	payload, err := json.Marshal(bufferedEvents) // TODO: vs &bufferedEvents?
	fmt.Printf("MUNC: +++++ jSON-ified apiUse buffer array %+v\n", payload)
	if err != nil {
		Log.Errorf("Failed to stringify array of API usage structs: %s; %s", bufferedEvents, err.Error())
		// TODO: need to not lose this vital (billable!) data...
	} else {
		fmt.Println("MUNC: publishing to subject:", natsAPIUsageIdentSubject)
		// nc, err := nats.Connect(*urls, opts...)
		nc := getNatsConnectionForAPIUsage()
		if nc == nil {
			fmt.Println("MUNC: nats connecetion is nil!")
		}
		nc.Publish(natsAPIUsageIdentSubject, payload)
		fmt.Println("MUNC: published!?")
		// TODO: Anything like this we can do for streaming?
		// if lastErr := nc.LastError(); lastErr != nil {
		// 	log.Fatal(lastErr) // TODO: ?
		// } else {
		// 	log.Printf("Published [%s] : '%s'\n", natsAPIUsageIdentSubject, payload)
		// }
		defer nc.Close()
	}
}

// getNatsConnectionForAPIUsage is a helper method to acquire a nats connection.
func getNatsConnectionForAPIUsage() stan.Conn {
	conn := natsutil.GetNatsStreamingConnection(func(_ stan.Conn, reason error) {
		fmt.Println("MUNC: in getNatsConnectionForAPIUsage in GetNatsStreamingConnection:", reason)
		processNatsStreaming()
	})
	if conn == nil {
		fmt.Println("MUNC: in getNatsConnectionForAPIUsage and connection is nil")
		return nil
	}
	fmt.Println("MUNC: in getNatsConnectionForAPIUsage and connection is NOT nil")
	return *conn
}

// processNatsStreaming will attempt a fresh nats streaming connection.
func processNatsStreaming() {
	natsConnection := getNatsConnectionForAPIUsage()
	if natsConnection == nil {
		fmt.Println("MUNC: in processNatsStreaming and connection is nil")
		return
	}
	fmt.Println("MUNC: in processNatsStreaming and connection is NOT nil")
}
