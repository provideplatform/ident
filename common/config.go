package common

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
	logger "github.com/kthomas/go-logger"
	"github.com/provideplatform/provide-go/common/util"
)

const apiAccountingAddressEnvVar = "API_ACCOUNTING_ADDRESS"
const defaultAuth0APINamespace = "v2"
const defaultBannedErrorMessage = "Your IP address has been banned from making API calls"

const defaultEmailVerificationAttempts = int(4)
const defaultEmailVerificationTimeout = time.Millisecond * time.Duration(2500)

var (
	// apiAccountingAddress is the UDP network address to which API call accounting packets will be delivered
	apiAccountingAddress *net.UDPAddr

	// apiAccountingConn is the network connection to which API call accounting packets will be delivered
	apiAccountingConn *net.UDPConn

	// Auth0IntegrationEnabled is a flag that indicates if the configured Auth0 integration should be used; this is a temporary config item and will be removed in the future
	Auth0IntegrationEnabled bool

	// Auth0IntegrationCustomDatabase is a flag that indicates if the configured Auth0 integration uses the ident instance as a custom database
	Auth0IntegrationCustomDatabase bool

	// Auth0WhitelistedIPs are the list of IPs that are used by Auth0 when invoking our callbacks
	Auth0WhitelistedIPs []string

	// BannedErrorMessage is the error message to render when an API request is made from a banned IP
	BannedErrorMessage string

	// BannedIPs are the list of IPs that are banned for abuse
	BannedIPs []string

	// ConsumeNATSStreamingSubscriptions is a flag the indicates if the ident instance is running in API or consumer mode
	ConsumeNATSStreamingSubscriptions bool

	// DispatchSiaNotifications is a flag that indicates if certain events should result in the publishing of a message for Sia
	DispatchSiaNotifications bool

	// EmailVerificationAttempts is the number of retries to attempt per address validation (i.e., for deliverability)
	EmailVerificationAttempts int

	// EmailVerificationFromDomain is the from domain used for email verification
	EmailVerificationFromDomain string

	// EmailVerificationFromAddress is the full email address used for connecting to verify deliverability of an email addresses
	EmailVerificationFromAddress string

	// EmailVerificationTimeout is the timeout upon which deliverability verification will fail
	EmailVerificationTimeout time.Duration

	// JWTKeypairs holds a reference to the configured keypairs
	JWTKeypairs map[string]*util.JWTKeypair

	// Log is the configured logger
	Log *logger.Logger

	// PerformEmailVerification flag indicates if email deliverability should be verified when creating new users
	PerformEmailVerification bool

	// OpenIDConfiguration is the openid configuration JSON which is served from .well-known/openid-configuration
	OpenIDConfiguration map[string]interface{}
)

func init() {
	godotenv.Load()

	requireLogger()
	requireEmailVerification()
	requireIPLists()
	requireOpenIDConfiguration()

	Auth0IntegrationEnabled = strings.ToLower(os.Getenv("AUTH0_INTEGRATION_ENABLED")) == "true"
	Auth0IntegrationCustomDatabase = strings.ToLower(os.Getenv("AUTH0_INTEGRATION_CUSTOM_DATABASE")) == "true"

	ConsumeNATSStreamingSubscriptions = strings.ToLower(os.Getenv("CONSUME_NATS_STREAMING_SUBSCRIPTIONS")) == "true"

	DispatchSiaNotifications = strings.ToLower(os.Getenv("DISPATCH_SIA_NOTIFICATIONS")) == "true"
}

// EnableAPIAccounting allows a package to conditionally require the presence of
// an API_ACCOUNTING_ADDRESS environment variable which specifies the address to
// which API call accounting packets will be delivered via UDP
func EnableAPIAccounting() {
	if os.Getenv(apiAccountingAddressEnvVar) != "" {
		addr := os.Getenv(apiAccountingAddressEnvVar)
		udpaddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			Log.Warningf("failed to parse %s; %s is not valid <ip>:<port>", apiAccountingAddressEnvVar, addr)
			return
		}
		apiAccountingAddress = udpaddr
		establishAPIAccountingConn()
	} else {
		Log.Tracef("failed to parse %s; no api accounting endpoint configured", apiAccountingAddressEnvVar)
	}
}

func establishAPIAccountingConn() error {
	if apiAccountingAddress == nil {
		return fmt.Errorf("failed to parse %s; no api accounting listener configured", apiAccountingAddressEnvVar)
	}
	conn, err := net.DialUDP("udp", nil, apiAccountingAddress)
	if err != nil {
		Log.Warningf("failed to establish connection for API accounting packets; %s", err.Error())
		return err
	}
	apiAccountingConn = conn
	return nil
}

func requireEmailVerification() {
	if os.Getenv("EMAIL_VERIFICATION_ATTEMPTS") != "" {
		attempts, err := strconv.Atoi(os.Getenv("EMAIL_VERIFICATION_ATTEMPTS"))
		if err != nil {
			log.Panicf("failed to parse EMAIL_VERIFICATION_ATTEMPTS from environment; %s", err.Error())
		}
		EmailVerificationAttempts = attempts
	} else {
		EmailVerificationAttempts = defaultEmailVerificationAttempts
	}
	if os.Getenv("EMAIL_VERIFICATION_TIMEOUT_MILLIS") != "" {
		timeoutMillis, err := strconv.Atoi(os.Getenv("EMAIL_VERIFICATION_TIMEOUT_MILLIS"))
		if err != nil {
			log.Panicf("failed to parse EMAIL_VERIFICATION_TIMEOUT_MILLIS from environment; %s", err.Error())
		}
		EmailVerificationTimeout = time.Millisecond * time.Duration(timeoutMillis)
	} else {
		EmailVerificationTimeout = defaultEmailVerificationTimeout
	}
	if os.Getenv("EMAIL_VERIFICATION_FROM_DOMAIN") != "" {
		EmailVerificationFromDomain = os.Getenv("EMAIL_VERIFICATION_FROM_DOMAIN")
	}
	if os.Getenv("EMAIL_VERIFICATION_FROM_ADDRESS") != "" {
		EmailVerificationFromAddress = os.Getenv("EMAIL_VERIFICATION_FROM_ADDRESS")
	}
	PerformEmailVerification = EmailVerificationFromDomain != "" && EmailVerificationFromAddress != ""
}

func requireLogger() {
	lvl := os.Getenv("LOG_LEVEL")
	if lvl == "" {
		lvl = "INFO"
	}

	var endpoint *string
	if os.Getenv("SYSLOG_ENDPOINT") != "" {
		endpt := os.Getenv("SYSLOG_ENDPOINT")
		endpoint = &endpt
	}

	Log = logger.NewLogger("ident", lvl, endpoint)
}

func requireIPLists() {
	Auth0WhitelistedIPs = []string{
		"35.167.74.121",
		"35.166.202.113",
		"35.160.3.103",
		"54.183.64.135",
		"54.67.77.38",
		"54.67.15.170",
		"54.183.204.205",
		"35.171.156.124",
		"18.233.90.226",
		"3.211.189.167",
		"18.232.225.224",
		"34.233.19.82",
		"52.204.128.250",
		"3.132.201.78",
		"3.19.44.88",
		"3.20.244.231",
	}

	if os.Getenv("BANNED_IP_ERROR_MESSAGE") != "" {
		BannedErrorMessage = os.Getenv("BANNED_IP_ERROR_MESSAGE")
	} else {
		BannedErrorMessage = defaultBannedErrorMessage
	}

	// FIXME-- remove these hardcoded values and make an API/CLI integration to manage them
	BannedIPs = []string{}
}

func requireOpenIDConfiguration() {
	openIDConfigURL := os.Getenv("OPENID_CONFIGURATION_URL")
	if openIDConfigURL != "" {
		resp, err := http.Get(openIDConfigURL)
		if err != nil {
			Log.Panicf("failed to fetch openid configuration; %s", err.Error())
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			Log.Panicf("failed to fetch openid configuration; %s", err.Error())
		}

		err = json.Unmarshal(body, &OpenIDConfiguration)
		if err != nil {
			Log.Panicf("failed to parse openid configuration; %s", err.Error())
		}
	}
}
