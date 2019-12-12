package common

import (
	"crypto/rsa"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"

	logger "github.com/kthomas/go-logger"
	selfsignedcert "github.com/kthomas/go-self-signed-cert"
)

const apiAccountingAddressEnvVar = "API_ACCOUNTING_ADDRESS"
const defaultAuth0APINamespace = "v2"
const defaultAuthorizationAudience = "https://provide.services"
const defaultAuthorizationIssuer = "https://ident.provide.services"
const defaultAuthorizationTTL = time.Hour * 24
const defaultBannedErrorMessage = "Your IP address has been banned from making API calls"

const defaultEmailVerificationAttempts = int(4)
const defaultEmailVerificationTimeout = time.Millisecond * time.Duration(2500)

const defaultJWTApplicationClaimsKey = "prvd"

var (
	// apiAccountingAddress is the UDP network address to which API call accounting packets will be delivered
	apiAccountingAddress *net.UDPAddr

	// apiAccountingConn is the network connection to which API call accounting packets will be delivered
	apiAccountingConn *net.UDPConn

	// Auth0IntegrationEnabled is a flag that indicates if the configured Auth0 integration should be used; this is a temporary config item and will be removed in the future
	Auth0IntegrationEnabled bool

	// Auth0WhitelistedIPs are the list of IPs that are used by Auth0 when invoking our callbacks
	Auth0WhitelistedIPs []string

	// BannedErrorMessage is the error message to render when an API request is made from a banned IP
	BannedErrorMessage string

	// BannedIPs are the list of IPs that are banned for abuse
	BannedIPs []string

	// ConsumeNATSStreamingSubscriptions is a flag the indicates if the ident instance is running in API or consumer mode
	ConsumeNATSStreamingSubscriptions bool

	// EmailVerificationAttempts is the number of retries to attempt per address validation (i.e., for deliverability)
	EmailVerificationAttempts int

	// EmailVerificationFromDomain is the from domain used for email verification
	EmailVerificationFromDomain string

	// EmailVerificationFromAddress is the full email address used for connecting to verify deliverability of an email addresses
	EmailVerificationFromAddress string

	// EmailVerificationTimeout is the timeout upon which deliverability verification will fail
	EmailVerificationTimeout time.Duration

	// Log is the configured logger
	Log *logger.Logger

	// ListenAddr is the http server listen address
	ListenAddr string

	// CertificatePath is the SSL certificate path used by HTTPS listener
	CertificatePath string

	// PrivateKeyPath is the private key used by HTTPS listener
	PrivateKeyPath string

	// JWTApplicationClaimsKey is the key within the JWT payload where application-specific claims are encoded
	JWTApplicationClaimsKey string

	// JWTAuthorizationAudience is the audience who will consume the JWT; this will be set as the JWT "aud" claim
	JWTAuthorizationAudience string

	// JWTAuthorizationIssuer is the common name of the operator of the token vending machine; this will be set as the JWT "iss" claim
	JWTAuthorizationIssuer string

	// JWTAuthorizationTTL is the ttl in milliseconds for new token authorizations, calculated from the issued at timestamp ("iat" claim)
	JWTAuthorizationTTL time.Duration

	// JWTPublicKeyPEM is the raw PEM-encoded JWT public key used for signature verification
	JWTPublicKeyPEM string

	// JWTPublicKey is the parsed RSA JWT public key instance
	JWTPublicKey *rsa.PublicKey

	// JWTPrivateKey is the parsed RSA JWT private key instance
	JWTPrivateKey *rsa.PrivateKey

	// PerformEmailVerification flag indicates if email deliverability should be verified when creating new users
	PerformEmailVerification bool

	// ServeTLS is true when CertificatePath and PrivateKeyPath are valid
	ServeTLS bool
)

func init() {
	lvl := os.Getenv("LOG_LEVEL")
	if lvl == "" {
		lvl = "INFO"
	}
	Log = logger.NewLogger("ident", lvl, true)

	requireEmailVerification()
	requireGin()
	requireIPLists()

	Auth0IntegrationEnabled = strings.ToLower(os.Getenv("AUTH0_INTEGRATION_ENABLED")) == "true"

	ConsumeNATSStreamingSubscriptions = strings.ToLower(os.Getenv("CONSUME_NATS_STREAMING_SUBSCRIPTIONS")) == "true"
}

// RequireAPIAccounting allows a package to conditionally require the presence of
// an API_ACCOUNTING_ADDRESS environment variable which specifies the address to
// which API call accounting packets will be delivered via UDP
func RequireAPIAccounting() {
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
		Log.Panicf("failed to parse %s; no api accounting endpoint configured", apiAccountingAddressEnvVar)
	}
}

// RequireJWT allows a package to conditionally require an RS256 keypair configured
// in the ident environment via JWT_SIGNER_PRIVATE_KEY and JWT_SIGNER_PUBLIC_KEY
func RequireJWT() {
	Log.Debug("attempting to read required RS256 keypair from environment for signing JWT tokens")

	jwtPrivateKeyPEM := strings.Replace(os.Getenv("JWT_SIGNER_PRIVATE_KEY"), `\n`, "\n", -1)
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(jwtPrivateKeyPEM))
	if err != nil {
		Log.Panicf("failed to parse JWT private key; %s", err.Error())
	}

	JWTPublicKeyPEM = strings.Replace(os.Getenv("JWT_SIGNER_PUBLIC_KEY"), `\n`, "\n", -1)
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(JWTPublicKeyPEM))
	if err != nil {
		Log.Panicf("failed to parse JWT public key; %s", err.Error())
	}

	JWTPrivateKey = privateKey
	JWTPublicKey = publicKey

	if os.Getenv("JWT_APPLICATION_CLAIMS_KEY") != "" {
		JWTApplicationClaimsKey = os.Getenv("JWT_APPLICATION_CLAIMS_KEY")
	} else {
		JWTApplicationClaimsKey = defaultJWTApplicationClaimsKey
	}

	JWTAuthorizationAudience = os.Getenv("JWT_AUTHORIZATION_AUDIENCE")
	if JWTAuthorizationAudience == "" {
		JWTAuthorizationAudience = defaultAuthorizationAudience
	}

	JWTAuthorizationIssuer = os.Getenv("JWT_AUTHORIZATION_ISSUER")
	if JWTAuthorizationIssuer == "" {
		JWTAuthorizationIssuer = defaultAuthorizationIssuer
	}

	if os.Getenv("JWT_AUTHORIZATION_TTL") != "" {
		ttlMillis, err := strconv.Atoi(os.Getenv("JWT_AUTHORIZATION_TTL"))
		if err != nil {
			log.Panicf("failed to parse JWT_AUTHORIZATION_TTL from environment; %s", err.Error())
		}
		JWTAuthorizationTTL = time.Millisecond * time.Duration(ttlMillis)
	} else {
		JWTAuthorizationTTL = defaultAuthorizationTTL
	}
}

// RequireJWTVerifier allows a package to conditionally require RS256 signature
// verification in the configured environment via JWT_SIGNER_PUBLIC_KEY; the
// use-case for this support is when another microservice is depending on the
// token authorization middleware provided in this package
func RequireJWTVerifier() {
	Log.Debug("attempting to read required public key from environment for verifying signed JWT")

	JWTPublicKeyPEM = strings.Replace(os.Getenv("JWT_SIGNER_PUBLIC_KEY"), `\n`, "\n", -1)
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(JWTPublicKeyPEM))
	if err != nil {
		Log.Panicf("failed to parse JWT public key; %s", err.Error())
	}

	JWTPublicKey = publicKey
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

func requireGin() {
	ListenAddr = os.Getenv("LISTEN_ADDR")
	if ListenAddr == "" {
		listenPort := os.Getenv("PORT")
		if listenPort == "" {
			listenPort = "8080"
		}
		ListenAddr = fmt.Sprintf("0.0.0.0:%s", listenPort)
	}

	requireTLSConfiguration()
}

func requireTLSConfiguration() {
	certificatePath := os.Getenv("TLS_CERTIFICATE_PATH")
	privateKeyPath := os.Getenv("TLS_PRIVATE_KEY_PATH")
	if certificatePath != "" && privateKeyPath != "" {
		CertificatePath = certificatePath
		PrivateKeyPath = privateKeyPath
		ServeTLS = true
	} else if os.Getenv("REQUIRE_TLS") == "true" {
		privKeyPath, certPath, err := selfsignedcert.GenerateToDisk()
		if err != nil {
			Log.Panicf("failed to generate self-signed certificate; %s", err.Error())
		}
		PrivateKeyPath = *privKeyPath
		CertificatePath = *certPath
		ServeTLS = true
	}
}

func requireIPLists() {
	Auth0WhitelistedIPs = []string{
		"3.211.189.167",
		"13.210.52.131",
		"13.54.254.182",
		"13.55.232.24",
		"18.233.90.226",
		"34.253.4.94",
		"35.156.51.163",
		"35.157.221.52",
		"35.160.3.103",
		"35.166.202.113",
		"35.167.74.121",
		"35.171.156.124",
		"52.16.193.66",
		"52.16.224.164",
		"52.208.95.174",
		"52.208.95.174",
		"52.210.122.50",
		"52.210.122.50",
		"52.211.56.181",
		"52.213.216.142",
		"52.213.38.246",
		"52.213.74.69",
		"52.28.184.187",
		"52.28.212.16",
		"52.28.45.240",
		"52.28.56.226",
		"52.29.176.99",
		"52.50.106.250",
		"52.57.230.214",
		"52.62.91.160",
		"52.63.36.78",
		"52.64.111.197",
		"52.64.120.184",
		"52.64.84.177",
		"54.153.131.0",
		"54.183.204.205",
		"54.183.64.135",
		"54.66.205.24",
		"54.67.15.170",
		"54.67.77.38",
		"54.76.184.103",
		"54.76.184.103",
		"54.79.46.4",
	}

	if os.Getenv("BANNED_IP_ERROR_MESSAGE") != "" {
		BannedErrorMessage = os.Getenv("BANNED_IP_ERROR_MESSAGE")
	} else {
		BannedErrorMessage = defaultBannedErrorMessage
	}

	// FIXME-- remove these hardcoded values and make an API/CLI integration to manage them
	BannedIPs = []string{}
}