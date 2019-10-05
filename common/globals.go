package common

import (
	"crypto/rsa"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"

	logger "github.com/kthomas/go-logger"
	natsutil "github.com/kthomas/go-natsutil"
	selfsignedcert "github.com/kthomas/go-self-signed-cert"
)

const defaultEmailVerificationAttempts = int(4)
const defaultEmailVerificationTimeout = time.Millisecond * time.Duration(2500)

var (
	// Log is the configured logger
	Log *logger.Logger

	// ListenAddr is the http server listen address
	ListenAddr string

	// CertificatePath is the SSL certificate path used by HTTPS listener
	CertificatePath string

	// PrivateKeyPath is the private key used by HTTPS listener
	PrivateKeyPath string

	requireTLS bool

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

	// PerformEmailVerification flag indicates if email deliverability should be verified when creating new users
	PerformEmailVerification bool

	// JWTPublicKeyPEM is the raw PEM-encoded JWT public key used for signature verification
	JWTPublicKeyPEM string

	// JWTPublicKey is the parsed RSA JWT public key instance
	JWTPublicKey *rsa.PublicKey

	// JWTPrivateKey is the parsed RSA JWT private key instance
	JWTPrivateKey *rsa.PrivateKey
)

func init() {
	ListenAddr = os.Getenv("LISTEN_ADDR")
	if ListenAddr == "" {
		ListenAddr = buildListenAddr()
	}

	lvl := os.Getenv("LOG_LEVEL")
	if lvl == "" {
		lvl = "INFO"
	}
	Log = logger.NewLogger("ident", lvl, true)

	requireEmailVerification()

	requireTLS = os.Getenv("REQUIRE_TLS") == "true"

	err := natsutil.EstablishSharedNatsStreamingConnection()
	if err != nil {
		log.Panicf("Failed to established NATS streaming connection; %s", err.Error())
	}

	ConsumeNATSStreamingSubscriptions = strings.ToLower(os.Getenv("CONSUME_NATS_STREAMING_SUBSCRIPTIONS")) == "true"
}

func requireEmailVerification() {
	if os.Getenv("EMAIL_VERIFICATION_ATTEMPTS") != "" {
		attempts, err := strconv.Atoi(os.Getenv("EMAIL_VERIFICATION_ATTEMPTS"))
		if err != nil {
			log.Panicf("Failed to parse EMAIL_VERIFICATION_ATTEMPTS from environment; %s", err.Error())
		}
		EmailVerificationAttempts = attempts
	} else {
		EmailVerificationAttempts = defaultEmailVerificationAttempts
	}
	if os.Getenv("EMAIL_VERIFICATION_TIMEOUT_MILLIS") != "" {
		timeoutMillis, err := strconv.Atoi(os.Getenv("EMAIL_VERIFICATION_TIMEOUT_MILLIS"))
		if err != nil {
			log.Panicf("Failed to parse EMAIL_VERIFICATION_TIMEOUT_MILLIS from environment; %s", err.Error())
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

// RequireJWT allows a package to conditionally require an RS256 keypair configured
// in the ident environment via JWT_SIGNER_PRIVATE_KEY and JWT_SIGNER_PUBLIC_KEY
func RequireJWT() {
	Log.Debug("Attempting to read required RS256 keypair from environment for signing JWT tokens")

	jwtPrivateKeyPEM := strings.Replace(os.Getenv("JWT_SIGNER_PRIVATE_KEY"), `\n`, "\n", -1)
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(jwtPrivateKeyPEM))
	if err != nil {
		Log.Panicf("Failed to parse JWT private key; %s", err.Error())
	}

	JWTPublicKeyPEM = strings.Replace(os.Getenv("JWT_SIGNER_PUBLIC_KEY"), `\n`, "\n", -1)
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(JWTPublicKeyPEM))
	if err != nil {
		Log.Panicf("Failed to parse JWT public key; %s", err.Error())
	}

	JWTPrivateKey = privateKey
	JWTPublicKey = publicKey
}

func buildListenAddr() string {
	listenPort := os.Getenv("PORT")
	if listenPort == "" {
		listenPort = "8080"
	}
	return fmt.Sprintf("0.0.0.0:%s", listenPort)
}

func shouldServeTLS() bool {
	if requireTLS {
		privKeyPath, certPath, err := selfsignedcert.GenerateToDisk()
		if err != nil {
			log.Panicf("Failed to generate self-signed certificate; %s", err.Error())
		}
		PrivateKeyPath = *privKeyPath
		CertificatePath = *certPath
		return true
	}
	return false
}
