package common

import (
	"crypto/rsa"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/dgrijalva/jwt-go"

	logger "github.com/kthomas/go-logger"
	selfsignedcert "github.com/kthomas/go-self-signed-cert"
	stan "github.com/nats-io/stan.go"
)

const defaultEmailVerificationAttempts = uint(2)

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
	EmailVerificationAttempts uint

	// EmailVerificationFromDomain is the from domain used for email verification
	EmailVerificationFromDomain string

	// EmailVerificationFromAddress is the full email address used for connecting to verify deliverability of email addresses
	EmailVerificationFromAddress string

	// PerformEmailVerification flag indicates if email deliverability should be verified when creating new users
	PerformEmailVerification bool

	// JWTPublicKeyPEM is the raw PEM-encoded JWT public key used for signature verification
	JWTPublicKeyPEM string

	// JWTPublicKey is the parsed RSA JWT public key instance
	JWTPublicKey *rsa.PublicKey

	// JWTPrivateKey is the parsed RSA JWT private key instance
	JWTPrivateKey *rsa.PrivateKey

	// SharedNatsConnection is a cached connection used by most NATS Publish calls
	SharedNatsConnection *stan.Conn
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
	requireJWT()

	requireTLS = os.Getenv("REQUIRE_TLS") == "true"

	err := EstablishNATSStreamingConnection()
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
		EmailVerificationAttempts = uint(attempts)
	} else {
		EmailVerificationAttempts = defaultEmailVerificationAttempts
	}
	if os.Getenv("EMAIL_VERIFICATION_FROM_DOMAIN") != "" {
		EmailVerificationFromDomain = os.Getenv("EMAIL_VERIFICATION_FROM_DOMAIN")
	}
	if os.Getenv("EMAIL_VERIFICATION_FROM_ADDRESS") != "" {
		EmailVerificationFromAddress = os.Getenv("EMAIL_VERIFICATION_FROM_ADDRESS")
	}
	PerformEmailVerification = EmailVerificationFromDomain != "" && EmailVerificationFromAddress != ""
}

func requireJWT() {
	jwtPrivateKeyPEM := strings.Replace(os.Getenv("JWT_SIGNER_PRIVATE_KEY"), `\n`, "\n", -1)
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(jwtPrivateKeyPEM))
	if err != nil {
		log.Panicf("Failed to parse JWT private key; %s", err.Error())
	}

	JWTPublicKeyPEM = strings.Replace(os.Getenv("JWT_SIGNER_PUBLIC_KEY"), `\n`, "\n", -1)
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(JWTPublicKeyPEM))
	if err != nil {
		log.Panicf("Failed to parse JWT public key; %s", err.Error())
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
