package main

import (
	"crypto/rsa"
	"fmt"
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
	log        *logger.Logger
	listenAddr string

	certificatePath string
	privateKeyPath  string
	requireTLS      bool

	emailVerificationAttempts    uint
	emailVerificationFromDomain  string
	emailVerificationFromAddress string
	performEmailVerification     bool

	jwtPublicKeyPEM string
	jwtPublicKey    *rsa.PublicKey
	jwtPrivateKey   *rsa.PrivateKey

	gpgPublicKey  string
	gpgPrivateKey string
	gpgPassword   string

	// SharedNatsConnection is a cached connection used by most NATS Publish calls
	SharedNatsConnection *stan.Conn

	siaAPIKey string
)

func init() {
	listenAddr = os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = buildListenAddr()
	}

	lvl := os.Getenv("LOG_LEVEL")
	if lvl == "" {
		lvl = "INFO"
	}
	log = logger.NewLogger("ident", lvl, true)

	requireEmailVerification()

	if os.Getenv("SIA_API_KEY") != "" {
		siaAPIKey = os.Getenv("SIA_API_KEY")
	}

	requireTLS = os.Getenv("REQUIRE_TLS") == "true"

	requireGPG()
	requireJWT()

	err := EstablishNATSStreamingConnection()
	if err != nil {
		log.Panicf("Failed to established NATS streaming connection; %s", err.Error())
	}
}

func requireEmailVerification() {
	if os.Getenv("EMAIL_VERIFICATION_ATTEMPTS") != "" {
		attempts, err := strconv.Atoi(os.Getenv("EMAIL_VERIFICATION_ATTEMPTS"))
		if err != nil {
			log.Panicf("Failed to parse EMAIL_VERIFICATION_ATTEMPTS from environment; %s", err.Error())
		}
		emailVerificationAttempts = uint(attempts)
	} else {
		emailVerificationAttempts = defaultEmailVerificationAttempts
	}
	if os.Getenv("EMAIL_VERIFICATION_FROM_DOMAIN") != "" {
		emailVerificationFromDomain = os.Getenv("EMAIL_VERIFICATION_FROM_DOMAIN")
	}
	if os.Getenv("EMAIL_VERIFICATION_FROM_ADDRESS") != "" {
		emailVerificationFromAddress = os.Getenv("EMAIL_VERIFICATION_FROM_ADDRESS")
	}
	performEmailVerification = emailVerificationFromDomain != "" && emailVerificationFromAddress != ""
}

func requireJWT() {
	jwtPrivateKeyPEM := strings.Replace(os.Getenv("JWT_SIGNER_PRIVATE_KEY"), `\n`, "\n", -1)
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(jwtPrivateKeyPEM))
	if err != nil {
		log.Panicf("Failed to parse JWT private key; %s", err.Error())
	}

	jwtPublicKeyPEM = strings.Replace(os.Getenv("JWT_SIGNER_PUBLIC_KEY"), `\n`, "\n", -1)
	log.Debugf("key\n%s", jwtPublicKeyPEM)
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(jwtPublicKeyPEM))
	if err != nil {
		log.Panicf("Failed to parse JWT public key; %s", err.Error())
	}

	jwtPrivateKey = privateKey
	jwtPublicKey = publicKey
}

func requireGPG() {
	gpgPublicKey = strings.Replace(os.Getenv("GPG_PUBLIC_KEY"), `\n`, "\n", -1)
	if gpgPublicKey == "" {
		log.Panicf("Failed to parse GPG public key")
	}

	gpgPrivateKey = strings.Replace(os.Getenv("GPG_PRIVATE_KEY"), `\n`, "\n", -1)
	if gpgPrivateKey == "" {
		log.Panicf("Failed to parse GPG private key")
	}

	gpgPassword = os.Getenv("GPG_PASSWORD")
	if gpgPassword == "" {
		log.Panicf("Failed to parse GPG password")
	}
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
		privateKeyPath = *privKeyPath
		certificatePath = *certPath
		return true
	}
	return false
}

func panicIfEmpty(val string, msg string) {
	if val == "" {
		panic(msg)
	}
}

func stringOrNil(str string) *string {
	if str == "" {
		return nil
	}
	return &str
}
