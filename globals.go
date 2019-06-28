package main

import (
	"fmt"
	"os"

	logger "github.com/kthomas/go-logger"
	selfsignedcert "github.com/kthomas/go-self-signed-cert"
	stan "github.com/nats-io/stan.go"
)

var (
	log        *logger.Logger
	listenAddr string

	certificatePath string
	privateKeyPath  string
	requireTLS      bool

	emailVerificationFromDomain  string
	emailVerificationFromAddress string
	performEmailVerification     bool

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

	if os.Getenv("EMAIL_VERIFICATION_FROM_DOMAIN") != "" {
		emailVerificationFromDomain = os.Getenv("EMAIL_VERIFICATION_FROM_DOMAIN")
	}
	if os.Getenv("EMAIL_VERIFICATION_FROM_ADDRESS") != "" {
		emailVerificationFromAddress = os.Getenv("EMAIL_VERIFICATION_FROM_ADDRESS")
	}
	performEmailVerification = emailVerificationFromDomain != "" && emailVerificationFromAddress != ""

	if os.Getenv("SIA_API_KEY") != "" {
		siaAPIKey = os.Getenv("SIA_API_KEY")
	}

	requireTLS = os.Getenv("REQUIRE_TLS") == "true"

	gpgPublicKey = `
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1

mQENBFlHZUMBCACo5hsdQGcvLzBWrlA19CRbgzNqA2e22yVrFWNEN4JAhrYsepXX
LUmqmLS2m/b9pfR7s5os3uluN+BWQBKNVrQtFhu6j6mhKNpZcDjbUjJNib5d/QEQ
t+qrq1GcY9+WWC13l3rp3YlwLWRKbJbkynQeFzQ8mnVpXNx91XLzFQsI0Oom2NsM
KP80C79zmAJghJcrZz2V5Mgl38ToitAsHBCvtusPEGWQ7kUe//PK0Vz0k0CYXRc0
qgaAIVqqsOQdpVbMu6js2AZGtLDmiXHmss4VJuKgouDVSx0pwp7SmfkCOA5CNTL/
GOTcm8rCaWsqsTilGEDmbxes28vvjn8mW1mFABEBAAG0KUt5bGUgVGhvbWFzIDxr
eWxlQHVubWFya2VkY29uc3VsdGluZy5jb20+iQFUBBMBCAA+FiEENgOAVL65Uk5E
aRndh71xCMLFehcFAllHZUMCGwMFCQPCZwAFCwkIBwIGFQgJCgsCBBYCAwECHgEC
F4AACgkQh71xCMLFehcOiwf/QpMwnmTBc9jj8QP08GZIIh7SDA8Wz8WNRwBEHOyg
hgSBt5jnKOS05QZLUhn2B9w9+aJyHqhwmr2/ReinCBWikc6/PjSCLtfEu1eAO0fZ
zo8z6an9qs2WodA/H6yS2CSmpI4KrZ1gnPNwWBUezUd2RrYjw1CUh9+RFViGPSNV
u4Pe3R1GFwgf21tIgy/AydWiJi7T3EqLTCMpMxiuEcVNS+ci678hN0/x+xexaKPg
m1+SFsqMKLpBmsqhegtnFBGROZh6T062DqgyR8S102cFRMjzNuTtVfz0EvpoYkAP
05MEDIbr6GhDCmsxhGPJ5N0zRc211AsuP/cChRKO6u/EOrkBDQRZR2VDAQgArYJm
7aI+rHoCZaHmjK6TAa6uJe6lyv3j85QHrjGP3vhl/WGBTuidcv9VtIj1Hep/3CDn
c7srnooK4PPJV1hYtkFrCYKPJDXpNwAeuaRzmSmTL11vWcgIl+CXWD3nNhN0vj7E
PMBNt+LoRhhfkNoT4RqEZp50QGzkyIGNfxi+I/8t+wCsZHm/gLVLXsnrYD6ohMzw
WMqikjzbIh2PDKKwe2/QHMvyKbz1avaa5zgT+zJZ0FOHgZg/njDWl73H2oZ0RWYG
rnB3evSEfjw0LOGwhgtJFwLMCeEZRbE9DiX7QMiDhI5DY1sbRd0LLp+KAr3VCoQM
fmw7gFG8wuigqUzJYwARAQABiQE8BBgBCAAmFiEENgOAVL65Uk5EaRndh71xCMLF
ehcFAllHZUMCGwwFCQPCZwAACgkQh71xCMLFeheEJAf9EnU6mqsXlvqB/AzVMA6l
DMOQ3jZmDICD2qqYyL0g2bDiHTLu0pAohdsne5gON/ake6bGCGqI5QpqcspegsgX
v0zRgKaAD8B7le8hl93ChDSzccBmIMHGVNaxjE3wlI3FNBZepEQUyGjXe9KEFFf8
ptxjlcysa+LUON7aUVDXZhYb2Hb8hCab01SALoIn76m6pv3W1jSDx93kKsJ1M/yB
CmjAgWQmf6yuxUHbCDpIez9mxLGYtjn0ZrN+yQJArqpdhbLjzUib1djDfedoTEhl
HOqs6gifyIkuQ1nvBueFWc2XZScNSjteNtjMVlfsBwJbBDL8v2DsomWbKqWOf3md
Cw==
=SSud
-----END PGP PUBLIC KEY BLOCK-----
`

	gpgPrivateKey = `
-----BEGIN PGP PRIVATE KEY BLOCK-----

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
eZ0L
=2aSe
-----END PGP PRIVATE KEY BLOCK-----
		`

	gpgPassword = "walletencryptionkey"

	err := EstablishNATSStreamingConnection()
	if err != nil {
		log.Panicf("Failed to established NATS streaming connection; %s", err.Error())
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
