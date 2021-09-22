package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kthomas/go-auth0"
	"github.com/kthomas/go-pgputil"
	"github.com/kthomas/go-redisutil"

	"github.com/provideplatform/ident/application"
	"github.com/provideplatform/ident/common"
	"github.com/provideplatform/ident/organization"
	"github.com/provideplatform/ident/token"
	"github.com/provideplatform/ident/user"

	provide "github.com/provideplatform/provide-go/common"
	util "github.com/provideplatform/provide-go/common/util"
)

const jsonWebKey2020Type = "JsonWebKey2020"

const privacyPolicyUpdatedAt = "2018-10-19T00:00:00.000000"
const termsOfServiceUpdatedAt = "2018-10-19T00:00:00.000000"

const runloopSleepInterval = 250 * time.Millisecond
const runloopTickInterval = 5000 * time.Millisecond

var (
	cancelF     context.CancelFunc
	closing     uint32
	shutdownCtx context.Context
	sigs        chan os.Signal

	srv *http.Server
)

func init() {
	if common.ConsumeNATSStreamingSubscriptions {
		common.Log.Panicf("dedicated API instance started with CONSUME_NATS_STREAMING_SUBSCRIPTIONS=true")
		return
	}

	auth0.RequireAuth0()
	common.JWTKeypairs = util.RequireJWT()
	util.RequireGin()
	pgputil.RequirePGP()
	redisutil.RequireRedis()
	common.EnableAPIAccounting()
}

func main() {
	common.Log.Debugf("starting ident API...")
	installSignalHandlers()

	runAPI()

	timer := time.NewTicker(runloopTickInterval)
	defer timer.Stop()

	for !shuttingDown() {
		select {
		case <-timer.C:
			// tick... no-op
		case sig := <-sigs:
			common.Log.Debugf("received signal: %s", sig)
			srv.Shutdown(shutdownCtx)
			shutdown()
		case <-shutdownCtx.Done():
			close(sigs)
		default:
			time.Sleep(runloopSleepInterval)
		}
	}

	common.Log.Debug("exiting ident API")
	cancelF()
}

func installSignalHandlers() {
	common.Log.Debug("installing signal handlers for ident API")
	sigs = make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	shutdownCtx, cancelF = context.WithCancel(context.Background())
}

func shutdown() {
	if atomic.AddUint32(&closing, 1) == 1 {
		common.Log.Debug("shutting down ident API")
		cancelF()
	}
}

func runAPI() {
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.Use(provide.CORSMiddleware())

	r.GET("/.well-known/jwks.json", token.FetchJWKsHandler) // deprecated
	r.GET("/.well-known/jwks", token.FetchJWKsHandler)      // deprecated

	r.GET("/.well-known/keys", token.FetchJWKsHandler)
	r.GET("/.well-known/openid-configuration", openIDConfigurationHandler)
	r.GET("/.well-known/resolve/:did", resolveDIDHandler) // deprecated

	r.GET("/status", statusHandler)
	r.GET("/legal/privacy_policy", privacyPolicyHandler)
	r.GET("/legal/terms_of_service", termsOfServiceHandler)
	user.InstallPublicUserAPI(r)

	r.Use(token.AuthMiddleware())
	r.Use(common.AccountingMiddleware())
	r.Use(common.RateLimitingMiddleware())

	application.InstallApplicationAPI(r)
	application.InstallApplicationOrganizationsAPI(r)
	application.InstallApplicationUsersAPI(r)
	organization.InstallOrganizationAPI(r)
	organization.InstallOrganizationUsersAPI(r)
	organization.InstallOrganizationVaultsAPI(r)
	token.InstallTokenAPI(r)
	user.InstallUserAPI(r)

	srv = &http.Server{
		Addr:    util.ListenAddr,
		Handler: r,
	}

	if util.ServeTLS {
		go srv.ListenAndServeTLS(util.CertificatePath, util.PrivateKeyPath)
	} else {
		go srv.ListenAndServe()
	}

	common.Log.Debugf("listening on %s", util.ListenAddr)
}

// openIDConfigurationHandler returns the openid configuration under the well-known path
func openIDConfigurationHandler(c *gin.Context) {
	provide.Render(common.OpenIDConfiguration, 200, c)
}

func statusHandler(c *gin.Context) {
	status := map[string]interface{}{
		"privacy_policy_updated_at":   privacyPolicyUpdatedAt,
		"terms_of_service_updated_at": termsOfServiceUpdatedAt,
	}

	provide.Render(status, 200, c)
}

func privacyPolicyHandler(c *gin.Context) {
	resp := map[string]interface{}{}
	provide.Render(resp, 200, c)
}

func termsOfServiceHandler(c *gin.Context) {
	resp := map[string]interface{}{}
	provide.Render(resp, 200, c)
}

func resolveDIDHandler(c *gin.Context) {
	did := c.Param("did")

	verificationMethod := make([]interface{}, 0)
	assertionMethod := make([]interface{}, 0)
	authentication := make([]interface{}, 0)
	capabilityInvocation := make([]interface{}, 0)
	capabilityDelegation := make([]interface{}, 0)
	keyAgreement := make([]interface{}, 0)

	jwks, _ := common.ResolveJWKs()
	for _, jwk := range jwks {
		uri := fmt.Sprintf("%s#%s", did, jwk.Fingerprint)

		verificationMethod = append(verificationMethod, map[string]interface{}{
			"id":           uri,
			"type":         jsonWebKey2020Type,
			"controller":   did,
			"publicKeyJwk": jwk,
		})

		assertionMethod = append(assertionMethod, uri)
		authentication = append(authentication, uri)
		capabilityInvocation = append(capabilityInvocation, uri)
		capabilityDelegation = append(capabilityDelegation, uri)
		keyAgreement = append(keyAgreement, uri)
	}

	document := &common.DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
		},
		ID:                   did,
		VerificationMethod:   verificationMethod,
		AssertionMethod:      assertionMethod,
		Authentication:       authentication,
		CapabilityInvocation: capabilityInvocation,
		CapabilityDelegation: capabilityDelegation,
		KeyAgreement:         keyAgreement,
	}

	provide.Render(document, 200, c)
}

func shuttingDown() bool {
	return (atomic.LoadUint32(&closing) > 0)
}
