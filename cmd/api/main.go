package api

import (
	"github.com/gin-gonic/gin"
	"github.com/provideapp/ident/application"
	"github.com/provideapp/ident/common"
	"github.com/provideapp/ident/consumer"
	"github.com/provideapp/ident/kyc"
	"github.com/provideapp/ident/token"
	"github.com/provideapp/ident/user"
	provide "github.com/provideservices/provide-go"
)

const defaultResultsPerPage = 25
const privacyPolicyUpdatedAt = "2018-10-19T00:00:00.000000"
const termsOfServiceUpdatedAt = "2018-10-19T00:00:00.000000"

func main() {
	if common.ConsumeNATSStreamingSubscriptions {
		common.Log.Panicf("Dedicated API instance started with CONSUME_NATS_STREAMING_SUBSCRIPTIONS=true")
		return
	}

	common.Log.Debugf("Running dedicated API instance main()")

	consumer.RunAPIUsageDaemon()

	r := gin.Default()
	r.Use(gin.Recovery())
	r.Use(provide.CORSMiddleware())
	r.Use(provide.TrackAPICalls())

	application.InstallApplicationAPI(r)
	token.InstallTokenAPI(r)
	user.InstallUserAPI(r)
	kyc.InstallKYCAPI(r)

	r.GET("/status", statusHandler)

	if common.ShouldServeTLS() {
		r.RunTLS(common.ListenAddr, common.CertificatePath, common.PrivateKeyPath)
	} else {
		r.Run(common.ListenAddr)
	}
}

func statusHandler(c *gin.Context) {
	status := map[string]interface{}{
		"privacy_policy_updated_at":   privacyPolicyUpdatedAt,
		"terms_of_service_updated_at": termsOfServiceUpdatedAt,
	}
	provide.Render(status, 200, c)
}
