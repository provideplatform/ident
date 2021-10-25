module github.com/provideplatform/ident

go 1.15

require (
	github.com/Microsoft/go-winio v0.4.14 // indirect
	github.com/badoux/checkmail v0.0.0-20200623144435-f9f80cb795fa
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v1.13.1 // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/gin-gonic/gin v1.7.0
	github.com/golang-migrate/migrate v3.5.4+incompatible
	github.com/jinzhu/gorm v1.9.16
	github.com/joho/godotenv v1.3.0
	github.com/kthomas/go-auth0 v0.0.0-20210417042937-27d1d2dadf19
	github.com/kthomas/go-db-config v0.0.0-20200612131637-ec0436a9685e
	github.com/kthomas/go-logger v0.0.0-20210526080020-a63672d0724c
	github.com/kthomas/go-natsutil v0.0.0-20210911093321-41b91674d612
	github.com/kthomas/go-pgputil v0.0.0-20200602073402-784e96083943
	github.com/kthomas/go-redisutil v0.0.0-20200602073431-aa49de17e9ff
	github.com/kthomas/go.uuid v1.2.1-0.20190324131420-28d1fa77e9a4
	github.com/kthomas/trumail v0.0.0-20190925185815-ab3de2e834a3
	github.com/lib/pq v1.2.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/nats-io/nats.go v1.12.0
	github.com/ockam-network/did v0.1.3
	github.com/onsi/ginkgo v1.14.0
	github.com/onsi/gomega v1.10.1
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/provideplatform/provide-go v0.0.0-20210624064849-d7328258f0d8
	golang.org/x/crypto v0.0.0-20210314154223-e6e6c4f2bb5b
)

replace github.com/provideplatform/provide-go => ../provide-go
