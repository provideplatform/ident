package sia

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	"github.com/provideapp/ident/application"
	"github.com/provideapp/ident/common"
	"github.com/provideapp/ident/user"
)

var siaDB *gorm.DB
var siaDBConfig *dbconf.DBConfig
var siaConfigOnce sync.Once
var siaDBOnce sync.Once

func init() {
	siaDatabaseConnection()
	dispatchSiaNotifications()
}

// siaDatabaseConnection returns a leased database connection from the underlying
// pool configured from the environment-configured sia database connection
func siaDatabaseConnection() *gorm.DB {
	siaDBOnce.Do(func() {
		db, err := dbconf.DatabaseConnectionFactory(getSiaDBConfig())
		if err != nil {
			msg := fmt.Sprintf("Sia database connection failed; %s", err.Error())
			panic(msg)
		}

		siaDB = db
	})
	return siaDB
}

// getSiaDBConfig reads the sia database config out of the environment
func getSiaDBConfig() *dbconf.DBConfig {
	siaConfigOnce.Do(func() {
		databaseName := os.Getenv("SIA_DATABASE_NAME")
		if databaseName == "" {
			databaseName = "sia_development"
		}

		databaseHost := os.Getenv("SIA_DATABASE_HOST")
		if databaseHost == "" {
			databaseHost = "localhost"
		}

		databasePort, _ := strconv.ParseUint(os.Getenv("SIA_DATABASE_PORT"), 10, 8)
		if databasePort == 0 {
			databasePort = 5432
		}

		databaseUser := os.Getenv("SIA_DATABASE_USER")
		if databaseUser == "" {
			databaseUser = "root"
		}

		databasePassword := os.Getenv("SIA_DATABASE_PASSWORD")
		if databasePassword == "" {
			databasePassword = "password"
		}

		databaseSSLMode := os.Getenv("SIA_DATABASE_SSL_MODE")
		if databaseSSLMode == "" {
			databaseSSLMode = "disable"
		}

		databasePoolMaxIdleConnections, _ := strconv.ParseInt(os.Getenv("SIA_DATABASE_POOL_MAX_IDLE_CONNECTIONS"), 10, 8)
		if databasePoolMaxIdleConnections == 0 {
			databasePoolMaxIdleConnections = -1
		}

		databasePoolMaxOpenConnections, _ := strconv.ParseInt(os.Getenv("SIA_DATABASE_POOL_MAX_OPEN_CONNECTIONS"), 10, 8)

		siaDBConfig = &dbconf.DBConfig{
			DatabaseName:                   databaseName,
			DatabaseHost:                   databaseHost,
			DatabasePort:                   uint(databasePort),
			DatabaseUser:                   databaseUser,
			DatabasePassword:               databasePassword,
			DatabaseSSLMode:                databaseSSLMode,
			DatabasePoolMaxIdleConnections: int(databasePoolMaxIdleConnections),
			DatabasePoolMaxOpenConnections: int(databasePoolMaxOpenConnections),
			DatabaseEnableLogging:          os.Getenv("SIA_DATABASE_LOGGING") == "true",
		}
	})
	return siaDBConfig
}

// dispatchSiaNotifications is currently a very naive way to publish a message
// about each record in ident that sia cares about and listens for in the
// embedded sia_consumer binary. as the number of users and applications grows
// this method could become very noisy...
func dispatchSiaNotifications() {
	identDB := dbconf.DatabaseConnection()

	if os.Getenv("SIA_DISPATCH_USER_NOTIFICATIONS") == "true" {
		dispatchUserNotifications(identDB)
	}

	if os.Getenv("SIA_DISPATCH_APPLICATION_NOTIFICATIONS") == "true" {
		dispatchApplicationNotifications(identDB)
	}
}

func dispatchUserNotifications(db *gorm.DB) {
	var users []*user.User
	db.Where("application_id IS NULL").Find(&users)

	common.Log.Debugf("Dispatching %d sia user notifications...", len(users))
	for _, usr := range users {
		usr.Enrich()
		payload, _ := json.Marshal(usr)
		natsutil.NatsStreamingPublish(natsSiaUserNotificationSubject, payload)
	}
}

func dispatchApplicationNotifications(db *gorm.DB) {
	var apps []*application.Application
	db.Find(&apps)

	common.Log.Debugf("Dispatching %d sia application notifications...", len(apps))
	for _, app := range apps {
		payload, _ := json.Marshal(app)
		natsutil.NatsStreamingPublish(natsSiaApplicationNotificationSubject, payload)
	}
}
