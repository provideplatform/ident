package main

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/provideapp/ident/common"

	"github.com/golang-migrate/migrate"
	"github.com/golang-migrate/migrate/database/postgres"
	_ "github.com/golang-migrate/migrate/source/file"

	dbconf "github.com/kthomas/go-db-config"
)

const initIfNotExistTimeout = time.Second * 30

func main() {
	cfg := dbconf.GetDBConfig()
	initIfNotExists(
		cfg,
		os.Getenv("DATABASE_SUPERUSER"),
		os.Getenv("DATABASE_SUPERUSER_PASSWORD"),
	)

	dsn := fmt.Sprintf(
		"postgres://%s/%s?user=%s&password=%s&sslmode=%s",
		cfg.DatabaseHost,
		cfg.DatabaseName,
		cfg.DatabaseUser,
		url.QueryEscape(cfg.DatabasePassword),
		cfg.DatabaseSSLMode,
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		common.Log.Warningf("migrations failed 1: %s", err.Error())
		panic(err)
	}

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		common.Log.Warningf("migrations failed 2: %s config: %a", err.Error(), &postgres.Config{})
		panic(err)
	}

	m, err := migrate.NewWithDatabaseInstance("file://./ops/migrations", cfg.DatabaseName, driver)
	if err != nil {
		common.Log.Warningf("migrations failed 3: %s", err.Error())
		panic(err)
	}

	err = m.Up()
	if err != nil && err != migrate.ErrNoChange {
		common.Log.Warningf("migrations failed 4: %s", err.Error())
	}
}

func initIfNotExists(cfg *dbconf.DBConfig, superuser, password string) error {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Debugf("migrations recovered during user/db setup; %s", r)
		}
	}()

	if superuser == "" || password == "" {
		return nil
	}

	superuserCfg := &dbconf.DBConfig{
		DatabaseName:     superuser,
		DatabaseHost:     cfg.DatabaseHost,
		DatabasePort:     cfg.DatabasePort,
		DatabaseUser:     superuser,
		DatabasePassword: password,
		DatabaseSSLMode:  "require",
	}

	var client *gorm.DB
	var err error

	ticker := time.NewTicker(initIfNotExistTimeout)
	startedAt := time.Now()
	for {
		select {
		case <-ticker.C:
			client, err = dbconf.DatabaseConnectionFactory(superuserCfg)
			if err == nil {
				ticker.Stop()
				break
			}

			if time.Now().Sub(startedAt) >= initIfNotExistTimeout {
				common.Log.Warningf("migrations failed 4.5: %s :debug: host name %s, port name %d", err.Error(), superuserCfg.DatabaseHost, superuserCfg.DatabasePort)
				ticker.Stop()
				break
			}
		}
	}

	if err != nil {
		common.Log.Warningf("migrations failed 5: %s :debug: host name %s, port name %d", err.Error(), superuserCfg.DatabaseHost, superuserCfg.DatabasePort)
		return err
	}
	defer client.Close()

	// create the ident user if it doesn't exist
	//HACK: this throws an unfriendly error, but the migration fail without it, so more investigation needed here...
	common.Log.Debugf("ident.main.initIfNotExists: creating db user.")
	if err := client.Exec(fmt.Sprintf("CREATE ROLE %s WITH LOGIN NOSUPERUSER", cfg.DatabaseUser)); err != nil {
		common.Log.Warningf("ident.main.initIfNotExists: Error creating user %s, error: ", cfg.DatabaseUser, err)
	}

	result := client.Exec(fmt.Sprintf("ALTER USER %s WITH SUPERUSER PASSWORD '%s'", cfg.DatabaseUser, cfg.DatabasePassword))
	if err != nil {
		common.Log.Warningf("migrations failed-alteruser: %s with parameters %s %s", err.Error(), cfg.DatabaseName, cfg.DatabaseUser)
		return err
	}

	if err == nil {
		result = client.Exec(fmt.Sprintf("CREATE DATABASE %s OWNER %s", cfg.DatabaseName, cfg.DatabaseUser))
		err = result.Error
		if err != nil {
			common.Log.Warningf("migrations failed-createdb: %s for parameters %a %b", err.Error(), cfg.DatabaseName, cfg.DatabaseUser)
			return err
		}
	}

	return nil
}
