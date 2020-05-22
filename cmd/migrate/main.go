package main

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"

	"github.com/provideapp/ident/common"

	"github.com/golang-migrate/migrate"
	"github.com/golang-migrate/migrate/database/postgres"
	_ "github.com/golang-migrate/migrate/source/file"

	dbconf "github.com/kthomas/go-db-config"
)

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
		common.Log.Warningf("migrations failed: %s", err.Error())
		panic(err)
	}

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		common.Log.Warningf("migrations failed: %s", err.Error())
		panic(err)
	}

	m, err := migrate.NewWithDatabaseInstance("file://./ops/migrations", cfg.DatabaseName, driver)
	if err != nil {
		common.Log.Warningf("migrations failed: %s", err.Error())
		panic(err)
	}

	err = m.Up()
	if err != nil && err != migrate.ErrNoChange {
		common.Log.Warningf("migrations failed: %s", err.Error())
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
		DatabaseHost:     cfg.DatabaseHost,
		DatabasePort:     cfg.DatabasePort,
		DatabaseName:     superuser,
		DatabaseUser:     superuser,
		DatabasePassword: password,
		DatabaseSSLMode:  "require",
	}

	client, err := dbconf.DatabaseConnectionFactory(superuserCfg)
	if err != nil {
		common.Log.Warningf("migrations failed: %s", err.Error())
		return err
	}
	defer client.Close()

	result := client.Exec(fmt.Sprintf("ALTER USER %s WITH SUPERUSER PASSWORD '%s'", cfg.DatabaseUser, cfg.DatabasePassword))
	if err != nil {
		common.Log.Warningf("migrations failed: %s", err.Error())
		return err
	}
	if err == nil {
		result = client.Exec(fmt.Sprintf("CREATE DATABASE %s OWNER %s", cfg.DatabaseName, cfg.DatabaseUser))
		err = result.Error
		if err != nil {
			common.Log.Warningf("migrations failed: %s", err.Error())
			return err
		}
	}

	return nil
}
