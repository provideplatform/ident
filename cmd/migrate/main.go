package main

import (
	"database/sql"
	"fmt"
	"net/url"

	"github.com/provideapp/ident/common"

	"github.com/golang-migrate/migrate"
	"github.com/golang-migrate/migrate/database/postgres"
	_ "github.com/golang-migrate/migrate/source/file"

	dbconf "github.com/kthomas/go-db-config"
)

func main() {
	cfg := dbconf.GetDBConfig()
	dsn := fmt.Sprintf("postgres://%s/%s?user=%s&password=%s&sslmode=%s",
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
