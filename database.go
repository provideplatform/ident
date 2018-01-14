package main

import (
	"sync"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/kthomas/go-db-config"
)

var (
	migrateOnce sync.Once
)

func migrateSchema() {
	migrateOnce.Do(func() {
		db := dbconf.DatabaseConnection()

		db.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";")

		db.AutoMigrate(&User{})
		db.Model(&User{}).AddUniqueIndex("idx_users_email", "email")

		db.AutoMigrate(&Application{})
		db.Model(&Application{}).AddForeignKey("user_id", "users(id)", "SET NULL", "CASCADE")
		db.Model(&User{}).AddForeignKey("application_id", "applications(id)", "SET NULL", "CASCADE")

		db.AutoMigrate(&Token{})
		db.Model(&Token{}).AddIndex("idx_tokens_token", "token")
		db.Model(&Token{}).AddForeignKey("application_id", "applications(id)", "SET NULL", "CASCADE")
		db.Model(&Token{}).AddForeignKey("user_id", "users(id)", "SET NULL", "CASCADE")

	})
}

func DatabaseConnection() *gorm.DB {
	return dbconf.DatabaseConnection()
}
