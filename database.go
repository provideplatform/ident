package main

import (
	"sync"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	dbconf "github.com/kthomas/go-db-config"
)

var (
	migrateOnce sync.Once
)

func migrateSchema() {
	migrateOnce.Do(func() {
		db := dbconf.DatabaseConnection()

		db.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";")
		db.Exec("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\";")

		db.AutoMigrate(&User{})
		db.Model(&User{}).AddIndex("idx_users_application_id", "application_id")
		db.Model(&User{}).AddIndex("idx_users_email", "email")
		db.Model(&User{}).AddUniqueIndex("idx_users_application_id_email", "application_id", "email")
		db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_null_application_id ON users (application_id, email) WHERE application_id IS NULL;")

		db.AutoMigrate(&Application{})
		db.Model(&Application{}).AddIndex("idx_applications_hidden", "hidden")
		db.Model(&Application{}).AddIndex("idx_applications_network_id", "network_id")
		db.Model(&Application{}).AddForeignKey("user_id", "users(id)", "SET NULL", "CASCADE")
		db.Model(&User{}).AddForeignKey("application_id", "applications(id)", "SET NULL", "CASCADE")

		db.AutoMigrate(&KYCApplication{})
		db.Model(&KYCApplication{}).AddIndex("idx_kyc_applications_application_id", "application_id")
		db.Model(&KYCApplication{}).AddIndex("idx_kyc_applications_user_id", "user_id")
		db.Model(&KYCApplication{}).AddIndex("idx_kyc_applications_identifier", "identifier")
		db.Model(&KYCApplication{}).AddIndex("idx_kyc_applications_status", "status")
		db.Model(&KYCApplication{}).AddForeignKey("user_id", "users(id)", "SET NULL", "CASCADE")

		db.AutoMigrate(&Token{})
		db.Model(&Token{}).AddIndex("idx_tokens_token", "token")
		db.Model(&Token{}).AddForeignKey("application_id", "applications(id)", "SET NULL", "CASCADE")
		db.Model(&Token{}).AddForeignKey("user_id", "users(id)", "SET NULL", "CASCADE")

	})
}

// DatabaseConnection returns the configured connecetion to the database.
func DatabaseConnection() *gorm.DB {
	return dbconf.DatabaseConnection()
}
