package db

import (
	"os/user"
	"sync"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres" // PostgreSQL dialect
	dbconf "github.com/kthomas/go-db-config"
	"github.com/provideapp/ident/application"
	"github.com/provideapp/ident/kyc"
	"github.com/provideapp/ident/token"
)

var (
	migrateOnce sync.Once
)

// MigrateSchema migrates the database schema from scratch
func MigrateSchema() {
	migrateOnce.Do(func() {
		db := dbconf.DatabaseConnection()

		db.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";")
		db.Exec("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\";")

		db.AutoMigrate(&user.User{})
		db.Model(&user.User{}).AddIndex("idx_users_application_id", "application_id")
		db.Model(&user.User{}).AddIndex("idx_users_email", "email")
		db.Model(&user.User{}).AddUniqueIndex("idx_users_application_id_email", "application_id", "email")
		db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_null_application_id ON users (application_id, email) WHERE application_id IS NULL;")

		db.AutoMigrate(&application.Application{})
		db.Model(&application.Application{}).AddIndex("idx_applications_hidden", "hidden")
		db.Model(&application.Application{}).AddIndex("idx_applications_network_id", "network_id")
		db.Model(&application.Application{}).AddForeignKey("user_id", "users(id)", "SET NULL", "CASCADE")
		db.Model(&user.User{}).AddForeignKey("application_id", "applications(id)", "SET NULL", "CASCADE")

		db.AutoMigrate(&kyc.KYCApplication{})
		db.Model(&kyc.KYCApplication{}).AddIndex("idx_kyc_applications_user_id", "user_id")
		db.Model(&kyc.KYCApplication{}).AddIndex("idx_kyc_applications_application_id", "application_id")
		db.Model(&kyc.KYCApplication{}).AddIndex("idx_kyc_applications_identifier", "identifier")
		db.Model(&kyc.KYCApplication{}).AddIndex("idx_kyc_applications_status", "status")
		db.Model(&kyc.KYCApplication{}).AddForeignKey("user_id", "users(id)", "SET NULL", "CASCADE")

		db.AutoMigrate(&token.Token{})
		db.Model(&token.Token{}).AddIndex("idx_tokens_token", "token")
		db.Model(&token.Token{}).AddForeignKey("application_id", "applications(id)", "SET NULL", "CASCADE")
		db.Model(&token.Token{}).AddForeignKey("user_id", "users(id)", "SET NULL", "CASCADE")

	})
}

// DatabaseConnection returns the configured connecetion to the database.
func DatabaseConnection() *gorm.DB {
	return dbconf.DatabaseConnection()
}
