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

func PgEncrypt() (*string, error) {
	// var result
	// db.Raw("SELECT pgp_pub_encrypt(?, dearmor(?)) as private_key", encodedPrivateKey, gpgPublicKey).Scan(&result)
	return nil, nil
}

func PgDecrypt() (*string, error) {
	// results := make([]byte, 1)
	// db := DatabaseConnection()
	// rows, err := db.Raw("SELECT pgp_pub_decrypt(?, dearmor(?), ?) as private_key", w.PrivateKey, gpgPrivateKey, gpgEncryptionKey).Rows()
	// if err != nil {
	// 	return nil, err
	// }
	// if rows.Next() {
	// 	rows.Scan(&results)
	// 	privateKeyBytes, err := hex.DecodeString(string(results))
	// 	if err != nil {
	// 		Log.Warningf("Failed to decode ecdsa private key from encrypted storage; %s", err.Error())
	// 		return nil, err
	// 	}
	// }
	return nil, nil
}
