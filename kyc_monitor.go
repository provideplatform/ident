package main

import "encoding/json"

func verifyUserEmailAddresses() {
	db := DatabaseConnection()
	users := make([]User, 0)
	db.Find(&users)
	for _, user := range users {
		if !user.verifyEmailAddress() {
			log.Debugf("Failed to verify user email address: %s; wiping user...", *user.Email)

			apps := make([]Application, 0)
			db.Where("user_id = ?", user.ID).Find(&apps)
			for _, app := range apps {
				db.Delete(&app)
			}

			tokens := make([]Token, 0)
			db.Where("user_id = ?", user.ID).Find(&tokens)
			for _, token := range tokens {
				db.Delete(&token)
			}

			db.Delete(&user)
		} else {
			payload, _ := json.Marshal(user)
			NATSPublish(natsSiaUserNotificationSubject, payload)
		}
	}
}
