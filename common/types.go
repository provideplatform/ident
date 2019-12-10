package common

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	uuid "github.com/kthomas/go.uuid"
)

// APICall for accounting purposes
type APICall struct {
	ApplicationID string    `json:"application_id"`
	UserID        string    `json:"user_id"`
	Sub           string    `json:"sub"`
	Method        string    `json:"method"`
	Host          string    `json:"host"`
	Path          string    `json:"path"`
	RemoteAddr    string    `json:"remote_addr"`
	Timestamp     time.Time `json:"timestamp"`
	ContentLength *uint     `json:"content_length"`
	StatusCode    int       `json:"status_code"`
	Sha256        *string   `json:"sha256"`
}

// CalculateHash calculates the sha256 hash of the APICall instance using
// the given packet; if packet is nil, the json representation of APICall
// is used to calculate the hash; this is used to ensure no api call is
// accounted for twice
func (a *APICall) CalculateHash(packet *[]byte) error {
	representation := packet
	if packet == nil {
		apiCallJSON, _ := json.Marshal(a)
		packet = &apiCallJSON
	}

	digest := sha256.New()
	_, err := digest.Write(*representation)
	if err != nil {
		return err
	}
	hash := hex.EncodeToString(digest.Sum(nil))
	a.Sha256 = &hash
	return nil
}

// Model base class with uuid v4 primary key id
type Model struct {
	ID        uuid.UUID `sql:"primary_key;type:uuid;default:uuid_generate_v4()" json:"id"`
	CreatedAt time.Time `sql:"not null;default:now()" json:"created_at,omitempty"`
	Errors    []*Error  `sql:"-" json:"-"`
}

// Error struct
type Error struct {
	Message *string `json:"message"`
	Status  *int    `json:"status,omitempty"`
}
