package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"time"
)

// TOTPSecret generates a new TOTP secret for a user
func GenerateTOTPSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return base32.StdEncoding.EncodeToString(secret), nil
}

// GenerateTOTPCode generates the current TOTP code for a secret
func GenerateTOTPCode(secret string) (string, error) {
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}

	// Get current 30-second interval
	counter := uint64(time.Now().Unix() / 30)

	// HMAC-SHA1
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	hash := mac.Sum(nil)

	// Dynamic truncation
	offset := hash[len(hash)-1] & 0x0f
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	return fmt.Sprintf("%06d", code%1000000), nil
}

// VerifyTOTP checks if the provided code matches the current or adjacent windows
func VerifyTOTP(secret, code string) bool {
	// Check current window and ±1 window for clock drift tolerance
	for delta := -1; delta <= 1; delta++ {
		expected, err := generateTOTPForTime(secret, time.Now().Add(time.Duration(delta)*30*time.Second))
		if err == nil && expected == code {
			return true
		}
	}
	return false
}

func generateTOTPForTime(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}

	counter := uint64(t.Unix() / 30)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0x0f
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	return fmt.Sprintf("%06d", code%1000000), nil
}

// GetTOTPProvisioningURI generates an otpauth:// URI for QR code generation
func GetTOTPProvisioningURI(username, secret, issuer string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		issuer, username, secret, issuer)
}

// EnableMFA stores the TOTP secret for a user
func EnableMFA(db *sql.DB, userID int, secret string) error {
	_, err := db.Exec("UPDATE users SET totp_secret = ?, mfa_enabled = 1 WHERE id = ?", secret, userID)
	return err
}

// GetUserMFAStatus checks if user has MFA enabled and returns the secret
func GetUserMFAStatus(db *sql.DB, userID int) (bool, string, error) {
	var enabled bool
	var secret sql.NullString
	err := db.QueryRow("SELECT mfa_enabled, totp_secret FROM users WHERE id = ?", userID).Scan(&enabled, &secret)
	if err != nil {
		return false, "", err
	}
	return enabled, secret.String, nil
}
