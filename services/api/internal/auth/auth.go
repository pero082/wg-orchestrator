package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/SamNet-dev/wg-orchestrator/services/api/internal/config"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
)

// GenerateWireGuardKeys generates a Curve25519 key pair for WireGuard
func GenerateWireGuardKeys() (privateKey, publicKey string, err error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", err
	}

	// Clamp the private key (to ensure it's a valid Curve25519 private key)
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	privateKey = base64.StdEncoding.EncodeToString(priv[:])
	publicKey = base64.StdEncoding.EncodeToString(pub[:])
	return privateKey, publicKey, nil
}

// GetPublicKeyFromPrivate derives the WireGuard public key from a base64 encoded private key
func GetPublicKeyFromPrivate(privateKeyB64 string) (string, error) {
	priv, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return "", err
	}
	if len(priv) != 32 {
		return "", errors.New("invalid private key length")
	}

	var pub [32]byte
	var privBytes [32]byte
	copy(privBytes[:], priv)
	curve25519.ScalarBaseMult(&pub, &privBytes)

	return base64.StdEncoding.EncodeToString(pub[:]), nil
}

// Argon2id default parameters (OWASP recommended)
// Can be overridden via env vars: ARGON2_TIME, ARGON2_MEMORY, ARGON2_THREADS
var (
	argon2TimeCost = getEnvIntOrDefault("ARGON2_TIME", 3)
	argon2Memory   = uint32(getEnvIntOrDefault("ARGON2_MEMORY", 64*1024))
	argon2Threads  = uint8(getEnvIntOrDefault("ARGON2_THREADS", 2))
	keyLen         = uint32(32)
	saltLen        = 16
)

func getEnvIntOrDefault(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		var i int
		if _, err := fmt.Sscanf(v, "%d", &i); err == nil && i > 0 {
			return i
		}
	}
	return defaultVal
}

// DummyHash is used for constant-time auth to prevent username enumeration
var DummyHash string

func init() {
	// Pre-compute a dummy hash to use when user doesn't exist
	// This ensures consistent timing regardless of user existence
	DummyHash, _ = HashPassword("dummy_password_for_timing_safety")
}

func VerifyPassword(encodedHash, password string) (bool, error) {
	// Format: $argon2id$v=19$m=65536,t=3,p=2$salt$hash
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, errors.New("invalid hash format")
	}

	if parts[1] != "argon2id" {
		return false, errors.New("unsupported variant")
	}

	var mem, time, thr int
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &time, &thr)
	if err != nil {
		return false, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}

	newHash := argon2.IDKey([]byte(password), salt, uint32(time), uint32(mem), uint8(thr), keyLen)

	if subtle.ConstantTimeCompare(decodedHash, newHash) == 1 {
		return true, nil
	}
	return false, nil
}

// VerifyPasswordConstantTime always runs Argon2id verification to prevent timing attacks.
// Call this even when user doesn't exist to prevent username enumeration.
func VerifyPasswordConstantTime(encodedHash, password string, userExists bool) (bool, error) {
	if !userExists {
		// Run verification against dummy hash to maintain constant timing
		VerifyPassword(DummyHash, password)
		return false, nil
	}
	return VerifyPassword(encodedHash, password)
}

// CheckPassword is an alias for VerifyPassword for API compatibility
func CheckPassword(encodedHash, password string) (bool, error) {
	return VerifyPassword(encodedHash, password)
}

func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, uint32(argon2TimeCost), argon2Memory, argon2Threads, keyLen)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argon2Memory, argon2TimeCost, argon2Threads, b64Salt, b64Hash), nil
}

// MaxSessionsPerUser limits concurrent sessions to prevent credential stuffing
const MaxSessionsPerUser = 5

// SessionTokenBytes is the entropy for session tokens (384 bits = quantum resistant)
const SessionTokenBytes = 48

func CreateSession(db *sql.DB, userID int) (string, error) {
	var oldSessionIDs []int
	rows, err := db.Query(`
		SELECT id FROM sessions 
		WHERE user_id = ? 
		ORDER BY created_at DESC 
		LIMIT -1 OFFSET ?`, userID, MaxSessionsPerUser-1)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id int
			if rows.Scan(&id) == nil {
				oldSessionIDs = append(oldSessionIDs, id)
			}
		}
		for _, id := range oldSessionIDs {
			db.Exec("DELETE FROM sessions WHERE id = ?", id)
		}
	}

	tokenBytes := make([]byte, SessionTokenBytes)
	rand.Read(tokenBytes)
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	expiry := time.Now().Add(12 * time.Hour)
	_, err = db.Exec("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
		tokenHash, userID, time.Now(), expiry)

	return token, err
}

// InvalidateAllSessions clears all sessions for a user (for password change, logout everywhere)
func InvalidateAllSessions(db *sql.DB, userID int) error {
	_, err := db.Exec("DELETE FROM sessions WHERE user_id = ?", userID)
	return err
}

func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// Encrypt encrypts data using AES-256-GCM and the master key.
func Encrypt(plaintext string) (string, error) {
	key, err := GetMasterKey()
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts data using AES-256-GCM and the master key.
func Decrypt(encoded string) (string, error) {
	key, err := GetMasterKey()
	if err != nil {
		return "", err
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// GetMasterKey loads or generates the master key with file locking to prevent race conditions.
// Uses atomic write pattern: write to temp file, then rename.
func GetMasterKey() ([]byte, error) {
	masterKeyPath := config.Get().MasterKeyPath
	dir := filepath.Dir(masterKeyPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}

	if data, err := os.ReadFile(masterKeyPath); err == nil && len(data) == 32 {
		return data, nil
	}

	// Use file locking to prevent race condition
	lockPath := masterKeyPath + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to create lock file: %w", err)
	}
	defer lockFile.Close()
	defer os.Remove(lockPath)

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

	// Double-check if another process created the key while we waited for lock
	if data, err := os.ReadFile(masterKeyPath); err == nil && len(data) == 32 {
		return data, nil
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	tmpPath := masterKeyPath + ".tmp"
	if err := os.WriteFile(tmpPath, key, 0600); err != nil {
		return nil, fmt.Errorf("failed to write temp key: %w", err)
	}
	if err := os.Rename(tmpPath, masterKeyPath); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("failed to rename key file: %w", err)
	}

	// Explicitly enforce permissions after rename (some filesystems don't preserve)
	if err := os.Chmod(masterKeyPath, 0600); err != nil {
		return nil, fmt.Errorf("failed to set key permissions: %w", err)
	}

	return key, nil
}
