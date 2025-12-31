package handler

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sync/atomic"
	"time"

	"github.com/SamNet-dev/wg-orchestrator/services/api/internal/auth"
)

// Global metrics counters
var (
	loginFailures  atomic.Int64
	loginSuccesses atomic.Int64
	apiErrors      atomic.Int64
)

// HealthLive returns 200 if process is alive
func HealthLive(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// HealthReady checks actual backend health before returning 200
func HealthReady(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Database is critical - must be accessible
		if err := db.Ping(); err != nil {
			apiErrors.Add(1)
			http.Error(w, "DB unavailable", http.StatusServiceUnavailable)
			return
		}

		// WireGuard check is best-effort - log but don't fail
		// Container may not have access to host WireGuard interface
		status := "READY"
		if _, err := exec.Command("wg", "show", "wg0").Output(); err != nil {
			status = "READY (WireGuard inaccessible from container)"
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(status))
	}
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Lockout configuration (can be overridden via env)
var (
	MaxFailedAttempts = getEnvInt("MAX_FAILED_ATTEMPTS", 5)
	LockoutDuration   = getEnvDuration("LOCKOUT_DURATION", 15*time.Minute)
)

func getEnvInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		var i int
		if _, err := fmt.Sscanf(v, "%d", &i); err == nil {
			return i
		}
	}
	return defaultVal
}

func getEnvDuration(key string, defaultVal time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return defaultVal
}

// GetClientIP extracts real client IP from request, trusting headers for UI display context
func GetClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return GetAuditIP(r)
}

// GetAuditIP strictly uses RemoteAddr for security-critical logging and lockout checks
func GetAuditIP(r *http.Request) string {
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}

func Login(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := GetAuditIP(r)

		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		var id int
		var pHash string
		var role string
		var failedAttempts int
		var lockoutUntil sql.NullTime

		err := db.QueryRow("SELECT id, password_hash, role, failed_attempts, lockout_until FROM users WHERE username = ?", req.Username).Scan(&id, &pHash, &role, &failedAttempts, &lockoutUntil)

		// Use constant-time verification to prevent username enumeration
		userExists := err == nil
		valid, _ := auth.VerifyPasswordConstantTime(pHash, req.Password, userExists)

		if !userExists {
			loginFailures.Add(1)
			// Log failed attempt with IP (for analysis, not blocking)
			db.Exec("INSERT INTO audit_logs (user_id, action, target, details, ip_address) VALUES (0, 'LOGIN_FAIL', ?, 'User not found', ?)",
				req.Username, clientIP)
			http.Error(w, "Invalid Credentials", http.StatusUnauthorized)
			return
		}

		if lockoutUntil.Valid && lockoutUntil.Time.After(time.Now()) {
			http.Error(w, "Account locked. Try again later.", http.StatusForbidden)
			return
		}

		if !valid {
			loginFailures.Add(1)
			failedAttempts++

			db.Exec("INSERT INTO audit_logs (user_id, action, target, details, ip_address) VALUES (?, 'LOGIN_FAIL', ?, 'Wrong password', ?)",
				id, req.Username, clientIP)

			if failedAttempts >= MaxFailedAttempts {
				lockout := time.Now().Add(LockoutDuration)
				db.Exec("UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE id = ?", failedAttempts, lockout, id)
				http.Error(w, "Too many attempts. Account locked.", http.StatusForbidden)
			} else {
				db.Exec("UPDATE users SET failed_attempts = ? WHERE id = ?", failedAttempts, id)
				http.Error(w, "Invalid Credentials", http.StatusUnauthorized)
			}
			return
		}

		loginSuccesses.Add(1)
		db.Exec("UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE id = ?", id)

		db.Exec("INSERT INTO audit_logs (user_id, action, target, details, ip_address) VALUES (?, 'LOGIN_SUCCESS', ?, 'Login successful', ?)",
			id, req.Username, clientIP)

		token, err := auth.CreateSession(db, id)
		if err != nil {
			apiErrors.Add(1)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		// Auto-detect HTTPS for Secure flag
		isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" || os.Getenv("INSECURE_HTTP") != "true"

		http.SetCookie(w, &http.Cookie{
			Name:     "samnet_session",
			Value:    token,
			HttpOnly: true,
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
			Secure:   isSecure,
			MaxAge:   43200, // 12 hours
		})

		// Rotate CSRF token after login (security best practice)
		csrfBytes := make([]byte, 32)
		rand.Read(csrfBytes)
		newCSRF := base64.URLEncoding.EncodeToString(csrfBytes)
		http.SetCookie(w, &http.Cookie{
			Name:     "csrf_token",
			Value:    newCSRF,
			Path:     "/",
			HttpOnly: false, // Must be readable by JS
			Secure:   isSecure,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   86400, // 24 hours
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "success", "role": role})
	}
}

func Logout(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("samnet_session")
		if err == nil {
			tokenHash := auth.HashToken(c.Value)
			db.Exec("DELETE FROM sessions WHERE token_hash = ?", tokenHash)
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "samnet_session",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		})

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "logged_out"}`))
	}
}

func Metrics(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var peerCount int
		db.QueryRow("SELECT COUNT(*) FROM peers").Scan(&peerCount)

		var userCount int
		db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)

		var activeSessions int
		db.QueryRow("SELECT COUNT(*) FROM sessions WHERE expires_at > CURRENT_TIMESTAMP").Scan(&activeSessions)

		w.Header().Set("Content-Type", "text/plain")

		// Core metrics
		fmt.Fprintf(w, "# HELP samnet_peers_total Total number of WireGuard peers\n")
		fmt.Fprintf(w, "# TYPE samnet_peers_total gauge\n")
		fmt.Fprintf(w, "samnet_peers_total %d\n", peerCount)

		fmt.Fprintf(w, "# HELP samnet_users_total Total number of registered users\n")
		fmt.Fprintf(w, "# TYPE samnet_users_total gauge\n")
		fmt.Fprintf(w, "samnet_users_total %d\n", userCount)

		fmt.Fprintf(w, "# HELP samnet_active_sessions Current active sessions\n")
		fmt.Fprintf(w, "# TYPE samnet_active_sessions gauge\n")
		fmt.Fprintf(w, "samnet_active_sessions %d\n", activeSessions)

		fmt.Fprintf(w, "samnet_up 1\n")

		// Error rate metrics
		fmt.Fprintf(w, "# HELP samnet_login_failures_total Total login failures\n")
		fmt.Fprintf(w, "# TYPE samnet_login_failures_total counter\n")
		fmt.Fprintf(w, "samnet_login_failures_total %d\n", loginFailures.Load())

		fmt.Fprintf(w, "# HELP samnet_login_successes_total Total successful logins\n")
		fmt.Fprintf(w, "# TYPE samnet_login_successes_total counter\n")
		fmt.Fprintf(w, "samnet_login_successes_total %d\n", loginSuccesses.Load())

		fmt.Fprintf(w, "# HELP samnet_api_errors_total Total API errors\n")
		fmt.Fprintf(w, "# TYPE samnet_api_errors_total counter\n")
		fmt.Fprintf(w, "samnet_api_errors_total %d\n", apiErrors.Load())

		// Per-Peer Metrics
		rows, err := db.Query("SELECT name, last_handshake, rx_bytes, tx_bytes FROM peers")
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var name string
				var hh sql.NullTime
				var rx, tx int64
				if err := rows.Scan(&name, &hh, &rx, &tx); err == nil {
					var ts int64
					if hh.Valid {
						ts = hh.Time.Unix()
					}
					fmt.Fprintf(w, "samnet_peer_last_handshake_seconds{peer=\"%s\"} %d\n", name, ts)
					fmt.Fprintf(w, "samnet_peer_rx_bytes_total{peer=\"%s\"} %d\n", name, rx)
					fmt.Fprintf(w, "samnet_peer_tx_bytes_total{peer=\"%s\"} %d\n", name, tx)
				}
			}
		}

		// Subnet capacity metrics for exhaustion monitoring
		var subnetCIDR string
		db.QueryRow("SELECT value FROM system_config WHERE key='subnet_cidr'").Scan(&subnetCIDR)
		if subnetCIDR == "" {
			subnetCIDR = "10.100.0.0/24"
		}
		maxPeers := CalculateMaxPeers(subnetCIDR)
		usagePercent := float64(peerCount) / float64(maxPeers) * 100

		fmt.Fprintf(w, "# HELP samnet_subnet_capacity_max Maximum peers in configured subnet\n")
		fmt.Fprintf(w, "# TYPE samnet_subnet_capacity_max gauge\n")
		fmt.Fprintf(w, "samnet_subnet_capacity_max{cidr=\"%s\"} %d\n", subnetCIDR, maxPeers)

		fmt.Fprintf(w, "# HELP samnet_subnet_usage_percent Percentage of subnet capacity used\n")
		fmt.Fprintf(w, "# TYPE samnet_subnet_usage_percent gauge\n")
		fmt.Fprintf(w, "samnet_subnet_usage_percent %.2f\n", usagePercent)
	}
}

// CalculateMaxPeers logic is centralized in subnet.go
