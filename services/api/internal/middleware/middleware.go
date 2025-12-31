package middleware

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/SamNet-dev/wg-orchestrator/services/api/internal/auth"
)

// Context keys for user info and request correlation
type contextKey string

const (
	UserIDKey    contextKey = "user_id"
	UserRoleKey  contextKey = "user_role"
	RequestIDKey contextKey = "request_id"
)

// GetUserID retrieves user ID from request context
func GetUserID(r *http.Request) int {
	if id, ok := r.Context().Value(UserIDKey).(int); ok {
		return id
	}
	return 0
}

// GetUserRole retrieves user role from request context
func GetUserRole(r *http.Request) string {
	if role, ok := r.Context().Value(UserRoleKey).(string); ok {
		return role
	}
	return ""
}

// GetRequestID retrieves request ID from context
func GetRequestID(r *http.Request) string {
	if id, ok := r.Context().Value(RequestIDKey).(string); ok {
		return id
	}
	return ""
}

// generateRequestID creates a new random request ID
func generateRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// RequestID middleware injects a unique request ID for distributed tracing
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if request already has an ID (from upstream proxy/load balancer)
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = generateRequestID()
		}
		
		// Add to response headers for client correlation
		w.Header().Set("X-Request-ID", id)
		
		ctx := context.WithValue(r.Context(), RequestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetClientIP extracts real client IP from request (for logging)
func getClientIP(r *http.Request) string {
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
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}

// Logger middleware with structured logging including User-Agent
func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)
		
		duration := time.Since(start)
		
		slog.Info("request",
			"request_id", GetRequestID(r),
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.statusCode,
			"duration_ms", duration.Milliseconds(),
			"ip", getClientIP(r),
			"user_agent", r.Header.Get("User-Agent"),
			"user_id", GetUserID(r),
		)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Auth middleware validates session and propagates user context
func Auth(db *sql.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token string
		cookie, err := r.Cookie("samnet_session")
		if err == nil {
			token = cookie.Value
		} else {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		tokenHash := auth.HashToken(token)

		var userID int
		var role string
		err = db.QueryRow(`
			SELECT s.user_id, u.role 
			FROM sessions s 
			JOIN users u ON s.user_id = u.id 
			WHERE s.token_hash = ? AND s.expires_at > CURRENT_TIMESTAMP`,
			tokenHash).Scan(&userID, &role)
		if err != nil {
			http.Error(w, "Unauthorized (Invalid/Expired)", http.StatusUnauthorized)
			return
		}



		ctx := context.WithValue(r.Context(), UserIDKey, userID)
		ctx = context.WithValue(ctx, UserRoleKey, role)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAdmin middleware ensures user has admin role
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := GetUserRole(r)
		if role != "admin" {
			http.Error(w, "Forbidden (Admin Required)", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SecurityHeaders adds security headers to all responses
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		next.ServeHTTP(w, r)
	})
}

// LocalhostOnly middleware restricts access to localhost (127.0.0.1) only
// This is used for the internal CLI API that bypasses authentication.
// It strictly checks RemoteAddr to prevent X-Forwarded-For spoofing.
func LocalhostOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.RemoteAddr
		// Strip port if present
		if i := strings.LastIndex(host, ":"); i != -1 {
			host = host[:i]
		}
		
		// Allow localhost access (IPv4 and IPv6)
		if host == "127.0.0.1" || host == "::1" || host == "localhost" {
			next.ServeHTTP(w, r)
			return
		}
		
		slog.Warn("Internal API access denied (Spoof Attempt?)", "remote_addr", r.RemoteAddr, "path", r.URL.Path)
		http.Error(w, "Forbidden - localhost only", http.StatusForbidden)
	})
}
