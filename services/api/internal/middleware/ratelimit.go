package middleware

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	csrfCookieName = "csrf_token"
	csrfHeaderName = "X-CSRF-Token"
	csrfTokenLen   = 32
)

// CSRFToken generates a new CSRF token
func generateCSRFToken() (string, error) {
	b := make([]byte, csrfTokenLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// CSRF middleware implements double-submit cookie pattern
func CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// GET/HEAD/OPTIONS are safe methods - just ensure token exists
		if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
			ensureCSRFCookie(w, r)
			next.ServeHTTP(w, r)
			return
		}

		// For state-changing methods (POST/PUT/DELETE), validate token
		cookie, err := r.Cookie(csrfCookieName)
		if err != nil {
			http.Error(w, "CSRF token missing", http.StatusForbidden)
			return
		}

		headerToken := r.Header.Get(csrfHeaderName)
		if headerToken == "" {
			// Also check form field for traditional form submissions
			headerToken = r.FormValue("csrf_token")
		}

		if headerToken == "" {
			http.Error(w, "CSRF token not provided", http.StatusForbidden)
			return
		}

		// Constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(headerToken)) != 1 {
			http.Error(w, "CSRF token invalid", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func ensureCSRFCookie(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie(csrfCookieName); err != nil {
		token, _ := generateCSRFToken()
		http.SetCookie(w, &http.Cookie{
			Name:     csrfCookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: false, // Must be readable by JS
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   86400, // 24 hours
		})
	}
}

// Rate limiter with bounded memory and LRU eviction
type boundedVisitor struct {
	lastSeen time.Time
	count    int
}

type BoundedRateLimiter struct {
	visitors map[string]*boundedVisitor
	order    []string // LRU order tracking
	mu       sync.Mutex
	maxSize  int
	limit    int
	window   time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
}

var globalLimiter = NewBoundedRateLimiter(100000, 300, time.Minute) // 100k IPs max, 300 req/min
var loginLimiter = NewBoundedRateLimiter(10000, 5, time.Minute)    // 10k IPs max, 5 login attempts/min

func NewBoundedRateLimiter(maxSize, limit int, window time.Duration) *BoundedRateLimiter {
	ctx, cancel := context.WithCancel(context.Background())
	rl := &BoundedRateLimiter{
		visitors: make(map[string]*boundedVisitor),
		order:    make([]string, 0, maxSize),
		maxSize:  maxSize,
		limit:    limit,
		window:   window,
		ctx:      ctx,
		cancel:   cancel,
	}
	go rl.cleanup()
	return rl
}

func (rl *BoundedRateLimiter) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			newOrder := make([]string, 0, len(rl.order))
			for _, ip := range rl.order {
				if v, ok := rl.visitors[ip]; ok {
					if now.Sub(v.lastSeen) > 10*time.Minute {
						delete(rl.visitors, ip)
					} else {
						newOrder = append(newOrder, ip)
					}
				}
			}
			rl.order = newOrder
			rl.mu.Unlock()
		case <-rl.ctx.Done():
			return
		}
	}
}

// Stop gracefully stops the rate limiter cleanup goroutine
func (rl *BoundedRateLimiter) Stop() {
	rl.cancel()
}

func (rl *BoundedRateLimiter) evictOldest() {
	if len(rl.order) > 0 {
		oldest := rl.order[0]
		rl.order = rl.order[1:]
		delete(rl.visitors, oldest)
	}
}

// Trusted proxy CIDRs - only trust X-Forwarded-For from these
var trustedProxies = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"127.0.0.0/8",
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range trustedProxies {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

// GetClientIP extracts real client IP, only trusting X-Forwarded-For from known proxies
// Exported for use by handlers and other packages
func GetClientIP(r *http.Request) string {
	remoteIP := r.RemoteAddr
	for i := len(remoteIP) - 1; i >= 0; i-- {
		if remoteIP[i] == ':' {
			remoteIP = remoteIP[:i]
			break
		}
	}

	// Only trust X-Forwarded-For if request is from known proxy
	if !isPrivateIP(remoteIP) {
		return remoteIP // Request from internet - don't trust headers
	}

	// Request from trusted proxy - parse X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Split and get rightmost non-private IP (client before our proxies)
		ips := strings.Split(xff, ",")
		for i := len(ips) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(ips[i])
			if !isPrivateIP(ip) {
				return ip
			}
		}
	}

	// Check X-Real-IP as fallback
	if xri := r.Header.Get("X-Real-IP"); xri != "" && !isPrivateIP(xri) {
		return xri
	}

	return remoteIP
}

// StopGlobalLimiter stops the global rate limiter cleanup goroutine
func StopGlobalLimiter() {
	globalLimiter.Stop()
}

// RateLimitMiddleware applies rate limiting to http.Handler
func RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := GetClientIP(r)

		globalLimiter.mu.Lock()

		v, exists := globalLimiter.visitors[ip]
		if !exists {
			if len(globalLimiter.visitors) >= globalLimiter.maxSize {
				globalLimiter.evictOldest()
			}
			globalLimiter.visitors[ip] = &boundedVisitor{time.Now(), 1}
			globalLimiter.order = append(globalLimiter.order, ip)
			globalLimiter.mu.Unlock()
			next.ServeHTTP(w, r)
			return
		}

		if time.Since(v.lastSeen) > globalLimiter.window {
			v.lastSeen = time.Now()
			v.count = 1
		} else {
			if v.count >= globalLimiter.limit {
				globalLimiter.mu.Unlock()
				w.Header().Set("Retry-After", "60")
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			v.count++
		}
		globalLimiter.mu.Unlock()

		next.ServeHTTP(w, r)
	})
}

// LoginRateLimitMiddleware applies tighter rate limiting to login attempts
func LoginRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := GetClientIP(r)

		loginLimiter.mu.Lock()
		v, exists := loginLimiter.visitors[ip]
		if !exists {
			if len(loginLimiter.visitors) >= loginLimiter.maxSize {
				loginLimiter.evictOldest()
			}
			loginLimiter.visitors[ip] = &boundedVisitor{time.Now(), 1}
			loginLimiter.order = append(loginLimiter.order, ip)
			loginLimiter.mu.Unlock()
			next.ServeHTTP(w, r)
			return
		}

		if time.Since(v.lastSeen) > loginLimiter.window {
			v.lastSeen = time.Now()
			v.count = 1
		} else {
			if v.count >= loginLimiter.limit {
				loginLimiter.mu.Unlock()
				w.Header().Set("Retry-After", "300") // Longer lockout for login attempts
				http.Error(w, "Too many login attempts from this network. Try again in 5 minutes.", http.StatusTooManyRequests)
				return
			}
			v.count++
		}
		loginLimiter.mu.Unlock()

		next.ServeHTTP(w, r)
	})
}

// RateLimit middleware for http.HandlerFunc (backwards compat)
func RateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := GetClientIP(r)

		globalLimiter.mu.Lock()

		v, exists := globalLimiter.visitors[ip]
		if !exists {
			if len(globalLimiter.visitors) >= globalLimiter.maxSize {
				globalLimiter.evictOldest()
			}
			globalLimiter.visitors[ip] = &boundedVisitor{time.Now(), 1}
			globalLimiter.order = append(globalLimiter.order, ip)
			globalLimiter.mu.Unlock()
			next(w, r)
			return
		}

		if time.Since(v.lastSeen) > globalLimiter.window {
			v.lastSeen = time.Now()
			v.count = 1
		} else {
			if v.count >= globalLimiter.limit {
				globalLimiter.mu.Unlock()
				w.Header().Set("Retry-After", "60")
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			v.count++
		}
			globalLimiter.mu.Unlock()

		next(w, r)
	}
}
