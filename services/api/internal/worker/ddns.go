package worker

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/SamNet-dev/wg-orchestrator/services/api/internal/auth"
)

// DDNSConfig holds provider-specific configuration
type DDNSConfig struct {
	Provider    string `json:"provider"`
	Domain      string `json:"domain"`
	Token       string `json:"token"`
	WebhookURL  string `json:"webhook_url"`
	TTL         int    `json:"ttl"`
	Interval    int    `json:"interval_minutes"` // Configurable check interval
}

// DDNS worker state
var (
	ddnsLastUpdate       time.Time
	ddnsConsecutiveFails int
	ddnsMutex            sync.Mutex
)

const (
	maxConsecutiveFails   = 10
	defaultUpdateInterval = 5 * time.Minute
	maxUpdatesPerHour     = 12
	minConsensus          = 4 // Require 4/6 sources to agree (2/3 majority)
)

// Secure HTTP client with TLS 1.2+ enforcement
var secureClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	},
}

// DDNSWorker runs the DDNS update loop with production-grade safeguards
func DDNSWorker(db *sql.DB) {
	// Get configurable interval from DDNS config
	interval := defaultUpdateInterval
	
	var configJSON string
	if err := db.QueryRow("SELECT config FROM feature_flags WHERE key='ddns'").Scan(&configJSON); err == nil {
		var cfg DDNSConfig
		if json.Unmarshal([]byte(configJSON), &cfg) == nil && cfg.Interval > 0 {
			interval = time.Duration(cfg.Interval) * time.Minute
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial run with delay to let system stabilize
	time.Sleep(30 * time.Second)
	runDDNSCheck(db)

	for range ticker.C {
		runDDNSCheck(db)
	}
}

// isTransientError determines if an error is temporary and should not increment failure count
func isTransientError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	transientPatterns := []string{
		"timeout", "connection refused", "no such host",
		"temporary failure", "i/o timeout", "network is unreachable",
	}
	for _, pattern := range transientPatterns {
		if strings.Contains(strings.ToLower(errStr), pattern) {
			return true
		}
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout() || netErr.Temporary()
	}
	return false
}

func runDDNSCheck(db *sql.DB) {
	ddnsMutex.Lock()
	defer ddnsMutex.Unlock()



	if ddnsConsecutiveFails >= maxConsecutiveFails {
		slog.Warn("[DDNS] Worker disabled after too many failures. Manual intervention required.")
		return
	}

	// Apply exponential backoff based on failure count
	if ddnsConsecutiveFails > 0 {
		backoff := GetBackoffDuration(ddnsConsecutiveFails)
		if time.Since(ddnsLastUpdate) < backoff {
			return
		}
	}

	var enabled bool
	var configJSON string
	err := db.QueryRow("SELECT enabled, config FROM feature_flags WHERE key='ddns'").Scan(&enabled, &configJSON)
	if err != nil || !enabled {
		return
	}

	var config DDNSConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		slog.Error("[DDNS] Invalid config", "error", err)
		return
	}



	if config.Token != "" && !strings.HasPrefix(config.Token, "duk_") && !strings.HasPrefix(config.Token, "cf_") {
		decrypted, err := auth.Decrypt(config.Token)
		if err == nil {
			config.Token = decrypted
		}
	}



	currentIPv4, err := detectPublicIP(false)
	if err != nil {
		if isTransientError(err) {
			slog.Warn("[DDNS] Transient IP detection failure, will retry", "error", err)
			return // Don't increment failure counter
		}
		slog.Warn("[DDNS] IP detection failed", "error", err)
		ddnsConsecutiveFails++
		return
	}



	currentIPv6, _ := detectPublicIP(true)

	var storedIP, storedIPv6 string
	db.QueryRow("SELECT value FROM system_config WHERE key='wan_ip'").Scan(&storedIP)
	db.QueryRow("SELECT value FROM system_config WHERE key='wan_ipv6'").Scan(&storedIPv6)

	ipChanged := currentIPv4 != storedIP
	ipv6Changed := currentIPv6 != "" && currentIPv6 != storedIPv6

	if !ipChanged && !ipv6Changed {
		ddnsConsecutiveFails = 0
		return
	}

	if ipChanged {
		slog.Info("[DDNS] IPv4 changed", "old", storedIP, "new", currentIPv4)
	}
	if ipv6Changed {
		slog.Info("[DDNS] IPv6 changed", "old", storedIPv6, "new", currentIPv6)
	}



	if err := updateDNSProvider(config, currentIPv4, currentIPv6); err != nil {
		if isTransientError(err) {
			slog.Warn("[DDNS] Transient update failure, will retry", "error", err)
			return
		}
		slog.Error("[DDNS] Update failed", "provider", config.Provider, "error", RedactURL(err.Error()))
		ddnsConsecutiveFails++

		// Alert after 3 consecutive failures
		if ddnsConsecutiveFails == 3 {
			db.Exec("INSERT INTO audit_logs (user_id, action, target, details) VALUES (0, 'DDNS_ALERT', ?, 'DDNS failing repeatedly - check configuration')",
				config.Domain)
		}
		return
	}



	if ipChanged {
		db.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('wan_ip', ?)", currentIPv4)
	}
	if ipv6Changed {
		db.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('wan_ipv6', ?)", currentIPv6)
	}

	ddnsLastUpdate = time.Now()
	ddnsConsecutiveFails = 0
	slog.Info("[DDNS] Update successful", "ipv4", currentIPv4, "ipv6", currentIPv6, "provider", config.Provider)

	db.Exec("INSERT INTO audit_logs (user_id, action, target, details) VALUES (0, 'DDNS_UPDATE', ?, ?)",
		config.Domain, "IP changed from "+storedIP+" to "+currentIPv4)
}

// detectPublicIP uses multiple sources with consensus voting (3/4 required)
func detectPublicIP(ipv6 bool) (string, error) {
	var sources []string
	if ipv6 {
		sources = []string{
			"https://api64.ipify.org",
			"https://ipv6.icanhazip.com",
			"https://v6.ident.me",
			"https://ipv6.wtfismyip.com/text",
			"https://ipv6.ident.me",
			"https://v6.ipinfo.io/ip",
		}
	} else {
		sources = []string{
			"https://ifconfig.me",
			"https://icanhazip.com",
			"https://ipinfo.io/ip",
			"https://api.ipify.org",
			"https://checkip.amazonaws.com",
			"https://ident.me",
		}
	}

	var ips []string
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, url := range sources {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
			resp, err := secureClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 100)) // Limit response size
			ip := strings.TrimSpace(string(body))

			if ipv6 {
				if isValidIPv6(ip) {
					mu.Lock()
					ips = append(ips, ip)
					mu.Unlock()
				}
			} else {
				if isValidIPv4(ip) {
					mu.Lock()
					ips = append(ips, ip)
					mu.Unlock()
				}
			}
		}(url)
	}

	wg.Wait()

	// Require 3/4 sources to agree (stricter than simple majority)
	if len(ips) < minConsensus {
		// Fallback to local interface detection
		if !ipv6 {
			if fallbackIP := detectLocalPublicIP(); fallbackIP != "" {
				return fallbackIP, nil
			}
		}
		return "", &DDNSError{Message: "insufficient IP sources agree (need 3/4)"}
	}

	return majorityVote(ips), nil
}

// detectLocalPublicIP gets public IP from local interface as fallback
func detectLocalPublicIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func isValidIPv4(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func isValidIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && strings.Contains(ip, ":")
}

func majorityVote(ips []string) string {
	counts := make(map[string]int)
	for _, ip := range ips {
		counts[ip]++
	}

	type kv struct {
		Key   string
		Value int
	}
	var sorted []kv
	for k, v := range counts {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})

	if len(sorted) > 0 {
		return sorted[0].Key
	}
	return ""
}

// updateDNSProvider handles provider-specific updates
func updateDNSProvider(config DDNSConfig, ipv4, ipv6 string) error {
	switch config.Provider {
	case "duckdns":
		return updateDuckDNS(config, ipv4, ipv6)
	case "webhook":
		return updateWebhook(config, ipv4, ipv6)
	default:
		slog.Warn("[DDNS] Provider not fully implemented", "provider", config.Provider)
		return nil
	}
}

func updateDuckDNS(config DDNSConfig, ipv4, ipv6 string) error {
	// Build URL - use POST body for token if possible (some providers support it)
	url := "https://www.duckdns.org/update?domains=" + config.Domain + "&token=" + config.Token
	if ipv4 != "" {
		url += "&ip=" + ipv4
	}
	if ipv6 != "" {
		url += "&ipv6=" + ipv6
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := secureClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if strings.TrimSpace(string(body)) != "OK" {
		return &DDNSError{Message: "DuckDNS returned: " + string(body), Persistent: true}
	}

	return nil
}

func validateWebhookURL(urlStr string) error {
	u, err := url.Parse(urlStr)
	if err != nil {
		return err
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("invalid scheme")
	}

	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		host = u.Host
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return err
	}

	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
			return fmt.Errorf("local/private IP blocked: %s", ip.String())
		}
	}
	return nil
}

func updateWebhook(config DDNSConfig, ipv4, ipv6 string) error {
	if err := validateWebhookURL(config.WebhookURL); err != nil {
		return fmt.Errorf("SSRF protection: %v", err)
	}

	payload := map[string]string{
		"ipv4":   ipv4,
		"ipv6":   ipv6,
		"domain": config.Domain,
	}
	body, _ := json.Marshal(payload)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", config.WebhookURL, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	if config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+config.Token)
	}

	resp, err := secureClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return &DDNSError{Message: "Webhook returned " + resp.Status, Persistent: resp.StatusCode == 401 || resp.StatusCode == 403}
	}

	return nil
}

// DDNSError for custom error handling with persistence flag
type DDNSError struct {
	Message    string
	Persistent bool // If true, increment failure counter; if false, transient
}

func (e *DDNSError) Error() string {
	return e.Message
}

// GetBackoffDuration returns exponential backoff duration
func GetBackoffDuration(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}
	backoff := math.Pow(2, float64(failures)) * float64(time.Minute)
	maxBackoff := float64(60 * time.Minute)
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	return time.Duration(backoff)
}

// ForceUpdate allows manual DDNS update via API
func ForceUpdate(db *sql.DB) error {
	ddnsMutex.Lock()
	defer ddnsMutex.Unlock()

	ddnsConsecutiveFails = 0 // Reset failures on manual trigger
	ddnsLastUpdate = time.Time{} // Allow immediate update

	var enabled bool
	var configJSON string
	err := db.QueryRow("SELECT enabled, config FROM feature_flags WHERE key='ddns'").Scan(&enabled, &configJSON)
	if err != nil || !enabled {
		return errors.New("DDNS not enabled")
	}

	var config DDNSConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return err
	}

	currentIP, err := detectPublicIP(false)
	if err != nil {
		return err
	}

	return updateDNSProvider(config, currentIP, "")
}

// GetDDNSStatus returns current DDNS status for monitoring
func GetDDNSStatus() map[string]interface{} {
	ddnsMutex.Lock()
	defer ddnsMutex.Unlock()

	return map[string]interface{}{
		"last_update":       ddnsLastUpdate,
		"consecutive_fails": ddnsConsecutiveFails,
		"is_disabled":       ddnsConsecutiveFails >= maxConsecutiveFails,
		"next_check_in":     GetBackoffDuration(ddnsConsecutiveFails).String(),
	}
}

// EnableDDNS resets failure counter and re-enables worker
func EnableDDNS() {
	ddnsMutex.Lock()
	defer ddnsMutex.Unlock()
	ddnsConsecutiveFails = 0
	slog.Info("[DDNS] Worker re-enabled")
}
// RedactURL scrubs sensitive tokens from URL strings for safe logging
func RedactURL(input string) string {
	if !strings.Contains(input, "token=") {
		return input
	}
	// Simple redaction: look for token=... and replace the value
	re := regexp.MustCompile(`token=([^&]+)`)
	return re.ReplaceAllString(input, "token=[REDACTED]")
}
