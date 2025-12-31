package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/SamNet-dev/wg-orchestrator/services/api/internal/auth"
	"github.com/SamNet-dev/wg-orchestrator/services/api/internal/config"
	"github.com/SamNet-dev/wg-orchestrator/services/api/internal/db"
	"github.com/SamNet-dev/wg-orchestrator/services/api/internal/handler"
	"github.com/SamNet-dev/wg-orchestrator/services/api/internal/middleware"
	"github.com/SamNet-dev/wg-orchestrator/services/api/internal/worker"
)

func main() {
	// Early logging to stderr for container troubleshooting
	fmt.Fprintf(os.Stderr, "[BOOT] API starting... (Time: %s)\n", time.Now().Format(time.RFC3339))
	
	createAdmin := flag.String("create-admin", "", "Create admin user with this username")
	adminPass := flag.String("password", "", "Password for the admin user")
	decryptFlag := flag.String("decrypt", "", "Decrypt a base64 string using the master key")
	encryptFlag := flag.String("encrypt", "", "Encrypt a plaintext string using the master key")
	flag.Parse()

	// CLI Mode: Crypt utility (for samnet.sh integration)
	if *decryptFlag != "" || *encryptFlag != "" {
		// Initialize config just to get paths (don't validate full stack)
		_ = config.Load()
		
		if *decryptFlag != "" {
			fmt.Fprintf(os.Stderr, "[BOOT] Running in decrypt mode\n")
			plaintext, err := auth.Decrypt(*decryptFlag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Decryption failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Print(plaintext)
		} else {
			fmt.Fprintf(os.Stderr, "[BOOT] Running in encrypt mode\n")
			ciphertext, err := auth.Encrypt(*encryptFlag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Encryption failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Print(ciphertext)
		}
		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "[BOOT] Loading configuration...\n")
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		slog.Error("Invalid config", "error", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "[BOOT] Connecting to database at %s...\n", cfg.DBPath)
	database, err := db.Connect(cfg.DBPath)
	if err != nil {
		slog.Error("Failed to connect to DB", "error", err)
		os.Exit(1)
	}
	defer database.Close()

	fmt.Fprintf(os.Stderr, "[BOOT] Running database migrations...\n")
	if err := db.RunMigrations(cfg.DBPath); err != nil {
		slog.Error("Failed to run migrations", "error", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "[BOOT] Validating database schema...\n")
	// Validate schema integrity before starting workers
	if err := db.ValidateSchema(database); err != nil {
		slog.Error("Database schema validation failed", "error", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "[BOOT] Initializing JSON logger and starting workers...\n")
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	// CLI Mode: Create admin user
	if *createAdmin != "" && *adminPass != "" {
		hash, err := auth.HashPassword(*adminPass)
		if err != nil {
			slog.Error("Failed to hash password", "error", err)
			os.Exit(1)
		}
		_, err = database.Exec("INSERT OR REPLACE INTO users (username, password_hash, role, failed_attempts) VALUES (?, ?, 'admin', 0)", *createAdmin, hash)
		if err != nil {
			slog.Error("Failed to create user", "error", err)
			os.Exit(1)
		}
		slog.Info("User created successfully", "username", *createAdmin)
		os.Exit(0)
	}

	// Start background workers with panic recovery
	var safeWorker func(name string, workerFunc func(*sql.DB))
	safeWorker = func(name string, workerFunc func(*sql.DB)) {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("Worker crashed - restarting", "worker", name, "panic", r, "stack", string(debug.Stack()))
					time.Sleep(10 * time.Second)
					safeWorker(name, workerFunc) // Restart with backoff
				}
			}()
			workerFunc(database)
		}()
	}

	safeWorker("limits", worker.LimitWorker)
	safeWorker("expiry", worker.ExpiryWorker)
	safeWorker("schedule", worker.ScheduleWorker) // If ScheduleWorker is exported
	safeWorker("ddns", worker.DDNSWorker)
	safeWorker("alerts", worker.AlertsWorker)
	safeWorker("monitor", worker.MonitorWorker)
	safeWorker("automation", worker.AutomationWorker)
	
	// Start System Stats Worker (1s ticker, no database needed)
	go worker.StatsWorker()

	// Run DB maintenance every hour
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			db.RunMaintenance(database)
		}
	}()

	mux := http.NewServeMux()

	// Public endpoints (no auth, no CSRF)
	mux.HandleFunc("/health/live", handler.HealthLive)
	mux.HandleFunc("/health/ready", handler.HealthReady(database))
	mux.HandleFunc("/metrics", handler.Metrics(database))
	
	// Sync health check (Hardening: Single Source of Truth verification)
	mux.HandleFunc("/health/sync", func(w http.ResponseWriter, r *http.Request) {
		clientDir := config.Get().ClientsDir
		files, _ := filepath.Glob(filepath.Join(clientDir, "*.conf"))
		
		dbPeers := make(map[string]bool)
		rows, err := database.Query("SELECT name FROM peers")
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var name string
				if rows.Scan(&name) == nil {
					dbPeers[name] = true
				}
			}
		}
		
		filePeers := make(map[string]bool)
		for _, f := range files {
			name := strings.TrimSuffix(filepath.Base(f), ".conf")
			filePeers[name] = true
		}
		
		missingFiles := []string{}
		for name := range dbPeers {
			if !filePeers[name] {
				missingFiles = append(missingFiles, name)
			}
		}
		
		missingDB := []string{}
		for name := range filePeers {
			if !dbPeers[name] {
				missingDB = append(missingDB, name)
			}
		}
		
		status := "OK"
		if len(missingFiles) > 0 || len(missingDB) > 0 {
			status = "DESYNC"
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":            status,
			"database_peers":    len(dbPeers),
			"filesystem_peers":  len(filePeers),
			"missing_files":     missingFiles,
			"missing_database":  missingDB,
			"timestamp":         time.Now().Unix(),
		})
	})

	// Public login endpoint (rate limited but no auth/CSRF)
	publicAPI := http.NewServeMux()
	publicAPI.HandleFunc("POST /login", handler.Login(database))
	mux.Handle("/api/v1/login", http.StripPrefix("/api/v1", middleware.LoginRateLimitMiddleware(publicAPI)))

	// Internal API - localhost only, no auth (for CLI cross-engine mode)
	// This is safe because it only accepts connections from 127.0.0.1
	internalAPI := http.NewServeMux()
	internalAPI.HandleFunc("DELETE /peers/{id}", handler.DeletePeer(database))
	internalAPI.HandleFunc("PUT /peers/{id}", handler.UpdatePeer(database))
	internalAPI.HandleFunc("GET /peers/config", handler.DownloadPeerConfig(database))
	mux.Handle("/internal/", http.StripPrefix("/internal", middleware.LocalhostOnly(internalAPI)))

	// Protected endpoints (auth + CSRF)
	protectedAPI := http.NewServeMux()
	protectedAPI.HandleFunc("POST /logout", handler.Logout(database))
	protectedAPI.HandleFunc("GET /peers", handler.ListPeers(database))
	protectedAPI.HandleFunc("POST /peers", handler.CreatePeer(database))
	protectedAPI.HandleFunc("GET /peers/config", handler.DownloadPeerConfig(database))
	protectedAPI.HandleFunc("GET /peers/qr", handler.GetPeerQR(database))
	protectedAPI.HandleFunc("DELETE /peers/{id}", handler.DeletePeer(database))
	protectedAPI.HandleFunc("PUT /peers/{id}", handler.UpdatePeer(database))
	protectedAPI.HandleFunc("GET /peers/export", handler.ExportAllPeers(database))

	// Backup endpoint
	protectedAPI.HandleFunc("GET /backup", handler.CreateBackup(database))

	// Subnet configuration
	protectedAPI.HandleFunc("GET /network/subnet", func(w http.ResponseWriter, r *http.Request) {
		var subnet, preset string
		database.QueryRow("SELECT value FROM system_config WHERE key='subnet_cidr'").Scan(&subnet)
		database.QueryRow("SELECT value FROM system_config WHERE key='subnet_preset'").Scan(&preset)
		if subnet == "" {
			subnet = "10.100.0.0/24"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"subnet": subnet,
			"preset": preset,
		})
	})
	protectedAPI.HandleFunc("POST /network/subnet", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Subnet string `json:"subnet"`
			Preset string `json:"preset"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		// Validate subnet format
		if !strings.Contains(req.Subnet, "/") {
			http.Error(w, "Invalid subnet format (must be CIDR)", http.StatusBadRequest)
			return
		}
		database.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('subnet_cidr', ?)", req.Subnet)
		database.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('subnet_preset', ?)", req.Preset)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "configured"}`))
	})

	// DDNS management
	protectedAPI.HandleFunc("GET /ddns/config", func(w http.ResponseWriter, r *http.Request) {
		var config struct {
			Enabled  bool   `json:"enabled"`
			Provider string `json:"provider"`
			Domain   string `json:"domain"`
		}
		var enabledStr, configJSON string
		database.QueryRow("SELECT value FROM system_config WHERE key='ddns_enabled'").Scan(&enabledStr)
		database.QueryRow("SELECT value FROM system_config WHERE key='ddns_config'").Scan(&configJSON)
		config.Enabled = enabledStr == "true" || enabledStr == "1"
		if configJSON != "" {
			json.Unmarshal([]byte(configJSON), &config)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
	})
	protectedAPI.HandleFunc("POST /ddns/config", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Enabled  bool   `json:"enabled"`
			Provider string `json:"provider"`
			Domain   string `json:"domain"`
			Token    string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		enabledStr := "false"
		if req.Enabled {
			enabledStr = "true"
		}
		database.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('ddns_enabled', ?)", enabledStr)
		configJSON, _ := json.Marshal(map[string]string{
			"provider": req.Provider,
			"domain":   req.Domain,
			"token":    req.Token,
		})
		database.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('ddns_config', ?)", string(configJSON))
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "saved"}`))
	})
	protectedAPI.HandleFunc("POST /ddns/force-update", func(w http.ResponseWriter, r *http.Request) {
		if err := worker.ForceUpdate(database); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "update triggered"}`))
	})
	protectedAPI.HandleFunc("GET /ddns/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		status := worker.GetDDNSStatus()
		json.NewEncoder(w).Encode(status)
	})

	// Subnet management
	protectedAPI.HandleFunc("GET /subnets/presets", handler.GetSubnetPresets(database))
	protectedAPI.HandleFunc("GET /subnets/current", handler.GetCurrentSubnet(database))
	protectedAPI.HandleFunc("POST /subnets/configure", handler.ConfigureSubnet(database))
	protectedAPI.HandleFunc("GET /network/stats", handler.SubnetStats(database))

	// Database scaling monitor
	protectedAPI.HandleFunc("GET /db/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"backend": "sqlite",
			"status":  "operational",
		})
	})

	// Audit logs endpoint
	protectedAPI.HandleFunc("GET /audit-logs", func(w http.ResponseWriter, r *http.Request) {
		rows, err := database.Query(`
			SELECT a.created_at, COALESCE(u.username, 'system') as username, a.action, a.target, a.ip_address 
			FROM audit_logs a 
			LEFT JOIN users u ON a.user_id = u.id 
			ORDER BY a.created_at DESC LIMIT 20
		`)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]interface{}{})
			return
		}
		defer rows.Close()

		var logs []map[string]interface{}
		for rows.Next() {
			var createdAt, username, action string
			var target, ip sql.NullString
			rows.Scan(&createdAt, &username, &action, &target, &ip)
			logs = append(logs, map[string]interface{}{
				"created_at": createdAt,
				"username":   username,
				"action":     action,
				"target":     target.String,
				"ip_address": ip.String,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logs)
	})

	// Network settings
	protectedAPI.HandleFunc("GET /network/settings", handler.GetNetworkSettings(database))
	protectedAPI.HandleFunc("POST /network/settings", handler.UpdateNetworkSettings(database))
	protectedAPI.HandleFunc("GET /network/global", handler.GetGlobalSettings(database))
	protectedAPI.HandleFunc("POST /network/global", handler.UpdateGlobalSettings(database))

	// User stats
	protectedAPI.HandleFunc("GET /users/stats", func(w http.ResponseWriter, r *http.Request) {
		var adminCount, userCount int
		database.QueryRow("SELECT COUNT(*) FROM users WHERE role='admin'").Scan(&adminCount)
		database.QueryRow("SELECT COUNT(*) FROM users WHERE role!='admin'").Scan(&userCount)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{
			"admin_count": adminCount,
			"user_count":  userCount,
		})
	})

	// System stats endpoint for Web UI dashboard
	protectedAPI.HandleFunc("GET /system/stats", func(w http.ResponseWriter, r *http.Request) {
		stats := worker.GetSystemStats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	})

	// Password change endpoint
	protectedAPI.HandleFunc("POST /users/password", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CurrentPassword string `json:"current_password"`
			NewPassword     string `json:"new_password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if len(req.NewPassword) < 8 {
			http.Error(w, "Password must be at least 8 characters", http.StatusBadRequest)
			return
		}

		// Get user ID from session
		userID := middleware.GetUserID(r)
		if userID == 0 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Verify current password
		var storedHash string
		err := database.QueryRow("SELECT password_hash FROM users WHERE id = ?", userID).Scan(&storedHash)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		valid, err := auth.CheckPassword(storedHash, req.CurrentPassword)
		if err != nil || !valid {
			http.Error(w, "Current password is incorrect", http.StatusForbidden)
			return
		}

		// Hash and update new password
		newHash, err := auth.HashPassword(req.NewPassword)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}
		_, err = database.Exec("UPDATE users SET password_hash = ? WHERE id = ?", newHash, userID)
		if err != nil {
			http.Error(w, "Failed to update password", http.StatusInternalServerError)
			return
		}

	w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "password_updated"}`))
	})

	// Observability Alerts endpoint - returns actionable system warnings
	protectedAPI.HandleFunc("GET /system/alerts", func(w http.ResponseWriter, r *http.Request) {
		alerts := []map[string]interface{}{}
		
		// 1. Stale handshake check (>5 minutes without handshake = potential issue)
		rows, err := database.Query("SELECT name, public_key FROM peers WHERE disabled = 0 OR disabled IS NULL")
		if err == nil {
			defer rows.Close()
			wgStats := handler.GetWireGuardStats()
			for rows.Next() {
				var name, pubKey string
				if rows.Scan(&name, &pubKey) == nil {
					if stats, ok := wgStats[pubKey]; ok {
						if stats.LastHandshake == "never" || stats.LastHandshake == "" {
							alerts = append(alerts, map[string]interface{}{
								"type":    "stale_handshake",
								"level":   "warning",
								"peer":    name,
								"message": "Peer has never established connection",
							})
						}
					}
				}
			}
		}
		
		// 2. Subnet capacity check (warn at 80%)
		var subnetCIDR string
		database.QueryRow("SELECT value FROM system_config WHERE key='subnet_cidr'").Scan(&subnetCIDR)
		if subnetCIDR == "" {
			subnetCIDR = "10.100.0.0/24"
		}
		var peerCount, maxPeers int
		database.QueryRow("SELECT COUNT(*) FROM peers").Scan(&peerCount)
		maxPeers = handler.CalculateMaxPeers(subnetCIDR)
		usagePercent := float64(peerCount) / float64(maxPeers) * 100
		if usagePercent >= 80 {
			level := "warning"
			if usagePercent >= 95 {
				level = "critical"
			}
			alerts = append(alerts, map[string]interface{}{
				"type":    "subnet_capacity",
				"level":   level,
				"message": fmt.Sprintf("Subnet at %.0f%% capacity (%d/%d peers)", usagePercent, peerCount, maxPeers),
			})
		}
		
		// 3. Disabled peers count (informational)
		var disabledCount int
		database.QueryRow("SELECT COUNT(*) FROM peers WHERE disabled = 1").Scan(&disabledCount)
		if disabledCount > 0 {
			alerts = append(alerts, map[string]interface{}{
				"type":    "disabled_peers",
				"level":   "info",
				"message": fmt.Sprintf("%d peer(s) are currently disabled", disabledCount),
			})
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"alerts":      alerts,
			"alert_count": len(alerts),
			"timestamp":   time.Now().Unix(),
		})
	})

	// Apply middleware in correct order: Auth -> CSRF -> RateLimit
	authProtected := middleware.Auth(database, protectedAPI)
	csrfProtected := middleware.CSRF(authProtected)
	rateLimited := middleware.RateLimitMiddleware(csrfProtected) // Rate limit ALL protected routes

	mux.Handle("/api/v1/", http.StripPrefix("/api/v1", rateLimited))

	// Apply security headers and request ID to all routes
	secureHandler := middleware.SecurityHeaders(middleware.RequestID(middleware.Logger(mux)))

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      secureHandler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		slog.Info("Starting API", "port", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server failure", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	slog.Info("Shutting down server...")

	// Stop rate limiter cleanup goroutine
	middleware.StopGlobalLimiter()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("Server stopped gracefully")
}

// getSystemStats removed (logic moved to internal/worker/stats.go)
