package handler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"

	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SamNet-dev/wg-orchestrator/services/api/internal/auth"
	"github.com/SamNet-dev/wg-orchestrator/services/api/internal/config"
	"github.com/SamNet-dev/wg-orchestrator/services/api/internal/middleware"
	"github.com/SamNet-dev/wg-orchestrator/services/api/internal/reconcile"
	"syscall"
	"io"
	"archive/zip"
)

// IP allocation mutex to prevent race conditions
var ipAllocMu sync.Mutex

// Peer lifecycle mutex to prevent concurrent update/delete races
var peerOpMu sync.Mutex

var (
	lastSyncTime time.Time
	syncMu       sync.Mutex
)

// Cached server public key to avoid shell exec per request
var (
	serverPubKeyCache string
	serverPubKeyOnce  sync.Once
)

const (
	DefaultPageSize = 100
	MaxPageSize     = 500
)

// isValidIPv4 checks if a string is a valid IPv4 address
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
		num := 0
		fmt.Sscanf(p, "%d", &num)
		if num < 0 || num > 255 {
			return false
		}
	}
	return true
}



// isValidHostname checks if a string is a valid hostname for DDNS
func isValidHostname(h string) bool {
	if h == "" {
		return false
	}
	// Basic regex for hostname: alphanumeric, dots, hyphens
	match, _ := regexp.MatchString(`^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]))*$`, h)
	return match
}

// getValidWanIP gets the WAN IP or Hostname from DB with validation and fallback
func getValidWanIP(db *sql.DB) string {
	var wanIP string
	db.QueryRow("SELECT value FROM system_config WHERE key='wan_ip'").Scan(&wanIP)
	
	// Priority 1: Valid IPv4
	if isValidIPv4(wanIP) {
		return wanIP
	}

	// Priority 2: Valid Hostname (for DDNS users)
	if isValidHostname(wanIP) {
		return wanIP
	}
	
	// Fallback: try to detect public IPv4
	slog.Warn("wan_ip missing or invalid, attempting to detect public IP", "stored_value", wanIP)
	
	// Quick detection using curl -4 (forces IPv4)
	out, err := exec.Command("curl", "-4", "-sf", "--max-time", "5", "https://ifconfig.me").Output()
	if err == nil {
		detected := strings.TrimSpace(string(out))
		if isValidIPv4(detected) {
			// Store it for future use
			db.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('wan_ip', ?)", detected)
			slog.Info("Detected and stored public IPv4", "ip", detected)
			return detected
		}
	}
	
	// Last resort: return placeholder
	slog.Error("Could not determine valid public IPv4 or hostname for endpoint")
	return "YOUR_SERVER_IP"
}

type NewPeerRequest struct {
	Name      string `json:"name"`
	IP        string `json:"ip,omitempty"`
	ExpiresIn int    `json:"expires_in,omitempty"` // Days until expiry, 0 = permanent
}

type Peer struct {
	ID           int     `json:"id"`
	Name         string  `json:"name"`
	PublicKey    string  `json:"public_key"`
	PrivateKey   string  `json:"private_key,omitempty"`
	AllowedIPs   string  `json:"allowed_ips"`
	Disabled     bool    `json:"disabled"`
	ExpiresAt    *int64  `json:"expires_at,omitempty"` // Unix timestamp, nil = permanent
	Rx           string  `json:"rx,omitempty"`         // Transfer received (formatted)
	Tx           string  `json:"tx,omitempty"`         // Transfer sent (formatted)
	RxBytes      int64   `json:"rx_bytes"`             // Raw bytes
	TxBytes      int64   `json:"tx_bytes"`             // Raw bytes
	DataLimitGB  int     `json:"data_limit_gb"`        // Data limit in GB
	LastHandshake string `json:"last_handshake,omitempty"`
}

type PeerListResponse struct {
	Peers      []Peer `json:"peers"`
	Total      int    `json:"total"`
	Page       int    `json:"page"`
	PageSize   int    `json:"page_size"`
	TotalPages int    `json:"total_pages"`
}

// WireGuardStats holds per-peer transfer statistics
type WireGuardStats struct {
	Rx            string
	Tx            string
	RxBytes       int64  // Raw byte value for calculations
	TxBytes       int64  // Raw byte value for calculations
	LastHandshake string
}

// GetWireGuardStats runs 'wg show wg0 dump' and parses per-peer stats
// Format: public_key preshared_key endpoint allowed_ips latest_handshake rx tx persistent_keepalive
func GetWireGuardStats() map[string]WireGuardStats {
	stats := make(map[string]WireGuardStats)

	out, err := exec.Command("wg", "show", "wg0", "dump").Output()
	if err != nil {
		return stats
	}

	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if i == 0 || line == "" { // Skip header line
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) >= 7 {
			pubKey := fields[0]
			rxBytes, _ := strconv.ParseInt(fields[5], 10, 64)
			txBytes, _ := strconv.ParseInt(fields[6], 10, 64)
			handshakeTs, _ := strconv.ParseInt(fields[4], 10, 64)

			var lastHandshake string
			if handshakeTs > 0 {
				// Format as relative time
				hs := time.Unix(handshakeTs, 0)
				since := time.Since(hs)
				if since.Hours() > 24 {
					lastHandshake = fmt.Sprintf("%.0fd ago", since.Hours()/24)
				} else if since.Hours() > 1 {
					lastHandshake = fmt.Sprintf("%.0fh ago", since.Hours())
				} else if since.Minutes() > 1 {
					lastHandshake = fmt.Sprintf("%.0fm ago", since.Minutes())
				} else {
					lastHandshake = fmt.Sprintf("%.0fs ago", since.Seconds())
				}
			}

			stats[pubKey] = WireGuardStats{
				Rx:            formatBytes(rxBytes),
				Tx:            formatBytes(txBytes),
				RxBytes:       rxBytes,
				TxBytes:       txBytes,
				LastHandshake: lastHandshake,
			}
		}
	}
	return stats
}

// formatBytes converts bytes to human-readable format
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func GetServerPublicKey() string {
	serverPubKeyOnce.Do(func() {
		out, _ := os.ReadFile("/etc/wireguard/publickey")
		serverPubKeyCache = strings.TrimSpace(string(out))
		if serverPubKeyCache == "" {
			// Fallback to cat if direct read fails (e.g. permission issues that sudo might handle better via shell)
			out, _ := exec.Command("cat", "/etc/wireguard/publickey").Output()
			serverPubKeyCache = strings.TrimSpace(string(out))
		}
	})
	return serverPubKeyCache
}

func DownloadPeerConfig(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "Missing ID", http.StatusBadRequest)
			return
		}

		var p Peer
		var dnsProfile sql.NullString
		var encPrivKey string

		err := db.QueryRow(`
			SELECT p.name, p.encrypted_private_key, p.allowed_ips, ps.dns_profile 
			FROM peers p 
			LEFT JOIN peer_settings ps ON p.id = ps.peer_id 
			WHERE p.id = ?`, id).Scan(&p.Name, &encPrivKey, &p.AllowedIPs, &dnsProfile)
		if err != nil {
			http.Error(w, "Peer not found", http.StatusNotFound)
			return
		}

		// Only attempt decryption if there's actually something to decrypt
		if encPrivKey != "" && encPrivKey != "CLI_MANAGED" {
			p.PrivateKey, err = auth.Decrypt(encPrivKey)
			if err != nil && len(encPrivKey) == 44 {
				slog.Info("Decryption failed but key looks like plaintext WireGuard key, using as-is", "peer", p.Name)
				p.PrivateKey = encPrivKey
				err = nil
			}
		}
		
		// Fallback to file system if decryption failed or key was empty/CLI_MANAGED
		if p.PrivateKey == "" {
			clientConfPath := filepath.Join("/opt/samnet/clients", p.Name+".conf")
			content, fileErr := os.ReadFile(clientConfPath)
			if fileErr == nil {
				re := regexp.MustCompile(`(?i)PrivateKey\s*=\s*([a-zA-Z0-9+/=]+)`)
				match := re.FindStringSubmatch(string(content))
				if len(match) > 1 {
					p.PrivateKey = match[1]
					// Self-heal: Encrypt and update DB asynchronously
					go func(n, k string) {
						if enc, err := auth.Encrypt(k); err == nil {
							db.Exec("UPDATE peers SET encrypted_private_key = ? WHERE name = ?", enc, n)
						}
					}(p.Name, p.PrivateKey)
				}
			}
			
			// If still empty, we truly failed
			if p.PrivateKey == "" {
				slog.Error("Failed to decrypt key and file fallback failed", "peer", p.Name, "err", err)
				http.Error(w, "Failed to decrypt key", http.StatusInternalServerError)
				return
			}
		}

// Update DNS to include 8.8.8.8
		dns := "1.1.1.1, 8.8.8.8"
		if dnsProfile.Valid {
			switch dnsProfile.String {
			case "adblock":
				dns = "94.140.14.14"
			case "family":
				dns = "1.1.1.3"
			}
		}

		var endpoint string
		var customHost string
		db.QueryRow("SELECT value FROM system_config WHERE key='endpoint_hostname'").Scan(&customHost)
		if customHost != "" {
			endpoint = customHost
		} else {
			endpoint = getValidWanIP(db)
		}
		port := "51820"
		db.QueryRow("SELECT value FROM system_config WHERE key='listen_port'").Scan(&port)
		endpoint = fmt.Sprintf("%s:%s", endpoint, port)

		serverPub := GetServerPublicKey()

		// Get system config for routing
		var subnetCIDR string
		var splitTunnel string
		db.QueryRow("SELECT value FROM system_config WHERE key='subnet_cidr'").Scan(&subnetCIDR)
		if subnetCIDR == "" {
			subnetCIDR = "10.100.0.0/24"
		}
		db.QueryRow("SELECT value FROM system_config WHERE key='split_tunnel'").Scan(&splitTunnel)

		// Fix: Use subnet mask for Address (e.g., /24) instead of /32 from DB
		// This ensures clients know the subnet size
		_, ipNet, _ := net.ParseCIDR(subnetCIDR)
		ones, _ := ipNet.Mask.Size()
		clientAddr := strings.Split(p.AllowedIPs, "/")[0] + fmt.Sprintf("/%d", ones)

		cfg := "[Interface]\n"
		cfg += "PrivateKey = " + p.PrivateKey + "\n"
		cfg += "Address = " + clientAddr + "\n"

		// Use 1380 for better compatibility with PPPoE, tunnels, etc.
		mtu := "1380"
		db.QueryRow("SELECT value FROM system_config WHERE key='mtu'").Scan(&mtu)
		cfg += "MTU = " + mtu + "\n"
		
		cfg += "DNS = " + dns + "\n\n"
		cfg += "[Peer]\n"
		cfg += "PublicKey = " + serverPub + "\n"
		
		// Configure Split Tunnel vs Full Tunnel
		if splitTunnel == "true" {
			// Split tunnel: Only route VPN subnet and private ranges
			cfg += fmt.Sprintf("AllowedIPs = %s, 192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8\n", subnetCIDR)
		} else {
			// Full tunnel: Route everything
			cfg += "AllowedIPs = 0.0.0.0/0, ::/0\n"
		}
		
		cfg += "Endpoint = " + endpoint + "\n"
		cfg += "PersistentKeepalive = 25\n"

		// Clear private key from memory ASAP
		p.PrivateKey = ""

		w.Header().Set("Content-Disposition", "attachment; filename="+p.Name+".conf")
		w.Write([]byte(cfg))
	}
}

// syncSubnetWithFiles reads the authoritative subnet from wg0.conf and updates the DB
func syncSubnetWithFiles(db *sql.DB) {
	cfg := config.Get()
	wg0Path := cfg.WGConfigPath
	
	content, err := os.ReadFile(wg0Path)
	if err != nil {
		// Try via cat if permission issue (even as root, some filesystems/apparmor can be weird)
		out, err := exec.Command("cat", wg0Path).Output()
		if err == nil {
			content = out
		} else {
			return
		}
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Address") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				// Handle potential multiple addresses (e.g. IPv4, IPv6)
				addrParts := strings.Split(parts[1], ",")
				for _, addrPart := range addrParts {
					addr := strings.TrimSpace(addrPart)
					if strings.Contains(addr, ".") { // Focus on IPv4 for now
						_, ipNet, err := net.ParseCIDR(addr)
						if err == nil {
							subnet := ipNet.String()
							slog.Info("Authoritative subnet discovered", "subnet", subnet)
							db.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('subnet_cidr', ?)", subnet)
							
							// Also try to sync the mask to subnet_preset if it matches a preset size
							maskParts := strings.Split(subnet, "/")
							if len(maskParts) == 2 {
								mask := maskParts[1]
								var preset string
								switch mask {
								case "24": preset = "large"
								case "18": preset = "massive"
								case "22": preset = "enterprise"
								case "30": preset = "tiny"
								}
								if preset != "" {
									db.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('subnet_preset', ?)", preset)
								}
							}
						}
					}
				}
			}
		}
	}

	// 2. Discover peers directly from wg0.conf and ensure they have .conf files or DB entries
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "[Peer]" {
			var pub, allowedIPs string
			var name string
			// Look ahead for public key and name comment
			for j := 1; j < 5 && i+j < len(lines); j++ {
				ln := strings.TrimSpace(lines[i+j])
				if strings.HasPrefix(ln, "PublicKey") {
					parts := strings.SplitN(ln, "=", 2)
					if len(parts) == 2 {
						pub = strings.TrimSpace(parts[1])
					}
				} else if strings.HasPrefix(ln, "AllowedIPs") {
					parts := strings.SplitN(ln, "=", 2)
					if len(parts) == 2 {
						allowedIPs = strings.TrimSpace(parts[1])
					}
				} else if strings.HasPrefix(ln, "#") {
					name = strings.TrimSpace(strings.TrimPrefix(ln, "#"))
				}
			}

			if pub != "" && allowedIPs != "" {
				if name == "" {
					name = "discovered-" + pub[:8]
				}
				// Ensure this peer is in DB if not there
				var exists int
				db.QueryRow("SELECT 1 FROM peers WHERE public_key = ?", pub).Scan(&exists)
				if exists == 0 {
					slog.Info("Discovering peer from wg0.conf", "name", name, "pub", pub)
					db.Exec("INSERT OR IGNORE INTO peers (name, public_key, encrypted_private_key, allowed_ips) VALUES (?, ?, 'CLI_MANAGED', ?)",
						name, pub, allowedIPs)
				}
			}
		}
	}
}

// syncPeersWithFiles scans the CLI client directory and synchronizes it with the database
func syncPeersWithFiles(db *sql.DB) {
	syncSubnetWithFiles(db)
	clientDir := "/opt/samnet/clients"
	// Ensure directory exists or we might fail
	os.MkdirAll(clientDir, 0700)
	files, err := filepath.Glob(filepath.Join(clientDir, "*.conf"))
	if err != nil {
		return
	}

	ipAllocMu.Lock()
	defer ipAllocMu.Unlock()

	// 1. Map existing peers by public key for quick lookup
	dbPeers := make(map[string]bool)
	rows, err := db.Query("SELECT public_key FROM peers")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var pk string
			if err := rows.Scan(&pk); err == nil {
				dbPeers[pk] = true
			}
		}
	}

	foundPubKeys := make(map[string]bool)

	// 2. Discover peers from files
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			// Try cat 
			out, err := exec.Command("cat", file).Output()
			if err == nil {
				content = out
			} else {
				continue
			}
		}

		name := strings.TrimSuffix(filepath.Base(file), ".conf")
		lines := strings.Split(string(content), "\n")
		var priv, allowed string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "PrivateKey") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					priv = strings.TrimSpace(parts[1])
				}
			} else if strings.HasPrefix(line, "Address") || strings.HasPrefix(line, "AllowedIPs") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					allowed = strings.TrimSpace(parts[1])
				}
			}
		}

		if priv != "" && (allowed != "" || strings.HasPrefix(name, "discovered-")) {
			// Calculate public key from private key securely without shell injection risk
			cmd := exec.Command("wg", "pubkey")
			cmd.Stdin = strings.NewReader(priv)
			out, err := cmd.Output()
			if err != nil {
				slog.Error("Failed to get public key", "peer", name, "err", err)
				continue
			}
			pub := strings.TrimSpace(string(out))
			if pub == "" {
				continue
			}

			foundPubKeys[pub] = true

			// Normalize IP for DB (Force /32)
			// The file contains /24 (Client View), but DB must have /32 (Server View)
			var dbAllowed string
			if ip, _, err := net.ParseCIDR(allowed); err == nil {
				dbAllowed = ip.String() + "/32"
			} else {
				// Fallback if not CIDR (just IP)
				dbAllowed = allowed
				if !strings.Contains(dbAllowed, "/") {
					dbAllowed += "/32"
				}
			}

			// If not in DB, insert it. If in DB but missing encryption key, update it.
			if !dbPeers[pub] {
				// Defensive: Never insert a ghost peer (0.0.0.0)
				if strings.HasPrefix(allowed, "0.0.0.0") || !strings.Contains(allowed, ".") {
					slog.Warn("Ignoring new peer from file with invalid IP", "peer", name, "ip", allowed)
					continue
				}

				encPriv, _ := auth.Encrypt(priv)
				// FIX: Insert normalized /32 into DB
				db.Exec("INSERT INTO peers (name, public_key, encrypted_private_key, allowed_ips) VALUES (?, ?, ?, ?)",
					name, pub, encPriv, dbAllowed)
			} else {
				// Peer exists in DB - check if it needs encryption key update (CLI-created with empty key)
				// Also check if CIDR needs update (e.g. replacing /32 from wg0.conf with /24 from .conf)
				var existingEnc, existingIP, existingName string
				db.QueryRow("SELECT encrypted_private_key, allowed_ips, name FROM peers WHERE public_key = ?", pub).Scan(&existingEnc, &existingIP, &existingName)
				
				// 1. Sync Name from File (CLI Rename -> API)
				if existingName != "" && name != "" && existingName != name {
					slog.Info("Syncing rename from file", "old_name", existingName, "new_name", name)
					db.Exec("UPDATE peers SET name = ? WHERE public_key = ?", name, pub)
				}

				// 2. Sync Private Key (CLI Create -> API)
				if existingEnc == "" && priv != "" {
					slog.Info("Adopting CLI peer: encrypting private key from .conf file", "peer", name)
					encPriv, _ := auth.Encrypt(priv)
					db.Exec("UPDATE peers SET encrypted_private_key = ? WHERE public_key = ?", encPriv, pub)
				}
				
				// 3. Fix CIDR mismatch
				// WE ONLY UPDATE IF DB IS BROKEN (e.g. has /24). 
				// We DO NOT update if DB is /32 and File is /24.
				if existingIP != "" && dbAllowed != "" && existingIP != dbAllowed {
					// If DB has /24 (broken) and we calculated /32 (correct), update it.
					// If DB has /32 (correct) and File has /24 (correct for client), dbAllowed is /32. Matches.
					
					// Defensive checks
					if strings.HasPrefix(dbAllowed, "0.0.0.0") { continue }

					slog.Info("Correcting peer CIDR in DB to /32", "peer", name, "old", existingIP, "new", dbAllowed)
					db.Exec("UPDATE peers SET allowed_ips = ? WHERE public_key = ?", dbAllowed, pub)
				}
			}
		}
	}

	// 3. Re-generate missing .conf files for DB peers (CLI Visibility)
	// (Except for those we just discovered/synced from files)
	for pk := range dbPeers {
		if !foundPubKeys[pk] {
			var name, encPriv, allowed string
			db.QueryRow("SELECT name, encrypted_private_key, allowed_ips FROM peers WHERE public_key = ?", pk).Scan(&name, &encPriv, &allowed)
			if name != "" && encPriv != "" {
				priv, _ := auth.Decrypt(encPriv)
				if priv != "" {
					// Reconstruct the file so CLI can see it
					cfgPath := filepath.Join(clientDir, name+".conf")
					if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
						slog.Info("Self-healing missing cliffer config", "name", name)
						// Basic client config reconstruction
						serverPub := GetServerPublicKey()
						wanIP := getValidWanIP(db)
						port := "51820"
						db.QueryRow("SELECT value FROM system_config WHERE key='listen_port'").Scan(&port)
						mtu := "1420"
						db.QueryRow("SELECT value FROM system_config WHERE key='mtu'").Scan(&mtu)
						
						clientConf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = 1.1.1.1, 8.8.8.8\nMTU = %s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = %s:%s\nPersistentKeepalive = 25\n",
							priv, allowed, mtu, serverPub, wanIP, port)
						os.WriteFile(cfgPath, []byte(clientConf), 0600)
					}
				}
			}
		}
	}

	// 4. Encryption Self-Healing: Migrate/Fix plaintext keys inserted by legacy CLI or direct DB edits
	migrateRows, err := db.Query("SELECT id, encrypted_private_key FROM peers WHERE encrypted_private_key != ''")
	if err == nil {
		defer migrateRows.Close()
		for migrateRows.Next() {
			var id int
			var enc string
			if err := migrateRows.Scan(&id, &enc); err == nil {
				// A WireGuard private key is exactly 44 chars in base64.
				if len(enc) == 44 {
					slog.Info("Self-healing: Found plaintext key in DB, encrypting...", "peer_id", id)
					newEnc, err := auth.Encrypt(enc)
					if err == nil {
						db.Exec("UPDATE peers SET encrypted_private_key = ? WHERE id = ?", newEnc, id)
					}
				}
			}
		}
	}
}

// ListPeers returns paginated list of peers
func ListPeers(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// S0171 Optimization: Only sync if explicitly requested or if stale (60s)
		shouldSync := r.URL.Query().Get("sync") == "true"
		syncMu.Lock()
		if shouldSync || time.Since(lastSyncTime) > 60*time.Second {
			syncPeersWithFiles(db)
			lastSyncTime = time.Now()
		}
		syncMu.Unlock()

		page := 1
		pageSize := DefaultPageSize

		if p := r.URL.Query().Get("page"); p != "" {
			if v, err := strconv.Atoi(p); err == nil && v > 0 {
				page = v
			}
		}
		if ps := r.URL.Query().Get("page_size"); ps != "" {
			if v, err := strconv.Atoi(ps); err == nil && v > 0 && v <= MaxPageSize {
				pageSize = v
			}
		}

		offset := (page - 1) * pageSize



		var total int
		db.QueryRow("SELECT COUNT(*) FROM peers").Scan(&total)

		rows, err := db.Query(`SELECT id, name, public_key, allowed_ips, 
			COALESCE(disabled, 0), expires_at, 
			COALESCE(total_rx_bytes, 0), COALESCE(total_tx_bytes, 0),
			COALESCE(data_limit_gb, 0)
			FROM peers ORDER BY id LIMIT ? OFFSET ?`, pageSize, offset)
		if err != nil {
			apiErrors.Add(1)
			http.Error(w, "DB Error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		// Get current subnet for display masking
		var subnetCIDR string
		db.QueryRow("SELECT value FROM system_config WHERE key='subnet_cidr'").Scan(&subnetCIDR)
		if subnetCIDR == "" {
			subnetCIDR = "10.100.0.0/24"
		}
		mask := "/24"
		if parts := strings.Split(subnetCIDR, "/"); len(parts) == 2 {
			mask = "/" + parts[1]
		}

		// Get WireGuard stats for traffic display
		wgStats := GetWireGuardStats()

		peers := make([]Peer, 0)
		for rows.Next() {
			var p Peer
			var expiresAt sql.NullInt64
			var disabled int
			var totalRx, totalTx int64
			var limitGB int
			if err := rows.Scan(&p.ID, &p.Name, &p.PublicKey, &p.AllowedIPs, &disabled, &expiresAt, &totalRx, &totalTx, &limitGB); err != nil {
				continue
			}
			p.Disabled = disabled == 1
			p.DataLimitGB = limitGB
			if expiresAt.Valid {
				p.ExpiresAt = &expiresAt.Int64
			}
			// Mask IP for UI display correctness
			p.AllowedIPs = strings.Replace(p.AllowedIPs, "/32", mask, 1)

			// Add traffic stats: combine stored totals with live WG stats
			// This gives persistent usage even across disable/enable cycles
			if stats, ok := wgStats[p.PublicKey]; ok {
				p.RxBytes = totalRx + stats.RxBytes
				p.TxBytes = totalTx + stats.TxBytes
				p.Rx = formatBytes(p.RxBytes)
				p.Tx = formatBytes(p.TxBytes)
				p.LastHandshake = stats.LastHandshake
			} else {
				// Peer is disabled or not in WG - show stored totals only
				p.RxBytes = totalRx
				p.TxBytes = totalTx
				p.Rx = formatBytes(totalRx)
				p.Tx = formatBytes(totalTx)
			}
			peers = append(peers, p)
		}

		totalPages := (total + pageSize - 1) / pageSize

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(PeerListResponse{
			Peers:      peers,
			Total:      total,
			Page:       page,
			PageSize:   pageSize,
			TotalPages: totalPages,
		})
	}
}

// getSubnetMax removed, use CalculateMaxPeers from handlers package

func CreatePeer(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req NewPeerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}



		match, _ := regexp.MatchString("^[a-zA-Z0-9_-]{1,64}$", req.Name)
		if !match {
			http.Error(w, "Invalid Peer Name (1-64 alphanumeric chars)", http.StatusBadRequest)
			return
		}



		var exists int
		db.QueryRow("SELECT 1 FROM peers WHERE name = ?", req.Name).Scan(&exists)
		if exists == 1 {
			http.Error(w, "Peer name already exists", http.StatusConflict)
			return
		}

		// Acquire IP allocation lock to prevent race condition
		ipAllocMu.Lock()
		defer ipAllocMu.Unlock()

		// Always sync with physical config before allocating to prevent "split brain"
		syncSubnetWithFiles(db)


		tx, err := db.Begin()
		if err != nil {
			http.Error(w, "Transaction error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback()

		var subnetCIDR string
		db.QueryRow("SELECT value FROM system_config WHERE key='subnet_cidr'").Scan(&subnetCIDR)
		if subnetCIDR == "" {
			subnetCIDR = "10.100.0.0/24"
		}

		var peerCount int
		tx.QueryRow("SELECT COUNT(*) FROM peers").Scan(&peerCount)
		maxPeers := CalculateMaxPeers(subnetCIDR)
		if peerCount >= maxPeers {
			http.Error(w, fmt.Sprintf("Subnet exhausted (max %d peers for %s)", maxPeers, subnetCIDR), http.StatusConflict)
			return
		}



		// Generate WireGuard keys securely using native Go crypto
		privateKey, publicKey, err := auth.GenerateWireGuardKeys()
		if err != nil {
			apiErrors.Add(1)
			http.Error(w, "Key generation failed", http.StatusInternalServerError)
			return
		}



		encPriv, err := auth.Encrypt(privateKey)
		if err != nil {
			http.Error(w, "Encryption failed", http.StatusInternalServerError)
			return
		}

		// Robust IP allocation with hole-filling or requested IP
		nextIP, err := AllocateIP(tx, req.IP)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		
		// CRITICAL: Server-side AllowedIPs must use /32 for per-client routing
		// nextIP has subnet mask (e.g., 10.100.0.5/24) for client Address
		// serverAllowedIP uses /32 for WireGuard routing on server
		serverAllowedIP := strings.Split(nextIP, "/")[0] + "/32"

		// Calculate expiry timestamp if temporary peer
		var expiresAt interface{}
		if req.ExpiresIn > 0 && req.ExpiresIn <= 365 {
			expiresAt = time.Now().Add(time.Duration(req.ExpiresIn) * 24 * time.Hour).Unix()
		}

		_, err = tx.Exec("INSERT INTO peers (name, public_key, encrypted_private_key, allowed_ips, expires_at) VALUES (?, ?, ?, ?, ?)",
			req.Name, publicKey, encPriv, nextIP, expiresAt)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				http.Error(w, "Duplicate public key", http.StatusConflict)
			} else {
				http.Error(w, "Failed to create peer", http.StatusInternalServerError)
			}
			return
		}


		// --- BEGIN CLI SYNC (Atomic Side Effects) ---
		clientDir := "/opt/samnet/clients"
		os.MkdirAll(clientDir, 0700)
		clientConfPath := filepath.Join(clientDir, req.Name+".conf")
		
		serverPub := GetServerPublicKey()
		wanIP := getValidWanIP(db)
		port := "51820"
		db.QueryRow("SELECT value FROM system_config WHERE key='listen_port'").Scan(&port)
		
		_, ipNet, _ := net.ParseCIDR(subnetCIDR)
		ones, _ := ipNet.Mask.Size()
		clientAddr := strings.Split(nextIP, "/")[0] + fmt.Sprintf("/%d", ones)
		
		dns := "1.1.1.1"
		db.QueryRow("SELECT value FROM system_config WHERE key='dns_server'").Scan(&dns)
		mtu := "1420"
		db.QueryRow("SELECT value FROM system_config WHERE key='mtu'").Scan(&mtu)

		clientConf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = %s\nMTU = %s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = %s:%s\nPersistentKeepalive = 25\n",
			privateKey, clientAddr, dns, mtu, serverPub, wanIP, port)
		
		if err := os.WriteFile(clientConfPath, []byte(clientConf), 0600); err != nil {
			slog.Error("Failed to write client config", "peer", req.Name, "error", err)
			return // Transaction will rollback via defer
		}

		// Update wg0.conf with locking (use separate lock file for cross-process compatibility with CLI)
		wg0Path := config.Get().WGConfigPath
		lockPath := filepath.Dir(wg0Path) + "/.wg0.lock"
		
		lockFile, lockErr := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
		if lockErr != nil {
			slog.Warn("Could not open lock file", "error", lockErr)
		} else {
			defer lockFile.Close()
			
			// Acquire exclusive lock (blocks until CLI releases it)
			if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
				slog.Warn("Could not acquire lock", "error", err)
			} else {
				defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
				
				if f, err := os.OpenFile(wg0Path, os.O_APPEND|os.O_WRONLY, 0600); err != nil {
					slog.Warn("Could not open wg0.conf for append", "error", err)
				} else {
					fmt.Fprintf(f, "\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s\n", req.Name, publicKey, serverAllowedIP)
					f.Close()
				}
			}
		}

		// Try direct wg set first (works if container has host network access or NET_ADMIN capability)
		// This is the most reliable method when available
		wgSetCmd := exec.Command("wg", "set", "wg0", "peer", publicKey, "allowed-ips", serverAllowedIP)
		if err := wgSetCmd.Run(); err != nil {
			slog.Warn("Direct wg set failed (expected in container), using trigger file fallback", "error", err)
			
			// Fallback: Write trigger file for host-side inotifywait service to pick up
			triggerPath := "/etc/wireguard/.reload_trigger"
			if err := os.WriteFile(triggerPath, []byte(fmt.Sprintf("%d", time.Now().Unix())), 0644); err != nil {
				slog.Error("Could not write WG reload trigger", "error", err)
			} else {
				slog.Info("Wrote WG reload trigger for host-side sync")
			}
		} else {
			slog.Info("Successfully added peer to live WireGuard via wg set", "peer", req.Name)
		}

		// Only commit if side effects (at least file writes) succeeded
		if err := tx.Commit(); err != nil {
			os.Remove(clientConfPath) // Cleanup file if DB failed
			http.Error(w, "Final DB commit failed", http.StatusInternalServerError)
			return
		}
		// --- END CLI SYNC ---

		reconcile.Trigger()
		// cfg := config.Get()

		// Audit log - use middleware.GetClientIP and GetRequestID for consistency
		clientIP := middleware.GetClientIP(r)
		requestID := middleware.GetRequestID(r)
		userID := middleware.GetUserID(r)
		db.Exec("INSERT INTO audit_logs (user_id, action, target, details, ip_address, request_id) VALUES (?, 'CREATE_PEER', ?, 'Peer created via API (Synced with CLI)', ?, ?)",
			userID, req.Name, clientIP, requestID)

		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "accepted",
			"name":   req.Name,
		})
	}
}

func DeletePeer(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		peerOpMu.Lock()
		defer peerOpMu.Unlock()
		
		syncPeersWithFiles(db)
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "Missing ID", http.StatusBadRequest)
			return
		}


		var name, pub string
		var totalRx, totalTx int64
		var currentRx, currentTx int64

		err := db.QueryRow("SELECT name, public_key, COALESCE(total_rx_bytes, 0), COALESCE(total_tx_bytes, 0), COALESCE(rx_bytes, 0), COALESCE(tx_bytes, 0) FROM peers WHERE id = ?", id).Scan(&name, &pub, &totalRx, &totalTx, &currentRx, &currentTx)
		if err != nil {
			// Idempotent: Return success if peer already deleted
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status": "deleted", "already_deleted": true}`))
			return
		}

		// Archive to historical_usage
		// Note: We use stored current values. Ideally we'd sync live stats one last time, 
		// but syncPeersWithFiles at start of handler should have caught most recent data.
		db.Exec("INSERT INTO historical_usage (peer_name, public_key, rx_bytes, tx_bytes) VALUES (?, ?, ?, ?)",
			name, pub, totalRx+currentRx, totalTx+currentTx)

		// 1. Remove from live WireGuard (log errors but continue)
		if pub != "" {
			if err := exec.Command("wg", "set", "wg0", "peer", pub, "remove").Run(); err != nil {
				slog.Warn("WireGuard remove failed (peer may not exist in live config)", "peer", name, "error", err)
			}
		}

		// 2. Remove .conf file (ignore if doesn't exist)
		clientConfPath := filepath.Join("/opt/samnet/clients", name+".conf")
		os.Remove(clientConfPath)
		os.Remove(clientConfPath + ".limit")
		os.Remove(clientConfPath + ".expiry")
		os.Remove(clientConfPath + ".disabled")

		// 3. Remove from wg0.conf with locking
		wg0Path := config.Get().WGConfigPath
		if f, err := os.OpenFile(wg0Path, os.O_RDWR, 0600); err == nil {
			defer f.Close()
			if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err == nil {
				defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				
				content, _ := os.ReadFile(wg0Path)
				lines := strings.Split(string(content), "\n")
				var newLines []string
				skip := false
				for i := 0; i < len(lines); i++ {
					line := strings.TrimSpace(lines[i])
					if line == "[Peer]" {
						isTarget := false
						for j := 1; j < 5 && i+j < len(lines); j++ {
							if strings.Contains(lines[i+j], pub) || (name != "" && strings.Contains(lines[i+j], "# "+name)) {
								isTarget = true
								break
							}
						}
						if isTarget {
							skip = true
							continue
						}
					}
					if skip && (strings.HasPrefix(line, "[") && line != "[Peer]") {
						skip = false
					}
					if !skip {
						newLines = append(newLines, lines[i])
					}
				}
				result := strings.Join(newLines, "\n")
				result = regexp.MustCompile(`\n{3,}`).ReplaceAllString(result, "\n\n")
				
				f.Truncate(0)
				f.Seek(0, 0)
				f.Write([]byte(result))
			}
		}

		// 4. Delete from DB
		db.Exec("DELETE FROM peers WHERE id = ?", id)
		
		reconcile.Trigger()

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "deleted"}`))
	}
}

// UpdatePeerRequest allows partial updates
type UpdatePeerRequest struct {
	Name        *string `json:"name"`
	Disabled    *bool   `json:"disabled"`
	DataLimitGB *int    `json:"data_limit_gb"` // pointer to distinguish 0 (remove) from nil (no change)
}

func UpdatePeer(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		peerOpMu.Lock()
		defer peerOpMu.Unlock()
		
		syncPeersWithFiles(db)
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "Missing ID", http.StatusBadRequest)
			return
		}

		var req UpdatePeerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Get current state
		var currentName, pubKey, allowedIPs string
		var currentDisabled bool
		var disabledInt int
		err := db.QueryRow("SELECT name, public_key, allowed_ips, COALESCE(disabled, 0) FROM peers WHERE id = ?", id).Scan(&currentName, &pubKey, &allowedIPs, &disabledInt)
		if err != nil {
			http.Error(w, "Peer not found", http.StatusNotFound)
			return
		}
		currentDisabled = disabledInt == 1

		// 1. Handle Rename
		if req.Name != nil && *req.Name != "" && *req.Name != currentName {
			newName := *req.Name
			match, _ := regexp.MatchString("^[a-zA-Z0-9_-]{1,64}$", newName)
			if !match {
				http.Error(w, "Invalid Peer Name", http.StatusBadRequest)
				return
			}

			// Rename .conf file
			oldPath := filepath.Join("/opt/samnet/clients", currentName+".conf")
			newPath := filepath.Join("/opt/samnet/clients", newName+".conf")
			
			// Rename if exists
			if _, err := os.Stat(oldPath); err == nil {
				os.Rename(oldPath, newPath)
			}
			// Rename sidecar files if they exist
			if _, err := os.Stat(oldPath + ".limit"); err == nil {
				os.Rename(oldPath+".limit", newPath+".limit")
			}
			if _, err := os.Stat(oldPath + ".expiry"); err == nil {
				os.Rename(oldPath+".expiry", newPath+".expiry")
			}
			if _, err := os.Stat(oldPath + ".disabled"); err == nil {
				os.Rename(oldPath+".disabled", newPath+".disabled")
			}
			
			// Update DB
			db.Exec("UPDATE peers SET name = ? WHERE id = ?", newName, id)
			currentName = newName
			
			// Update wg0.conf comment (Best effort regex)
			// Read file, replace "# oldName" with "# newName"
			wg0Path := config.Get().WGConfigPath
			if content, err := os.ReadFile(wg0Path); err == nil {
				newContent := strings.Replace(string(content), "# "+currentName, "# "+newName, 1)
				os.WriteFile(wg0Path, []byte(newContent), 0600)
			}
			
			slog.Info("Renamed peer", "old", currentName, "new", newName)
		}

		// 2. Handle Data Limit
		if req.DataLimitGB != nil {
			limit := *req.DataLimitGB
			db.Exec("UPDATE peers SET data_limit_gb = ? WHERE id = ?", limit, id)
			
			// Sync with file system for CLI compatibility
			limitFile := filepath.Join("/opt/samnet/clients", currentName+".conf.limit")
			if limit > 0 {
				os.WriteFile(limitFile, []byte(fmt.Sprintf("%d", limit)), 0644)
			} else {
				os.Remove(limitFile)
			}
			slog.Info("Updated peer limit", "peer", currentName, "limit_gb", limit)
		}

		// 2. Handle Disable/Enable
		if req.Disabled != nil && *req.Disabled != currentDisabled {
			shouldDisable := *req.Disabled
			
			if shouldDisable {
				// Accumulate current data into total counters before removing from WG
				// This preserves data usage history across disable/enable cycles
				db.Exec(`UPDATE peers SET 
					total_rx_bytes = total_rx_bytes + COALESCE(rx_bytes, 0),
					total_tx_bytes = total_tx_bytes + COALESCE(tx_bytes, 0),
					rx_bytes = 0, tx_bytes = 0
					WHERE id = ?`, id)
				
				// Remove from live WireGuard
				exec.Command("wg", "set", "wg0", "peer", pubKey, "remove").Run()
				db.Exec("UPDATE peers SET disabled = 1 WHERE id = ?", id)
				
				// Create marker file for CLI compatibility
				markerPath := filepath.Join("/opt/samnet/clients", currentName+".conf.disabled")
				os.Create(markerPath)
				
				// Update wg0.conf on disk to persist across reboots
				removePeerFromWGConf(currentName, pubKey)
				
				slog.Info("Disabled peer", "peer", currentName)
			} else {
				// S0243: Key Integrity Check
				// Verify that the local .conf file still matches the DB record
				clientConfPath := filepath.Join("/opt/samnet/clients", currentName+".conf")
				if content, err := os.ReadFile(clientConfPath); err == nil {
					// Extract PrivateKey from file
					re := regexp.MustCompile(`(?i)PrivateKey\s*=\s*([a-zA-Z0-9+/=]+)`)
					match := re.FindStringSubmatch(string(content))
					if len(match) > 1 {
						filePriv := strings.TrimSpace(match[1])
						filePub, err := auth.GetPublicKeyFromPrivate(filePriv)
						if err != nil || filePub != pubKey {
							slog.Warn("Key Integrity Violation (Mismatch)", "peer", currentName, "db_pub", pubKey, "file_pub", filePub)
							// Do not block - allow enabling even if file is out of sync (DB is authoritative for Server)
						}
					}
				}

				// Enable: Add back to live WireGuard with AllowedIPs
				// CRITICAL: Server-side must use /32, not the subnet mask from DB
				serverIP := strings.Split(allowedIPs, "/")[0] + "/32"
				exec.Command("wg", "set", "wg0", "peer", pubKey, "allowed-ips", serverIP).Run()
				db.Exec("UPDATE peers SET disabled = 0 WHERE id = ?", id)
				
				// Remove marker file for CLI compatibility
				markerPath := filepath.Join("/opt/samnet/clients", currentName+".conf.disabled")
				os.Remove(markerPath)
				
				// Update wg0.conf on disk to persist across reboots
				// Reconcile/Trigger will handle adding it back if missing during next cycle
				// but let's be proactive. Trigger() is called at the end.
				
				slog.Info("Enabled peer", "peer", currentName)
			}
		}

		reconcile.Trigger()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "updated"}`))
	}
}

func ExportAllPeers(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientDir := config.Get().ClientsDir
		files, err := os.ReadDir(clientDir)
		if err != nil {
			http.Error(w, "Failed to read client configs", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", "attachment; filename=samnet-configs.zip")

		zw := zip.NewWriter(w)
		defer zw.Close()

		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".conf") {
				continue
			}

			filePath := filepath.Join(clientDir, f.Name())
			file, err := os.Open(filePath)
			if err != nil {
				continue
			}
			defer file.Close()

			fw, err := zw.Create(f.Name())
			if err != nil {
				continue
			}

			if _, err := io.Copy(fw, file); err != nil {
				continue
			}
		}
	}
}

func removePeerFromWGConf(name, pub string) {
	wg0Path := config.Get().WGConfigPath
	content, err := os.ReadFile(wg0Path)
	if err != nil {
		slog.Error("Failed to read wg0.conf for removal", "err", err)
		return
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	peerFound := false

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "[Peer]") {
			// Check if this block belongs to our peer by looking ahead
			isTarget := false
			for j := i + 1; j < len(lines) && j < i+10; j++ {
				next := strings.TrimSpace(lines[j])
				if strings.HasPrefix(next, "[Peer]") {
					break
				}
				if strings.Contains(next, "PublicKey = "+pub) || strings.Contains(next, "# "+name) {
					isTarget = true
					break
				}
			}
			if isTarget {
				peerFound = true
				// Skip this block
				for i+1 < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i+1]), "[Peer]") {
					i++
				}
				continue
			}
		}
		newLines = append(newLines, lines[i])
	}

	if peerFound {
		os.WriteFile(wg0Path, []byte(strings.Join(newLines, "\n")), 0600)
		slog.Info("Removed peer from wg0.conf", "peer", name)
	}
}
