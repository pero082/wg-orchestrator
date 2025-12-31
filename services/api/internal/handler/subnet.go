package handler

import (
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/SamNet-dev/wg-orchestrator/services/api/internal/config"
	"github.com/SamNet-dev/wg-orchestrator/services/api/internal/middleware"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

// SubnetPreset represents a predefined subnet option
type SubnetPreset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	CIDR        string `json:"cidr"`
	MaxPeers    int    `json:"max_peers"`
	Description string `json:"description"`
	Category    string `json:"category"`
}

// SubnetConfig represents the current subnet configuration
type SubnetConfig struct {
	CurrentCIDR     string `json:"current_cidr"`
	CurrentPreset   string `json:"current_preset,omitempty"`
	MaxPeers        int    `json:"max_peers"`
	UsedPeers       int    `json:"used_peers"`
	AvailablePeers  int    `json:"available_peers"`
	GatewayIP       string `json:"gateway_ip"`
	ServerIP        string `json:"server_ip"`
	FirstPeerIP     string `json:"first_peer_ip"`
	LastPeerIP      string `json:"last_peer_ip"`
}

// SubnetHelp provides explanations for subnet selection
var SubnetHelp = map[string]string{
	"overview": `WireGuard uses private IP addresses to create a secure virtual network. 
You need to choose a subnet (IP range) that doesn't conflict with your existing network.

Common private IP ranges:
• 10.0.0.0/8      - Class A (10.x.x.x) - 16 million addresses
• 172.16.0.0/12   - Class B (172.16-31.x.x) - 1 million addresses  
• 192.168.0.0/16  - Class C (192.168.x.x) - 65,000 addresses`,

	"sizing": `Choose a size based on how many devices you'll connect:

/28 = 14 devices   → Home lab, personal use
/25 = 126 devices  → Small business
/24 = 254 devices  → Medium organization (most common)
/22 = 1,022 devices → Large enterprise
/20 = 4,094 devices → Service provider`,

	"conflicts": `IMPORTANT: Avoid subnets that conflict with:
• Your home/office LAN (commonly 192.168.1.0/24 or 192.168.0.0/24)
• Docker default (172.17.0.0/16)
• Cloud provider VPCs (often 10.0.0.0/8 ranges)

We provide 5 different IP pools to avoid conflicts.`,

	"pools": `IP POOLS EXPLAINED:

• Pool A (10.100.x.x) - Default, works for most setups
• Pool B (10.200.x.x) - Alternative if 10.100 conflicts
• Pool C (10.50.x.x)  - Lower range, avoids common VPCs
• Pool D (172.30.x.x) - Class B, good for Docker environments
• Pool E (192.168.100.x) - Class C, familiar format`,
}

var SubnetPresetsBySize = []SubnetPreset{
	{
		ID:          "small",
		Name:        "Small Office",
		CIDR:        "10.100.0.0/28",
		MaxPeers:    14,
		Description: "Home lab or small team (up to 14 devices)",
		Category:    "size",
	},
	{
		ID:          "medium",
		Name:        "Medium Team",
		CIDR:        "10.100.0.0/25",
		MaxPeers:    126,
		Description: "Small business (up to 126 devices)",
		Category:    "size",
	},
	{
		ID:          "large",
		Name:        "Large Organization",
		CIDR:        "10.100.0.0/24",
		MaxPeers:    254,
		Description: "Standard deployment (up to 254 devices) [DEFAULT]",
		Category:    "size",
	},
	{
		ID:          "enterprise",
		Name:        "Enterprise",
		CIDR:        "10.100.0.0/22",
		MaxPeers:    1022,
		Description: "Large enterprise (up to 1,022 devices)",
		Category:    "size",
	},
	{
		ID:          "huge",
		Name:        "Huge",
		CIDR:        "10.100.0.0/19",
		MaxPeers:    8190,
		Description: "Multi-site (up to 8,190 devices)",
		Category:    "size",
	},
	{
		ID:          "massive",
		Name:        "Massive",
		CIDR:        "10.100.0.0/18",
		MaxPeers:    16382,
		Description: "Campus (up to 16,382 devices)",
		Category:    "size",
	},
	{
		ID:          "colossal",
		Name:        "Colossal",
		CIDR:        "10.100.0.0/17",
		MaxPeers:    32766,
		Description: "Regional (up to 32,766 devices)",
		Category:    "size",
	},
	{
		ID:          "carrier",
		Name:        "Service Provider",
		CIDR:        "10.100.0.0/20",
		MaxPeers:    4094,
		Description: "ISP/Carrier-grade (up to 4,094 devices)",
		Category:    "size",
	},
}

var IPPoolPresets = []SubnetPreset{
	{
		ID:          "pool_a",
		Name:        "Pool A - Standard",
		CIDR:        "10.100.0.0/24",
		MaxPeers:    254,
		Description: "10.100.0.x - Default range, works for most networks",
		Category:    "pool",
	},
	{
		ID:          "pool_b",
		Name:        "Pool B - Alternate",
		CIDR:        "10.200.0.0/24",
		MaxPeers:    254,
		Description: "10.200.0.x - Use if 10.100 conflicts with your network",
		Category:    "pool",
	},
	{
		ID:          "pool_c",
		Name:        "Pool C - Low Range",
		CIDR:        "10.50.0.0/24",
		MaxPeers:    254,
		Description: "10.50.0.x - Lower range, avoids common cloud VPCs",
		Category:    "pool",
	},
	{
		ID:          "pool_d",
		Name:        "Pool D - Docker-Safe",
		CIDR:        "172.30.0.0/24",
		MaxPeers:    254,
		Description: "172.30.0.x - Class B range, avoids Docker default",
		Category:    "pool",
	},
	{
		ID:          "pool_e",
		Name:        "Pool E - Classic",
		CIDR:        "192.168.100.0/24",
		MaxPeers:    254,
		Description: "192.168.100.x - Familiar format, easy to remember",
		Category:    "pool",
	},
	{
		ID:          "pool_f",
		Name:        "Pool F - Specific",
		CIDR:        "10.7.0.0/24",
		MaxPeers:    254,
		Description: "10.7.0.x - User requested range",
		Category:    "pool",
	},
}

// Combine all presets for legacy compatibility
var SubnetPresets = append(SubnetPresetsBySize, IPPoolPresets...)

// Standard CIDR options for advanced users
var StandardCIDROptions = []string{"/20", "/21", "/22", "/23", "/24", "/25", "/26", "/27", "/28"}

// GetSubnetPresets returns available subnet presets with help
func GetSubnetPresets(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"size_presets":    SubnetPresetsBySize,
			"pool_presets":    IPPoolPresets,
			"standard_cidrs":  StandardCIDROptions,
			"custom_allowed":  true,
			"custom_pattern":  "^(10|172\\.(1[6-9]|2[0-9]|3[01])|192\\.168)\\.[0-9]+\\.[0-9]+/[0-9]+$",
			"help":            SubnetHelp,
		})
	}
}

// GetCurrentSubnet returns the current subnet configuration
func GetCurrentSubnet(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		config := getCurrentSubnetConfig(db)
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
	}
}

func getCurrentSubnetConfig(db *sql.DB) SubnetConfig {
	syncSubnetWithFiles(db)
	var cidr string
	err := db.QueryRow("SELECT value FROM system_config WHERE key='subnet_cidr'").Scan(&cidr)
	if err != nil || cidr == "" {
		cidr = "10.100.0.0/24" // Default
	}

	var preset string
	db.QueryRow("SELECT value FROM system_config WHERE key='subnet_preset'").Scan(&preset)

	var peerCount int
	db.QueryRow("SELECT COUNT(*) FROM peers").Scan(&peerCount)

	maxPeers := CalculateMaxPeers(cidr)
	

	
	gateway, server, firstPeer, lastPeer := calculateIPRanges(cidr, maxPeers)

	return SubnetConfig{
		CurrentCIDR:    cidr,
		CurrentPreset:  preset,
		MaxPeers:       maxPeers,
		UsedPeers:      peerCount,

		AvailablePeers: maxPeers - peerCount - 1, // -1 for Gateway IP
		GatewayIP:      gateway,
		ServerIP:       server,
		FirstPeerIP:    firstPeer,
		LastPeerIP:     lastPeer,
	}
}

// ConfigureSubnetRequest is the request body for subnet configuration
type ConfigureSubnetRequest struct {
	Preset     string `json:"preset,omitempty"`
	CustomCIDR string `json:"custom_cidr,omitempty"`
}

// ConfigureSubnet sets the VPN subnet (admin only)
func ConfigureSubnet(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Admin authorization check
		role := middleware.GetUserRole(r)
		if role != "admin" {
			http.Error(w, "Admin access required", http.StatusForbidden)
			return
		}

		var req ConfigureSubnetRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		var targetCIDR string
		var presetName string

		// Check if using preset
		if req.Preset != "" {
			for _, preset := range SubnetPresets {
				if preset.ID == req.Preset {
					targetCIDR = preset.CIDR
					presetName = preset.ID
					break
				}
			}
			if targetCIDR == "" {
				http.Error(w, "Unknown preset: "+req.Preset, http.StatusBadRequest)
				return
			}
		} else if req.CustomCIDR != "" {
			// Validate custom CIDR
			if err := validateCIDR(req.CustomCIDR); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			targetCIDR = req.CustomCIDR
			presetName = "custom"
		} else {
			http.Error(w, "Either preset or custom_cidr required", http.StatusBadRequest)
			return
		}

		// Check if subnet change is safe (no existing peers in different range)
		var peerCount int
		db.QueryRow("SELECT COUNT(*) FROM peers").Scan(&peerCount)
		if peerCount > 0 {
			// Check if existing peers fit in new subnet
			maxPeers := CalculateMaxPeers(targetCIDR)
			if peerCount > maxPeers {
				http.Error(w, fmt.Sprintf("Cannot shrink subnet: %d existing peers exceed new limit of %d", peerCount, maxPeers), http.StatusConflict)
				return
			}

			// Check if any peer IPs would be outside new range
			var currentCIDR string
			db.QueryRow("SELECT value FROM system_config WHERE key='subnet_cidr'").Scan(&currentCIDR)
			if currentCIDR != targetCIDR && !isCompatibleSubnetChange(currentCIDR, targetCIDR) {
				http.Error(w, "Subnet change requires peer reallocation. Existing peers have IPs outside new range.", http.StatusConflict)
				return
			}
		}

		// Store configuration with proper transaction handling
		tx, err := db.Begin()
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback() // Safe to call after Commit

		if _, err := tx.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('subnet_cidr', ?)", targetCIDR); err != nil {
			http.Error(w, "Failed to save subnet", http.StatusInternalServerError)
			return
		}
		if _, err := tx.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('subnet_preset', ?)", presetName); err != nil {
			http.Error(w, "Failed to save preset", http.StatusInternalServerError)
			return
		}
		
		// Reset IP pool if subnet changed and no peers exist
		var oldCIDR string
		db.QueryRow("SELECT value FROM system_config WHERE key='subnet_cidr'").Scan(&oldCIDR)
		if oldCIDR != targetCIDR && peerCount == 0 {
			tx.Exec("DELETE FROM ip_pool")
		}
		
		if err := tx.Commit(); err != nil {
			http.Error(w, "Failed to commit changes", http.StatusInternalServerError)
			return
		}

		// Audit log - use middleware's GetClientIP and GetRequestID
		clientIP := middleware.GetClientIP(r)
		requestID := middleware.GetRequestID(r)
		db.Exec("INSERT INTO audit_logs (user_id, action, target, details, ip_address, request_id) VALUES (?, 'CONFIGURE_SUBNET', 'system', ?, ?, ?)",
			middleware.GetUserID(r), fmt.Sprintf("Changed subnet to %s (preset: %s)", targetCIDR, presetName), clientIP, requestID)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(getCurrentSubnetConfig(db))
	}
}

// validateCIDR validates a custom CIDR
func validateCIDR(cidr string) error {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR format: %s", cidr)
	}

	// Must be private IP range
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("IPv4 only supported")
	}

	if !isPrivateIPRange(ip4) {
		return fmt.Errorf("CIDR must be in private IP range (10.x, 172.16-31.x, 192.168.x)")
	}

	// Validate prefix length
	ones, _ := ipNet.Mask.Size()
	if ones < 16 || ones > 30 {
		return fmt.Errorf("prefix must be between /16 and /30")
	}

	return nil
}

func isPrivateIPRange(ip net.IP) bool {
	private := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	for _, cidr := range private {
		_, ipNet, _ := net.ParseCIDR(cidr)
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

func CalculateMaxPeers(cidr string) int {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 254 // Default /24
	}

	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	
	// Total IPs - 2 (network + broadcast)
	// We do not subtract the gateway here to align with standard subnet sizing (e.g., /24 = 254)
	return (1 << hostBits) - 2
}

func calculateIPRanges(cidr string, maxPeers int) (gateway, server, firstPeer, lastPeer string) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "10.100.0.1", "10.100.0.1", "10.100.0.2", "10.100.0.254"
	}

	ip4 := ip.To4()
	base := binary.BigEndian.Uint32(ip4)

	gatewayIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(gatewayIP, base+1)
	gateway = gatewayIP.String()
	server = gateway // Server uses gateway IP

	firstIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(firstIP, base+2)
	firstPeer = firstIP.String()

	// Calculate last usable IP
	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	lastOffset := uint32((1 << hostBits) - 2) // -1 for broadcast, -1 for 0-index
	
	lastIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(lastIP, base+lastOffset)
	lastPeer = lastIP.String()

	return
}

func isCompatibleSubnetChange(oldCIDR, newCIDR string) bool {
	// Check if new subnet contains old subnet (expansion is safe)
	_, oldNet, _ := net.ParseCIDR(oldCIDR)
	_, newNet, _ := net.ParseCIDR(newCIDR)
	
	if oldNet == nil || newNet == nil {
		return false
	}

	oldOnes, _ := oldNet.Mask.Size()
	newOnes, _ := newNet.Mask.Size()

	// New subnet is larger (smaller prefix = more hosts)
	if newOnes < oldOnes {
		// Check if base networks match
		return newNet.Contains(oldNet.IP)
	}

	return false
}

// AllocateIP finds the first available IP or validates a requested one
func AllocateIP(tx *sql.Tx, requestedIP string) (string, error) {
	var cidr string
	err := tx.QueryRow("SELECT value FROM system_config WHERE key='subnet_cidr'").Scan(&cidr)
	if err != nil || cidr == "" {
		cidr = "10.100.0.0/24"
	}

	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("invalid subnet CIDR: %w", err)
	}

	ip4 := ip.To4()
	base := binary.BigEndian.Uint32(ip4)



	rows, err := tx.Query("SELECT allowed_ips FROM peers")
	if err != nil {
		return "", fmt.Errorf("failed to query used IPs: %w", err)
	}
	defer rows.Close()

	usedIPs := make(map[uint32]bool)
	for rows.Next() {
		var aip string

		if err := rows.Scan(&aip); err == nil {
			parts := strings.Split(aip, "/")
			parsed := net.ParseIP(parts[0]).To4()
			if parsed != nil {
				usedIPs[binary.BigEndian.Uint32(parsed)] = true
			}
		}
	}

	// 2. Discover used IPs from Filesystem (to be CLI-aware)
	cfg := config.Get()
	if cfg.ClientsDir != "" {
		files, _ := os.ReadDir(cfg.ClientsDir)
		for _, f := range files {
			if !f.IsDir() && strings.HasSuffix(f.Name(), ".conf") {
				path := filepath.Join(cfg.ClientsDir, f.Name())
				if content, err := os.ReadFile(path); err == nil {
					// Regex to find "Address = X.X.X.X/YY"
					re := regexp.MustCompile(`(?i)Address\s*=\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)`)
					match := re.FindStringSubmatch(string(content))
					if len(match) > 1 {
						if parsed := net.ParseIP(match[1]).To4(); parsed != nil {
							usedIPs[binary.BigEndian.Uint32(parsed)] = true
						}
					}
				}
			}
		}
	}

	// 3. Detect server's actual IP from wg0.conf
	serverIP := base + 1 // Fallback
	if content, err := os.ReadFile(cfg.WGConfigPath); err == nil {
		re := regexp.MustCompile(`(?i)Address\s*=\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)`)
		match := re.FindStringSubmatch(string(content))
		if len(match) > 1 {
			if parsed := net.ParseIP(match[1]).To4(); parsed != nil {
				serverIP = binary.BigEndian.Uint32(parsed)
			}
		}
	}
	usedIPs[serverIP] = true



	ones, bits := ipNet.Mask.Size()
	maxOffset := uint32(1 << (bits - ones))

	// If an IP was specifically requested, validate it
	if requestedIP != "" {
		reqIP := net.ParseIP(requestedIP).To4()
		if reqIP == nil {
			// Try as an octet
			if octet, err := strconv.Atoi(requestedIP); err == nil && octet > 0 && octet < 255 {
				reqIP = make(net.IP, 4)
				binary.BigEndian.PutUint32(reqIP, base+uint32(octet))
			} else {
				return "", fmt.Errorf("invalid requested IP: %s", requestedIP)
			}
		}
		
		reqVal := binary.BigEndian.Uint32(reqIP)
		if !ipNet.Contains(reqIP) {
			return "", fmt.Errorf("requested IP %s is not in subnet %s", reqIP.String(), cidr)
		}
		if reqVal == base || reqVal == base+maxOffset-1 {
			return "", fmt.Errorf("requested IP %s is a network or broadcast address", reqIP.String())
		}
		if usedIPs[reqVal] {
			return "", fmt.Errorf("requested IP %s is already in use", reqIP.String())
		}
		return fmt.Sprintf("%s/%d", reqIP.String(), ones), nil
	}

	// Find first free IP: skip network (0) and broadcast. offset 1 is server. 
	// We'll scan from 1 and skip anything in usedIPs (which now includes server)
	for offset := uint32(1); offset < maxOffset-1; offset++ {
		target := base + offset
		if !usedIPs[target] {
			targetIP := make(net.IP, 4)
			binary.BigEndian.PutUint32(targetIP, target)
			return fmt.Sprintf("%s/%d", targetIP.String(), ones), nil
		}
	}

	return "", fmt.Errorf("subnet %s is full", cidr)
}

// SubnetStats returns subnet usage statistics
func SubnetStats(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		syncSubnetWithFiles(db)
		config := getCurrentSubnetConfig(db)
		
		// Calculate usage percentage
		usagePercent := float64(config.UsedPeers) / float64(config.MaxPeers) * 100

		stats := map[string]interface{}{
			"subnet":           config.CurrentCIDR,
			"current_cidr":     config.CurrentCIDR, // Support both field names for UI robustness
			"preset":           config.CurrentPreset,
			"total_capacity":   config.MaxPeers,
			"used":             config.UsedPeers,
			"available":        config.AvailablePeers,
			"usage_percent":    usagePercent,
			"near_exhaustion":  usagePercent > 80,
			"exhausted":        config.AvailablePeers == 0,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	}
}

// Note: GetClientIP removed - use middleware.GetClientIP instead for consistency
// This ensures all IP extraction uses the same trusted proxy validation logic
