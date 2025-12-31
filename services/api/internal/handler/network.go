package handler

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"database/sql"
	"encoding/json"
	"os/exec"
	"strings"
)

// NetworkSettings represents exit node and split tunnel config
type NetworkSettings struct {
	ExitNodeEnabled bool   `json:"exit_node_enabled"`
	SplitTunnel     bool   `json:"split_tunnel"`
	AllowedRoutes   string `json:"allowed_routes"`
}

type GlobalSettings struct {
	MTU       string `json:"mtu"`
	DNSServer string `json:"dns_server"`
}

// GetNetworkSettings returns current network mode
func GetNetworkSettings(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var settings NetworkSettings
		db.QueryRow("SELECT value FROM system_config WHERE key='exit_node_enabled'").Scan(&settings.ExitNodeEnabled)
		db.QueryRow("SELECT value FROM system_config WHERE key='split_tunnel'").Scan(&settings.SplitTunnel)
		db.QueryRow("SELECT value FROM system_config WHERE key='allowed_routes'").Scan(&settings.AllowedRoutes)

		json.NewEncoder(w).Encode(settings)
	}
}

// UpdateNetworkSettings updates exit node / split tunnel mode
func UpdateNetworkSettings(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req NetworkSettings
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		db.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('exit_node_enabled', ?)", req.ExitNodeEnabled)
		db.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('split_tunnel', ?)", req.SplitTunnel)
		db.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('allowed_routes', ?)", req.AllowedRoutes)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "updated"}`))
	}
}

func GetGlobalSettings(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var s GlobalSettings
		db.QueryRow("SELECT value FROM system_config WHERE key='mtu'").Scan(&s.MTU)
		db.QueryRow("SELECT value FROM system_config WHERE key='dns_server'").Scan(&s.DNSServer)
		if s.MTU == "" {
			s.MTU = "1420"
		}
		if s.DNSServer == "" {
			s.DNSServer = "1.1.1.1"
		}
		json.NewEncoder(w).Encode(s)
	}
}

func UpdateGlobalSettings(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req GlobalSettings
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// 1. Save to DB
		db.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('mtu', ?)", req.MTU)
		db.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('dns_server', ?)", req.DNSServer)

		// 2. S0246: Propagate to ALL existing client configs
		clientDir := "/opt/samnet/clients"
		files, _ := os.ReadDir(clientDir)
		for _, f := range files {
			if !f.IsDir() && strings.HasSuffix(f.Name(), ".conf") {
				path := filepath.Join(clientDir, f.Name())
				content, err := os.ReadFile(path)
				if err != nil {
					continue
				}

				newContent := string(content)
				// Update MTU
				mtuRegex := regexp.MustCompile(`(?i)MTU\s*=\s*[0-9]+`)
				newContent = mtuRegex.ReplaceAllString(newContent, "MTU = "+req.MTU)

				// Update DNS
				dnsRegex := regexp.MustCompile(`(?i)DNS\s*=\s*[0-9\.,\s]+`)
				newContent = dnsRegex.ReplaceAllString(newContent, "DNS = "+req.DNSServer)

				os.WriteFile(path, []byte(newContent), 0600)
			}
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "updated_and_propagated"}`))
	}
}

// WakeOnLAN sends a magic packet to wake a device
type WoLRequest struct {
	MAC string `json:"mac"` // Format: AA:BB:CC:DD:EE:FF
}

func WakeOnLAN(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req WoLRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}



		if len(req.MAC) != 17 {
			http.Error(w, "Invalid MAC address", http.StatusBadRequest)
			return
		}

		// Use wakeonlan command (or implement magic packet directly)
		cmd := exec.Command("wakeonlan", req.MAC)
		if err := cmd.Run(); err != nil {
			// Fallback: use etherwake
			exec.Command("etherwake", req.MAC).Run()
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "magic_packet_sent"}`))
	}
}

// PiholeSettings represents Pi-hole integration config
type PiholeSettings struct {
	Enabled   bool   `json:"enabled"`
	ServerIP  string `json:"server_ip"`
	APIKey    string `json:"api_key"`
}

// GetPiholeSettings returns Pi-hole config
func GetPiholeSettings(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var settings PiholeSettings
		db.QueryRow("SELECT value FROM system_config WHERE key='pihole_enabled'").Scan(&settings.Enabled)
		db.QueryRow("SELECT value FROM system_config WHERE key='pihole_server'").Scan(&settings.ServerIP)
		
		json.NewEncoder(w).Encode(settings)
	}
}

// UpdatePiholeSettings configures Pi-hole as DNS
func UpdatePiholeSettings(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req PiholeSettings
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		db.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('pihole_enabled', ?)", req.Enabled)
		db.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('pihole_server', ?)", req.ServerIP)



		if req.Enabled && req.ServerIP != "" {
			db.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('default_dns', ?)", req.ServerIP)
		} else {
			db.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('default_dns', '1.1.1.1')")
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "pihole_configured"}`))
	}
}

// QRCodeTerminal generates ASCII QR code for a peer
func QRCodeTerminal(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		peerID := r.URL.Query().Get("id")
		if peerID == "" {
			http.Error(w, "Missing peer ID", http.StatusBadRequest)
			return
		}



		var name, privKey, allowedIPs string
		db.QueryRow("SELECT name, encrypted_private_key, allowed_ips FROM peers WHERE id = ?", peerID).Scan(&name, &privKey, &allowedIPs)

		serverPub := GetServerPublicKey()
		endpoint := getValidWanIP(db)

		config := "[Interface]\nPrivateKey = " + privKey + "\nAddress = " + allowedIPs + "\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = " + serverPub + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = " + endpoint + ":51820\n"

		cmd := exec.Command("qrencode", "-t", "UTF8", "-o", "-")
		cmd.Stdin = strings.NewReader(config)
		qr, err := cmd.Output()
		if err != nil {
			http.Error(w, "QR generation failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.Write(qr)
	}
}
