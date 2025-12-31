package handler

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/SamNet-dev/wg-orchestrator/services/api/internal/auth"
	"github.com/skip2/go-qrcode"
)

func GetPeerQR(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "Missing ID", http.StatusBadRequest)
			return
		}

		var name, encPrivKey, allowedIPs string
		var dnsProfile sql.NullString

		err := db.QueryRow(`
			SELECT p.name, p.encrypted_private_key, p.allowed_ips, ps.dns_profile 
			FROM peers p 
			LEFT JOIN peer_settings ps ON p.id = ps.peer_id 
			WHERE p.id = ?`, id).Scan(&name, &encPrivKey, &allowedIPs, &dnsProfile)
		if err != nil {
			http.Error(w, "Peer not found", http.StatusNotFound)
			return
		}

		var privateKey string
		
		// Only attempt decryption if there's actually something to decrypt
		if encPrivKey != "" && encPrivKey != "CLI_MANAGED" {
			privateKey, err = auth.Decrypt(encPrivKey)
			if err != nil {
				// Heuristic: If it looks like a raw WireGuard key (44 chars), use it as-is
				if len(encPrivKey) == 44 {
					slog.Info("Decryption failed but key looks like plaintext WireGuard key, using as-is", "peer", name)
					privateKey = encPrivKey
					err = nil // Clear error
				}
			}
		}
		
		// Fallback to file system if decryption failed or key was empty/CLI_MANAGED
		if privateKey == "" {
			clientConfPath := filepath.Join("/opt/samnet/clients", name+".conf")
			slog.Info("Decryption failed or key empty, attempting file fallback", "peer", name, "path", clientConfPath)
			
			content, fileErr := os.ReadFile(clientConfPath)
			if fileErr == nil {
				// Use robust regex for PrivateKey extraction
				re := regexp.MustCompile(`(?i)PrivateKey\s*=\s*([a-zA-Z0-9+/=]+)`)
				match := re.FindStringSubmatch(string(content))
				if len(match) > 1 {
					privateKey = match[1]
					slog.Info("Successfully recovered key from file", "peer", name)
					
					// Self-heal: Encrypt and update DB asynchronously
					go func(n, k string) {
						if enc, err := auth.Encrypt(k); err == nil {
							db.Exec("UPDATE peers SET encrypted_private_key = ? WHERE name = ?", enc, n)
						}
					}(name, privateKey)
				} else {
					slog.Warn("Found config file but could not find PrivateKey line", "peer", name, "path", clientConfPath)
				}
			} else {
				slog.Warn("File fallback failed: could not read config file", "peer", name, "path", clientConfPath, "error", fileErr)
			}
			
			// If still empty, we truly failed
			if privateKey == "" {
				slog.Error("Failed to decrypt key and all fallbacks failed", "peer", name)
				http.Error(w, "Failed to decrypt key - check API logs for details", http.StatusInternalServerError)
				return
			}
		}

		dns := "1.1.1.1, 8.8.8.8" // Match CLI format
		db.QueryRow("SELECT value FROM system_config WHERE key='dns_server'").Scan(&dns)
		
		if dnsProfile.Valid {
			switch dnsProfile.String {
			case "adblock":
				dns = "94.140.14.14"
			case "family":
				dns = "1.1.1.3"
			}
		}

		// Get system config for routing
		var subnetCIDR string
		var splitTunnel string
		db.QueryRow("SELECT value FROM system_config WHERE key='subnet_cidr'").Scan(&subnetCIDR)
		if subnetCIDR == "" {
			subnetCIDR = "10.100.0.0/24"
		}
		db.QueryRow("SELECT value FROM system_config WHERE key='split_tunnel'").Scan(&splitTunnel)
		
		var customHost string
		db.QueryRow("SELECT value FROM system_config WHERE key='endpoint_hostname'").Scan(&customHost)
		
		wanIP := ""
		if customHost != "" {
			wanIP = customHost
		} else {
			wanIP = getValidWanIP(db)
		}
		
		port := "51820"
		db.QueryRow("SELECT value FROM system_config WHERE key='listen_port'").Scan(&port)
		
		// Handle IPv6 literal in endpoint (shouldn't happen with getValidWanIP but safety)
		endpoint := fmt.Sprintf("%s:%s", wanIP, port)
		if strings.Contains(wanIP, ":") && !strings.Contains(wanIP, "[") {
			endpoint = fmt.Sprintf("[%s]:%s", wanIP, port)
		}

		// Fix: Use subnet mask for Address (e.g., /24) instead of /32
		_, ipNet, _ := net.ParseCIDR(subnetCIDR)
		ones, _ := ipNet.Mask.Size()
		if ones == 0 { ones = 24 } // Fallback safety
		clientAddr := strings.Split(allowedIPs, "/")[0] + fmt.Sprintf("/%d", ones)

		serverPub := GetServerPublicKey()
		
		// Get MTU from config (must match CLI-generated configs)
		mtu := "1380"
		db.QueryRow("SELECT value FROM system_config WHERE key='mtu'").Scan(&mtu)

		cfg := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = %s\nMTU = %s\n\n[Peer]\nPublicKey = %s\n",
			privateKey, clientAddr, dns, mtu, serverPub)

		if splitTunnel == "true" {
			cfg += fmt.Sprintf("AllowedIPs = %s, 192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8\n", subnetCIDR)
		} else {
			cfg += "AllowedIPs = 0.0.0.0/0, ::/0\n"
		}
		
		cfg += fmt.Sprintf("Endpoint = %s\nPersistentKeepalive = 25\n", endpoint)

		png, err := qrcode.Encode(cfg, qrcode.Medium, 256)
		if err != nil {
			http.Error(w, "Failed to generate QR code", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=peer-%s.png", id))
		w.Write(png)
	}
}
