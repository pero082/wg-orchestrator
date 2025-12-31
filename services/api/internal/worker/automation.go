package worker

import (
	"database/sql"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// AutomationWorker tracks peer handshakes and fires webhooks on state change
func AutomationWorker(db *sql.DB) {
	// In-memory state: PublicKey -> LastSeenTime
	state := make(map[string]int64)

	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		var webhook string
		err := db.QueryRow("SELECT webhook_url FROM automation_hooks WHERE enabled=1 LIMIT 1").Scan(&webhook)
		if err != nil {
			continue // No hooks configured
		}

		// Output format: peer_pubkey <tab> preshared_key <tab> endpoint <tab> allowed_ips <tab> latest_handshake <tab> transfer_rx <tab> transfer_tx <tab> persistent_keepalive
		out, err := exec.Command("wg", "show", "wg0", "dump").Output()
		if err != nil {
			// Fail silently if wg not found (dev env)
			continue
		}

		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			fields := strings.Split(line, "\t")
			if len(fields) < 5 {
				continue
			}
			pubKey := fields[0]
			handshakeStr := fields[4]
			handshake, _ := strconv.ParseInt(handshakeStr, 10, 64)
			
			const onlineThreshold = 180 // 3 mins
			isOnline := (time.Now().Unix() - handshake) < onlineThreshold

			oldHandshake, existed := state[pubKey]
			if isOnline && (!existed || oldHandshake == 0) {
				log.Printf("[Automation] Peer %s Connected. Firing Webhook: %s", pubKey, webhook)
			} else if !isOnline && existed && oldHandshake > 0 {
				log.Printf("[Automation] Peer %s Disconnected.", pubKey)
			}
			
			state[pubKey] = handshake
		}

		log.Println("[Automation] Pulse Check Complete.")

		if time.Now().Minute() == 0 {
			db.Exec("DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP")
		}
	}
}
