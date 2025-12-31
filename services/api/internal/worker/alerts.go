package worker

import (
	"database/sql"
	"log"
	"os/exec"
	"strings"
	"strconv"
	"time"
)

func AlertsWorker(db *sql.DB) {
	ticker := time.NewTicker(5 * time.Minute)
	go checkAlerts(db)

	for range ticker.C {
		checkAlerts(db)
	}
}

func checkAlerts(db *sql.DB) {
	var enabled bool
	err := db.QueryRow("SELECT enabled FROM feature_flags WHERE key='alerts'").Scan(&enabled)
	if err != nil || !enabled {
		return
	}

	out, err := exec.Command("wg", "show", "wg0", "dump").Output()
	if err != nil {
		return
	}

	lines := strings.Split(string(out), "\n")
    now := time.Now().Unix()
    
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) < 5 {
			continue
		}
		pubKey := fields[0]
		handshake, _ := strconv.ParseInt(fields[4], 10, 64)
        
        // If handshake is 0, never connected. If > 0 and (now - handshake) > 86400 (24h)
        if handshake > 0 && (now - handshake) > 86400 {
             // Look up name
             var name string
             err := db.QueryRow("SELECT name FROM peers WHERE public_key = ?", pubKey).Scan(&name)
             if err == nil {
                 log.Printf("[Alerts] Peer '%s' is Stale (Last seen > 24h ago)", name)
             }
        }
	}
}
