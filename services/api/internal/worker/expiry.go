package worker

import (
	"database/sql"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// ExpiryWorker checks for expired peers and disables them
func ExpiryWorker(db *sql.DB) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		// First, get the public keys of peers about to be expired
		rows, err := db.Query(`
			SELECT name, public_key FROM peers 
			WHERE expires_at IS NOT NULL 
			AND expires_at < CAST(strftime('%s', 'now') AS INTEGER) 
			AND disabled = 0
		`)
		if err != nil {
			slog.Error("Expiry check failed", "error", err)
			continue
		}
		
		var expiredPeers []struct{ name, pubKey string }
		for rows.Next() {
			var name, pubKey string
			if err := rows.Scan(&name, &pubKey); err == nil {
				expiredPeers = append(expiredPeers, struct{ name, pubKey string }{name, pubKey})
			}
		}
		rows.Close()
		
		if len(expiredPeers) == 0 {
			continue
		}
		
		// FULL REMOVAL for temp peers (not just disable)
		for _, p := range expiredPeers {
			slog.Info("Removing expired temp peer completely", "peer", p.name)
			
			// 1. Remove from live WireGuard interface
			if p.pubKey != "" {
				exec.Command("wg", "set", "wg0", "peer", p.pubKey, "remove").Run()
			}
			
			// 2. Delete from database
			db.Exec("DELETE FROM peers WHERE name = ?", p.name)
			
			// 2.5 Cleanup Stats (Logs/Jobs cleanup as requested)
			db.Exec("DELETE FROM bandwidth_hourly WHERE peer_name = ?", p.name)
			db.Exec("DELETE FROM bandwidth_daily WHERE peer_name = ?", p.name)
			db.Exec("DELETE FROM bandwidth_total WHERE peer_name = ?", p.name)
			
			// 3. Remove from wg0.conf (best effort regex cleanup)
			removeFromWg0Conf(p.pubKey)
			
			// 4. Remove client config file
			clientConfPath := "/opt/samnet/clients/" + p.name + ".conf"
			os.Remove(clientConfPath)
			os.Remove(clientConfPath + ".disabled")
			os.Remove(clientConfPath + ".expiry") // Remove expiry marker too
			
			slog.Info("Temp peer fully removed", "peer", p.name)
		}
		
		Trigger()
	}
}

// removeFromWg0Conf removes a peer block from wg0.conf by public key
func removeFromWg0Conf(pubKey string) {
	if pubKey == "" {
		return
	}
	
	wgConfPath := "/etc/wireguard/wg0.conf"
	data, err := os.ReadFile(wgConfPath)
	if err != nil {
		return
	}
	
	lines := strings.Split(string(data), "\n")
	var result []string
	skipBlock := false
	
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		
		// Start of a new [Peer] block
		if trimmed == "[Peer]" {
			// Check if next lines contain our public key
			skipBlock = false
		}
		
		// If this line has our public key, mark to skip this entire block
		if strings.Contains(line, pubKey) {
			skipBlock = true
			// Also remove lines from result that belong to this [Peer] block
			// by backtracking to remove the [Peer] header and any comments
			for len(result) > 0 {
				last := strings.TrimSpace(result[len(result)-1])
				if last == "[Peer]" || strings.HasPrefix(last, "#") || last == "" {
					result = result[:len(result)-1]
				} else {
					break
				}
			}
			continue
		}
		
		if skipBlock {
			// Check if we've hit a new section (new block starts, or end of peer config)
			if trimmed == "[Peer]" || trimmed == "[Interface]" {
				skipBlock = false
			} else {
				continue // Skip this line
			}
		}
		
		result = append(result, line)
	}
	
	// Write back with exclusive lock
	lockFile, err := os.OpenFile("/etc/wireguard/.wg0.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err == nil {
		defer lockFile.Close()
		syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX)
		defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		os.WriteFile(wgConfPath, []byte(strings.Join(result, "\n")), 0600)
	}
}

// ScheduleWorker enables/disables peers based on time schedules
func ScheduleWorker(db *sql.DB) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		weekday := int(now.Weekday())
		hour := now.Hour()

		// Enable peers within schedule
		db.Exec(`
			UPDATE peers SET disabled = 0 
			WHERE id IN (
				SELECT peer_id FROM peer_schedules 
				WHERE day_of_week = ? AND start_hour <= ? AND end_hour > ?
			) AND disabled = 1
		`, weekday, hour, hour)

		db.Exec(`
			UPDATE peers SET disabled = 1 
			WHERE id IN (
				SELECT ps.peer_id FROM peer_schedules ps
				WHERE ps.peer_id = peers.id
				GROUP BY ps.peer_id
				HAVING MAX(CASE WHEN ps.day_of_week = ? AND ps.start_hour <= ? AND ps.end_hour > ? THEN 1 ELSE 0 END) = 0
			) AND disabled = 0
		`, weekday, hour, hour)
	}
}

// Trigger signals reconciliation (placeholder - uses the existing reconcile.Trigger pattern)
func Trigger() {
	// Touch the trigger file to signal systemd path unit
}
