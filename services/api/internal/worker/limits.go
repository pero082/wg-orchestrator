package worker

import (
	"bufio"
	"bytes"
	"database/sql"

	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/SamNet-dev/wg-orchestrator/services/api/internal/config"
)

// LimitWorker checks for peers exceeding data limits and disables them
// Runs frequently (every 10 seconds) for fast enforcement
func LimitWorker(db *sql.DB) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		checkLimits(db)
	}
}

func checkLimits(db *sql.DB) {
	// 1. Get peers with limits (limit > 0)
	rows, err := db.Query("SELECT name, public_key, data_limit_gb, COALESCE(total_rx_bytes, 0), COALESCE(total_tx_bytes, 0) FROM peers WHERE data_limit_gb > 0 AND disabled = 0")
	if err != nil {
		slog.Error("Limit check query failed", "error", err)
		return
	}
	defer rows.Close()

	type PeerLimit struct {
		Name     string
		PubKey   string
		LimitGB  int
		TotalRx  int64
		TotalTx  int64
	}

	var peers []PeerLimit
	for rows.Next() {
		var p PeerLimit
		if err := rows.Scan(&p.Name, &p.PubKey, &p.LimitGB, &p.TotalRx, &p.TotalTx); err == nil {
			peers = append(peers, p)
		}
	}
	rows.Close()

	if len(peers) == 0 {
		return
	}

	// 2. Fetch live WG stats
	liveStats := make(map[string]struct{ rx, tx int64 })
	cmd := exec.Command("wg", "show", "wg0", "transfer")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil {
		scanner := bufio.NewScanner(&out)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 3 {
				pub := fields[0]
				rx, _ := strconv.ParseInt(fields[1], 10, 64)
				tx, _ := strconv.ParseInt(fields[2], 10, 64)
				liveStats[pub] = struct{ rx, tx int64 }{rx, tx}
			}
		}
	} else {
		// Log debug only to avoid spam if WG is down
		// slog.Debug("Failed to fetch WG stats", "error", err)
	}

	// 3. Check and Enforce
	for _, p := range peers {
		live, ok := liveStats[p.PubKey]
		currentRx := int64(0)
		currentTx := int64(0)
		if ok {
			currentRx = live.rx
			currentTx = live.tx
		}

		totalUsage := p.TotalRx + p.TotalTx + currentRx + currentTx
		limitBytes := int64(p.LimitGB) * 1024 * 1024 * 1024

		if totalUsage > limitBytes {
			slog.Info("Peer exceeded data limit. Disabling...", "peer", p.Name, "limit_gb", p.LimitGB, "usage_bytes", totalUsage)
			disablePeer(db, p.Name, p.PubKey, currentRx, currentTx)
		}
	}
}

func disablePeer(db *sql.DB, name, pub string, liveRx, liveTx int64) {
	// 1. Accumulate stats into DB (save the live usage before reset)
	if liveRx > 0 || liveTx > 0 {
		_, err := db.Exec("UPDATE peers SET total_rx_bytes = total_rx_bytes + ?, total_tx_bytes = total_tx_bytes + ?, rx_bytes = 0, tx_bytes = 0 WHERE name = ?", liveRx, liveTx, name)
		if err != nil {
			slog.Error("Failed to update peer stats during disable", "error", err)
		}
	}

	// 2. Disable in DB
	_, err := db.Exec("UPDATE peers SET disabled = 1 WHERE name = ?", name)
	if err != nil {
		slog.Error("Failed to set peer disabled in DB", "error", err)
	}

	// 3. Remove from WireGuard interface
	if pub != "" {
		exec.Command("wg", "set", "wg0", "peer", pub, "remove").Run()
	}

	// 4. Create marker file (for CLI compatibility)
	cfg := config.Get()
	if cfg.ClientsDir != "" {
		markerPath := filepath.Join(cfg.ClientsDir, name+".conf.disabled")
		os.Create(markerPath)
	}
	
	Trigger() // Signal UI update
}
