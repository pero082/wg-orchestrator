package worker

import (
	"database/sql"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func MonitorWorker(db *sql.DB) {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		updatePeerStats(db)
	}
}

func updatePeerStats(db *sql.DB) {
	// wg show all dump format:
	// interface public_key preshared_key endpoint allowed_ips latest_handshake rx_bytes tx_bytes persistent_keepalive
	out, err := exec.Command("wg", "show", "all", "dump").CombinedOutput()
	if err != nil {
		slog.Error("WireGuard command failed", "error", err, "output", string(out))
		return
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 8 {
			continue
		}

		pubKey := parts[1]
		handshake, _ := strconv.ParseInt(parts[5], 10, 64)
		rx, _ := strconv.ParseInt(parts[6], 10, 64)
		tx, _ := strconv.ParseInt(parts[7], 10, 64)

		if handshake == 0 {
			continue
		}

		t := time.Unix(handshake, 0)
		_, err = db.Exec("UPDATE peers SET last_handshake = ?, rx_bytes = ?, tx_bytes = ? WHERE public_key = ?", t, rx, tx, pubKey)
		if err != nil {
			slog.Error("Failed to update peer stats", "error", err, "peer", pubKey)
		}
	}
}
