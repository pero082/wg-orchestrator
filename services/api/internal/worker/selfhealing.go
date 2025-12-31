package worker

import (
	"database/sql"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// SelfHealingWorker monitors system health and auto-recovers failed components
func SelfHealingWorker(db *sql.DB) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {

		checkWireGuard()

		checkDockerContainers()

		checkDatabaseHealth(db)

		checkFirewallState()
	}

}

func checkWireGuard() {
	out, err := exec.Command("wg", "show", "wg0").Output()
	if err != nil || len(out) == 0 {
		slog.Warn("WireGuard interface down, attempting recovery...")
		exec.Command("systemctl", "restart", "wg-quick@wg0").Run()
		slog.Info("WireGuard restart triggered")
	}
}

func checkDockerContainers() {
	containers := []string{"samnet-api", "samnet-ui"}
	for _, c := range containers {
		out, _ := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", c).Output()
		if strings.TrimSpace(string(out)) != "true" {
			slog.Warn("Container not running, restarting", "container", c)
			exec.Command("docker", "restart", c).Run()
		}
	}
}

func checkDatabaseHealth(db *sql.DB) {
	if err := db.Ping(); err != nil {
		slog.Error("Database ping failed", "error", err)
	}
}

func checkFirewallState() {
	out, err := exec.Command("nft", "list", "table", "inet", "filter").Output()
	if err != nil || len(out) == 0 {
		slog.Warn("Firewall rules missing, reapplying...")
		exec.Command("nft", "-f", "/etc/nftables.conf").Run()
	}
}
