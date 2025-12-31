package reconcile

import (
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/SamNet-dev/wg-orchestrator/services/api/internal/config"
)

// Trigger updates the timestamp of the trigger file to signal systemd.
// Uses file locking to prevent race conditions with concurrent requests.
func Trigger() {
	triggerFile := config.Get().TriggerFile
	dir := filepath.Dir(triggerFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		slog.Error("Failed to create trigger directory", "error", err)
		return
	}

	// Open with secure permissions (0600, not world-writable)
	file, err := os.OpenFile(triggerFile, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		slog.Error("Failed to open reconcile trigger", "error", err)
		return
	}
	defer file.Close()

	// Acquire exclusive lock (blocks if another process holds lock)
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		slog.Error("Failed to acquire file lock", "error", err)
		return
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)

	now := time.Now()
	if err := os.Chtimes(triggerFile, now, now); err != nil {
		slog.Error("Failed to update trigger timestamp", "error", err)
	} else {
		slog.Info("Reconciliation triggered")
	}
}

