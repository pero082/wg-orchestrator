package db

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	MaxOpenConns    = 25
	MaxIdleConns    = 5
	ConnMaxLifetime = 30 * time.Minute
	BusyTimeout     = 10000 // ms
)

func Connect(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Connection pool limits to prevent "too many open files"
	db.SetMaxOpenConns(MaxOpenConns)
	db.SetMaxIdleConns(MaxIdleConns)
	db.SetConnMaxLifetime(ConnMaxLifetime)

	// WAL mode for concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		return nil, fmt.Errorf("failed to set WAL mode: %w", err)
	}

	// Busy timeout to handle concurrent access (retry for 5s instead of immediate error)
	if _, err := db.Exec(fmt.Sprintf("PRAGMA busy_timeout=%d;", BusyTimeout)); err != nil {
		return nil, fmt.Errorf("failed to set busy timeout: %w", err)
	}

	if _, err := db.Exec("PRAGMA foreign_keys=ON;"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	if err := ensureIndexes(db); err != nil {
		return nil, fmt.Errorf("failed to ensure indexes: %w", err)
	}

	return db, nil
}

func ensureIndexes(db *sql.DB) error {
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);",
		"CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);",
		"CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);",
		"CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);",
		"CREATE INDEX IF NOT EXISTS idx_peers_public_key ON peers(public_key);",
		"CREATE INDEX IF NOT EXISTS idx_peers_name ON peers(name);",
		"CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);",
		"CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);",
	}

	for _, idx := range indexes {
		if _, err := db.Exec(idx); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	// Create ip_pool table if not exists (for atomic IP allocation)
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS ip_pool (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			allocated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		return fmt.Errorf("failed to create ip_pool table: %w", err)
	}

	// Ensure unique constraint on public_key
	// SQLite doesn't support ALTER TABLE ADD CONSTRAINT, so we check at runtime
	// The constraint is enforced in handler/peer.go via duplicate key detection

	return nil
}

// CleanupOldSessions removes expired sessions (call from background worker)
func CleanupOldSessions(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP")
	return err
}

// CleanupOldAuditLogs keeps last 90 days of audit logs (call from background worker)
func CleanupOldAuditLogs(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM audit_logs WHERE created_at < datetime('now', '-90 days')")
	return err
}

// RunMaintenance performs DB maintenance tasks
func RunMaintenance(db *sql.DB) {
	CleanupOldSessions(db)
	CleanupOldAuditLogs(db)
	db.Exec("PRAGMA optimize;")
	db.Exec("PRAGMA wal_checkpoint(TRUNCATE);")
}

// RunMigrations applies SQL migrations from migrations directory incrementally
func RunMigrations(dbPath string) error {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open DB for migrations: %w", err)
	}
	defer db.Close()

	// Ensure schema_version table exists
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at DATETIME DEFAULT CURRENT_TIMESTAMP)`)
	if err != nil {
		return fmt.Errorf("failed to create schema_version table: %w", err)
	}

	var currentVersion int
	err = db.QueryRow("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1").Scan(&currentVersion)
	if err != nil {
		if err == sql.ErrNoRows {
			currentVersion = 0
		} else {
			return fmt.Errorf("failed to check current schema version: %w", err)
		}
	}

	migrationFiles, err := filepath.Glob("migrations/*.sql")
	if err != nil {
		return fmt.Errorf("failed to list migrations: %w", err)
	}

	for _, file := range migrationFiles {
		base := filepath.Base(file)
		var fileVersion int
		fmt.Sscanf(base, "%d", &fileVersion)

		if fileVersion > currentVersion {
			slog.Info("Applying migration", "file", base, "version", fileVersion)
			sqlBytes, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("failed to read migration %s: %w", base, err)
			}

			tx, err := db.Begin()
			if err != nil {
				return err
			}

			if _, err := tx.Exec(string(sqlBytes)); err != nil {
				// Ignore "duplicate column name" errors - these mean the column already exists
				// This makes migrations idempotent (safe to run multiple times)
				if !strings.Contains(err.Error(), "duplicate column name") {
					tx.Rollback()
					return fmt.Errorf("failed to apply migration %s: %w", base, err)
				}
				// Column already exists, continue with migration tracking
			}

			if _, err := tx.Exec("INSERT INTO schema_version (version) VALUES (?)", fileVersion); err != nil {
				tx.Rollback()
				return fmt.Errorf("failed to update schema version for %s: %w", base, err)
			}

			if err := tx.Commit(); err != nil {
				return err
			}
		}
	}

	return nil
}
// ValidateSchema ensures all required tables exist and are accessible
func ValidateSchema(db *sql.DB) error {
	requiredTables := []string{
		"users", "sessions", "peers", "system_config",
		"audit_logs", "feature_flags", "ip_pool",
	}

	for _, table := range requiredTables {
		var name string
		query := fmt.Sprintf("SELECT name FROM sqlite_master WHERE type='table' AND name='%s'", table)
		err := db.QueryRow(query).Scan(&name)
		if err != nil {
			if err == sql.ErrNoRows {
				return fmt.Errorf("required table missing: %s", table)
			}
			return fmt.Errorf("failed to check table %s: %w", table, err)
		}
	}
	return nil
}
