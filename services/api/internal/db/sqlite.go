package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteDriver implements Driver for SQLite
type SQLiteDriver struct {
	db      *sql.DB
	path    string
	counter *WriteCounter
}

// NewSQLiteDriver creates a new SQLite driver
func NewSQLiteDriver(path string) *SQLiteDriver {
	return &SQLiteDriver{
		path:    path,
		counter: NewWriteCounter(),
	}
}

func (d *SQLiteDriver) Connect() error {
	dir := filepath.Dir(d.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create database directory: %w", err)
	}

	db, err := sql.Open("sqlite", d.path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(MaxOpenConns)
	db.SetMaxIdleConns(MaxIdleConns)
	db.SetConnMaxLifetime(ConnMaxLifetime)

	// WAL mode for concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		return fmt.Errorf("failed to set WAL mode: %w", err)
	}

	if _, err := db.Exec(fmt.Sprintf("PRAGMA busy_timeout=%d;", BusyTimeout)); err != nil {
		return fmt.Errorf("failed to set busy timeout: %w", err)
	}

	if _, err := db.Exec("PRAGMA foreign_keys=ON;"); err != nil {
		return fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	d.db = db
	return nil
}

func (d *SQLiteDriver) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}

func (d *SQLiteDriver) Ping(ctx context.Context) error {
	return d.db.PingContext(ctx)
}

func (d *SQLiteDriver) Query(query string, args ...any) (*sql.Rows, error) {
	return d.db.Query(query, args...)
}

func (d *SQLiteDriver) QueryRow(query string, args ...any) *sql.Row {
	return d.db.QueryRow(query, args...)
}

func (d *SQLiteDriver) Exec(query string, args ...any) (sql.Result, error) {
	d.counter.Increment()
	return d.db.Exec(query, args...)
}

func (d *SQLiteDriver) Begin() (*sql.Tx, error) {
	return d.db.Begin()
}

func (d *SQLiteDriver) GetWriteMetrics() WriteMetrics {
	return d.counter.GetMetrics()
}

func (d *SQLiteDriver) RawDB() *sql.DB {
	return d.db
}

// StartMetricsReset resets window every minute for accurate WPS
func (d *SQLiteDriver) StartMetricsReset(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				d.counter.ResetWindow()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// ExportToSQL exports all data for migration with SQL injection protection
func (d *SQLiteDriver) ExportToSQL(outputPath string) error {
	// Disk space check before export (needs ~2x DB size)
	if err := CheckDiskSpace(outputPath, 50); err != nil { // Min 50MB for export
		return fmt.Errorf("insufficient disk space for export: %w", err)
	}

	// Whitelist of allowed tables - SQL injection prevention
	allowedTables := map[string]bool{
		"users": true, "sessions": true, "peers": true,
		"audit_logs": true, "system_config": true, "feature_flags": true,
		"ip_pool": true, "peer_settings": true, "schema_version": true,
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	for table := range allowedTables {
		rows, err := d.db.Query("SELECT * FROM " + table)
		if err != nil {
			continue // Table might not exist
		}
		
		cols, _ := rows.Columns()
		f.WriteString(fmt.Sprintf("-- %s\n", table))
		
		values := make([]interface{}, len(cols))
		valuePtrs := make([]interface{}, len(cols))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		for rows.Next() {
			if err := rows.Scan(valuePtrs...); err != nil {
				continue
			}
			f.WriteString(fmt.Sprintf("INSERT INTO %s VALUES (", table))
			for i, v := range values {
				if i > 0 {
					f.WriteString(", ")
				}
				switch val := v.(type) {
				case nil:
					f.WriteString("NULL")
				case string:
					// Escape single quotes to prevent SQL injection
					escaped := strings.ReplaceAll(val, "'", "''")
					f.WriteString(fmt.Sprintf("'%s'", escaped))
				case []byte:
					escaped := strings.ReplaceAll(string(val), "'", "''")
					f.WriteString(fmt.Sprintf("'%s'", escaped))
				default:
					f.WriteString(fmt.Sprintf("%v", val))
				}
			}
			f.WriteString(");\n")
		}
		rows.Close()
	}

	return nil
}
