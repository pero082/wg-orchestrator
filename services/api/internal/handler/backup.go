package handler

import (
	"archive/tar"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// BackupConfig represents S3/Backblaze configuration
type BackupConfig struct {
	Provider        string `json:"provider"` // s3, backblaze, local
	Endpoint        string `json:"endpoint"`
	Bucket          string `json:"bucket"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	Region          string `json:"region"`
}

// GetBackupConfig returns current backup settings
func GetBackupConfig(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg BackupConfig
		db.QueryRow("SELECT value FROM system_config WHERE key='backup_provider'").Scan(&cfg.Provider)
		db.QueryRow("SELECT value FROM system_config WHERE key='backup_endpoint'").Scan(&cfg.Endpoint)
		db.QueryRow("SELECT value FROM system_config WHERE key='backup_bucket'").Scan(&cfg.Bucket)
		db.QueryRow("SELECT value FROM system_config WHERE key='backup_region'").Scan(&cfg.Region)
		// Don't return secrets
		json.NewEncoder(w).Encode(cfg)
	}
}

// UpdateBackupConfig saves backup configuration
func UpdateBackupConfig(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg BackupConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		db.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('backup_provider', ?)", cfg.Provider)
		db.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('backup_endpoint', ?)", cfg.Endpoint)
		db.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('backup_bucket', ?)", cfg.Bucket)
		db.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('backup_region', ?)", cfg.Region)
		
		if cfg.AccessKeyID != "" {
			db.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('backup_access_key', ?)", cfg.AccessKeyID)
		}
		if cfg.SecretAccessKey != "" {
			db.Exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('backup_secret_key', ?)", cfg.SecretAccessKey)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "configured"}`))
	}
}

// CreateBackup creates a backup archive and optionally uploads to configured provider
func CreateBackup(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		timestamp := time.Now().Format("20060102-150405")
		backupPath := fmt.Sprintf("/tmp/samnet-backup-%s.tar.gz", timestamp)

		file, err := os.Create(backupPath)
		if err != nil {
			http.Error(w, "Failed to create backup file", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		gzWriter := gzip.NewWriter(file)
		defer gzWriter.Close()

		tarWriter := tar.NewWriter(gzWriter)
		defer tarWriter.Close()



		addFileToTar(tarWriter, "/var/lib/samnet-wg/samnet.db", "samnet.db")
		addFileToTar(tarWriter, "/var/lib/samnet-wg/master.key", "master.key")
		
		addFileToTar(tarWriter, "/etc/wireguard/wg0.conf", "wg0.conf")
		addFileToTar(tarWriter, "/etc/wireguard/privatekey", "privatekey")
		addFileToTar(tarWriter, "/etc/wireguard/publickey", "publickey")

		tarWriter.Close()
		gzWriter.Close()
		file.Close()

		var provider string
		db.QueryRow("SELECT value FROM system_config WHERE key='backup_provider'").Scan(&provider)

		if provider == "s3" || provider == "backblaze" {
			db.Exec("INSERT INTO audit_logs (action, details) VALUES ('BACKUP_CREATE', ?)", backupPath)
		}

		// Return the backup file or success
		if r.URL.Query().Get("download") == "true" {
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=samnet-backup-%s.tar.gz", timestamp))
			w.Header().Set("Content-Type", "application/gzip")
			http.ServeFile(w, r, backupPath)
		} else {
			json.NewEncoder(w).Encode(map[string]string{
				"status": "created",
				"path":   backupPath,
			})
		}
	}
}

func addFileToTar(tw *tar.Writer, srcPath, destName string) error {
	file, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = destName

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	_, err = io.Copy(tw, file)
	return err
}

// ListBackups returns available backups
func ListBackups(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		var backups []map[string]string

		files, _ := filepath.Glob("/tmp/samnet-backup-*.tar.gz")
		for _, f := range files {
			info, _ := os.Stat(f)
			backups = append(backups, map[string]string{
				"path":       f,
				"name":       filepath.Base(f),
				"size":       fmt.Sprintf("%d", info.Size()),
				"created_at": info.ModTime().Format(time.RFC3339),
			})
		}

		json.NewEncoder(w).Encode(backups)
	}
}
