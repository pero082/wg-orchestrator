package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

type Config struct {
	DBPath          string
	Port            string
	MasterKeyPath   string
	WGConfigPath    string
	WGPublicKeyPath string
	TriggerFile     string
	ClientsDir      string
}

var globalConfig *Config

func Load() *Config {
	globalConfig = &Config{
		DBPath:          getEnv("SAMNET_DB_PATH", "/var/lib/samnet-wg/samnet.db"),
		Port:            getEnv("PORT", "8766"),
		MasterKeyPath:   getEnv("MASTER_KEY_PATH", "/var/lib/samnet-wg/master.key"),
		WGConfigPath:    getEnv("WG_CONFIG_PATH", "/etc/wireguard/wg0.conf"),
		WGPublicKeyPath: getEnv("WG_PUBKEY_PATH", "/etc/wireguard/publickey"),
		TriggerFile:     getEnv("TRIGGER_FILE", "/var/lib/samnet-wg/reconcile.trigger"),
		ClientsDir:      getEnv("CLIENTS_DIR", "/opt/samnet/clients"),
	}
	return globalConfig
}

func Get() *Config {
	if globalConfig == nil {
		return Load()
	}
	return globalConfig
}

func (c *Config) Validate() error {
	dir := filepath.Dir(c.DBPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("cannot create DB directory %s: %w", dir, err)
	}

	port, err := strconv.Atoi(c.Port)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port: %s (must be 1-65535)", c.Port)
	}

	return nil
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
