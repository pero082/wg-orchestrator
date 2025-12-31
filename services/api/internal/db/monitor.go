package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"time"
)

const (
	WriteThresholdDefault = 500
	MonitorInterval       = 5 * time.Second
)

// ScalingMonitor watches write load and logs alerts
type ScalingMonitor struct {
	driver        Driver
	redis         *RedisCache
	threshold     int
	alertCallback func(metrics WriteMetrics)
	ctx           context.Context
	cancel        context.CancelFunc
}

func NewScalingMonitor(driver Driver, threshold int) *ScalingMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &ScalingMonitor{
		driver:    driver,
		threshold: threshold,
		ctx:       ctx,
		cancel:    cancel,
	}
}

func (m *ScalingMonitor) SetAlertCallback(cb func(WriteMetrics)) {
	m.alertCallback = cb
}

func (m *ScalingMonitor) SetRedis(r *RedisCache) {
	m.redis = r
}

func (m *ScalingMonitor) Start() {
	go func() {
		ticker := time.NewTicker(MonitorInterval)
		defer ticker.Stop()

		consecutiveHigh := 0

		for {
			select {
			case <-ticker.C:
				metrics := m.driver.GetWriteMetrics()

				if metrics.TotalWrites%1000 == 0 && metrics.TotalWrites > 0 {
					slog.Info("Database metrics",
						"backend", "sqlite",
						"writes_per_sec", metrics.WritesPerSecond,
						"peak", metrics.PeakWrites,
						"total", metrics.TotalWrites)
				}

				if metrics.WritesPerSecond > float64(m.threshold) {
					consecutiveHigh++
					slog.Warn("High write load detected",
						"wps", metrics.WritesPerSecond,
						"threshold", m.threshold,
						"consecutive", consecutiveHigh)

					if consecutiveHigh >= 3 {
						m.triggerAlert(metrics)
						consecutiveHigh = 0
					}
				} else {
					consecutiveHigh = 0
				}

			case <-m.ctx.Done():
				return
			}
		}
	}()
}

func (m *ScalingMonitor) Stop() {
	m.cancel()
}

func (m *ScalingMonitor) triggerAlert(metrics WriteMetrics) {
	slog.Error("DATABASE ALERT: High write load",
		"current_wps", metrics.WritesPerSecond,
		"threshold", m.threshold,
		"peak_wps", metrics.PeakWrites,
	)

	if db := m.driver.RawDB(); db != nil {
		db.Exec(`INSERT INTO audit_logs (user_id, action, target, details, ip_address) 
			VALUES (0, 'HIGH_LOAD_ALERT', 'database', ?, 'system')`,
			fmt.Sprintf("Write load: %.2f wps (threshold: %d)",
				metrics.WritesPerSecond, m.threshold))
	}

	if m.alertCallback != nil {
		m.alertCallback(metrics)
	}
}

// NewMonitorDriver creates a SQLite driver and connects
func NewMonitorDriver(path string) (Driver, error) {
	driver := NewSQLiteDriver(path)
	if err := driver.Connect(); err != nil {
		return nil, err
	}
	return driver, nil
}

// LoadConfigFromEnv loads database config from environment variables
func LoadConfigFromEnv() Config {
	cfg := DefaultConfig()

	if sqlitePath := os.Getenv("DB_PATH"); sqlitePath != "" {
		cfg.SQLitePath = sqlitePath
	}
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		cfg.RedisURL = redisURL
	}

	return cfg
}

// ConnectWithMetrics returns *sql.DB with metrics enabled
func ConnectWithMetrics(path string) (*sql.DB, error) {
	driver := NewSQLiteDriver(path)
	if err := driver.Connect(); err != nil {
		return nil, err
	}

	ctx := context.Background()
	driver.StartMetricsReset(ctx)

	return driver.RawDB(), nil
}
