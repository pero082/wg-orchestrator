package db

import (
	"context"
	"database/sql"
	"sync/atomic"
	"time"
)

// WriteMetrics tracks database write performance
type WriteMetrics struct {
	WritesPerSecond float64   `json:"writes_per_second"`
	PeakWrites      int64     `json:"peak_writes"`
	TotalWrites     int64     `json:"total_writes"`
	LastSample      time.Time `json:"last_sample"`
}

// Driver defines the interface for database backends
type Driver interface {
	Connect() error
	Close() error
	Ping(ctx context.Context) error

	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
	Exec(query string, args ...any) (sql.Result, error)
	Begin() (*sql.Tx, error)

	GetWriteMetrics() WriteMetrics
	RawDB() *sql.DB
}

// WriteCounter tracks writes for monitoring
type WriteCounter struct {
	total     atomic.Int64
	window    atomic.Int64
	peak      atomic.Int64
	lastReset atomic.Int64
}

func NewWriteCounter() *WriteCounter {
	w := &WriteCounter{}
	w.lastReset.Store(time.Now().UnixNano())
	return w
}

func (w *WriteCounter) Increment() {
	w.total.Add(1)
	w.window.Add(1)
}

func (w *WriteCounter) GetMetrics() WriteMetrics {
	lastResetNano := w.lastReset.Load()
	elapsed := time.Since(time.Unix(0, lastResetNano)).Seconds()
	if elapsed < 1 {
		elapsed = 1
	}

	windowWrites := w.window.Load()
	wps := float64(windowWrites) / elapsed

	current := int64(wps)
	for {
		peak := w.peak.Load()
		if current <= peak {
			break
		}
		if w.peak.CompareAndSwap(peak, current) {
			break
		}
	}

	return WriteMetrics{
		WritesPerSecond: wps,
		PeakWrites:      w.peak.Load(),
		TotalWrites:     w.total.Load(),
		LastSample:      time.Now(),
	}
}

func (w *WriteCounter) ResetWindow() {
	w.window.Store(0)
	w.lastReset.Store(time.Now().UnixNano())
}

// Config holds database configuration
type Config struct {
	SQLitePath     string
	RedisURL       string
	WriteThreshold int
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		SQLitePath:     "/var/lib/samnet-wg/samnet.db",
		WriteThreshold: 500,
	}
}
