-- Migration: Add data limit and persistent counters
-- These columns enable bandwidth quotas and data tracking across disable/enable cycles
-- NOTE: This migration is idempotent - it checks for column existence before adding

-- SQLite doesn't have native "ADD COLUMN IF NOT EXISTS", so we use a simple approach:
-- If column already exists, these will fail silently via error handling in Go code.
-- The Go migration runner should catch and ignore "duplicate column name" errors.

-- For fresh databases, these are already in the initial schema.
-- For older databases, this will add the missing columns.
ALTER TABLE peers ADD COLUMN total_rx_bytes INTEGER DEFAULT 0;
ALTER TABLE peers ADD COLUMN total_tx_bytes INTEGER DEFAULT 0;
ALTER TABLE peers ADD COLUMN data_limit_gb INTEGER DEFAULT 0;
ALTER TABLE peers ADD COLUMN expires_at INTEGER;
