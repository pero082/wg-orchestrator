-- Migration: Add historical usage table
-- Captures data usage from deleted peers for auditing

CREATE TABLE IF NOT EXISTS historical_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_name TEXT NOT NULL,
    public_key TEXT,
    rx_bytes INTEGER DEFAULT 0,
    tx_bytes INTEGER DEFAULT 0,
    deleted_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
