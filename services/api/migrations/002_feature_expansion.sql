-- SamNet-WG Database Migrations for Feature Expansion
-- Version: 2.0.0

-- MFA Support
ALTER TABLE users ADD COLUMN totp_secret TEXT;
ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN auth_provider TEXT DEFAULT 'local';
ALTER TABLE users ADD COLUMN email TEXT;

-- Peer Expiry & Scheduling
ALTER TABLE peers ADD COLUMN expires_at DATETIME;
ALTER TABLE peers ADD COLUMN disabled INTEGER DEFAULT 0;
ALTER TABLE peers ADD COLUMN last_endpoint TEXT;

-- Peer Groups/Tags
CREATE TABLE IF NOT EXISTS peer_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    color TEXT DEFAULT '#f97316',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS peer_group_members (
    peer_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    PRIMARY KEY (peer_id, group_id),
    FOREIGN KEY (peer_id) REFERENCES peers(id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES peer_groups(id) ON DELETE CASCADE
);

-- Peer Schedules (Time-based access)
CREATE TABLE IF NOT EXISTS peer_schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id INTEGER NOT NULL,
    day_of_week INTEGER NOT NULL, -- 0=Sunday, 6=Saturday
    start_hour INTEGER NOT NULL,  -- 0-23
    end_hour INTEGER NOT NULL,    -- 0-23
    FOREIGN KEY (peer_id) REFERENCES peers(id) ON DELETE CASCADE
);

-- Notification Queue
CREATE TABLE IF NOT EXISTS notification_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel TEXT NOT NULL,        -- telegram, discord, webhook
    webhook_url TEXT NOT NULL,
    message TEXT NOT NULL,
    sent INTEGER DEFAULT 0,
    sent_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Notification Settings
CREATE TABLE IF NOT EXISTS notification_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel TEXT NOT NULL,
    webhook_url TEXT NOT NULL,
    events TEXT NOT NULL,         -- JSON array: ["login", "peer_create", "alert"]
    enabled INTEGER DEFAULT 1
);

-- Traffic History (for graphs)
CREATE TABLE IF NOT EXISTS traffic_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id INTEGER NOT NULL,
    rx_bytes INTEGER DEFAULT 0,
    tx_bytes INTEGER DEFAULT 0,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (peer_id) REFERENCES peers(id) ON DELETE CASCADE
);

-- Create index for fast traffic queries
CREATE INDEX IF NOT EXISTS idx_traffic_peer_time ON traffic_history(peer_id, timestamp);

-- WakeOnLAN Devices
CREATE TABLE IF NOT EXISTS wol_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    mac_address TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Audit Log Extensions
ALTER TABLE audit_logs ADD COLUMN ip_address TEXT;
ALTER TABLE audit_logs ADD COLUMN user_agent TEXT;

-- Feature Flags (for DDNS and other toggleable features)
CREATE TABLE IF NOT EXISTS feature_flags (
    key TEXT PRIMARY KEY,
    enabled INTEGER DEFAULT 0,
    config TEXT,  -- JSON configuration
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert default feature flags
INSERT OR IGNORE INTO feature_flags (key, enabled, config) VALUES ('ddns', 0, '{}');
INSERT OR IGNORE INTO feature_flags (key, enabled, config) VALUES ('mfa_required', 0, '{}');
INSERT OR IGNORE INTO feature_flags (key, enabled, config) VALUES ('exit_node', 0, '{}');

-- Performance Indexes (Critical for 1000+ peers)
CREATE INDEX IF NOT EXISTS idx_peers_public_key ON peers(public_key);
CREATE INDEX IF NOT EXISTS idx_peers_allowed_ips ON peers(allowed_ips);
CREATE INDEX IF NOT EXISTS idx_peers_disabled ON peers(disabled);
CREATE INDEX IF NOT EXISTS idx_peers_expires_at ON peers(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_notification_queue_sent ON notification_queue(sent) WHERE sent = 0;

