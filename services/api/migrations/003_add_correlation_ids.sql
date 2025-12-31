-- SamNet-WG Database Migrations: Correlation IDs
-- Version: 3.0.0

-- Add request_id to audit_logs for end-to-end traceability
ALTER TABLE audit_logs ADD COLUMN request_id TEXT;

-- Index for fast correlation searches
CREATE INDEX IF NOT EXISTS idx_audit_logs_request_id ON audit_logs(request_id);
