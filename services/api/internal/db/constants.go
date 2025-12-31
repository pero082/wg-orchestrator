package db

// DefaultSubnetCIDR is the standard default subnet for WireGuard
// Used as fallback when no subnet is configured in system_config
const DefaultSubnetCIDR = "10.100.0.0/24"

// Default pool configuration
const (
	// MinDiskSpaceMB is minimum required disk space for safe operations
	MinDiskSpaceMB = 100

	// MaxPeersDefault is the default max peers for a /24 subnet
	MaxPeersDefault = 254

	// WriteThresholdForMigration is writes/sec that triggers migration alert
	WriteThresholdForMigration = 500
)
