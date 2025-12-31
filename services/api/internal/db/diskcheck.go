package db

import (
	"syscall"
)

// CheckDiskSpace validates available disk space before write operations
// Returns error if available space is below required MB
func CheckDiskSpace(path string, requiredMB int64) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return err
	}
	
	availMB := int64(stat.Bavail*uint64(stat.Bsize)) / 1024 / 1024
	if availMB < requiredMB {
		return &DiskSpaceError{
			Required:  requiredMB,
			Available: availMB,
		}
	}
	return nil
}

// DiskSpaceError indicates insufficient disk space
type DiskSpaceError struct {
	Required  int64
	Available int64
}

func (e *DiskSpaceError) Error() string {
	return "insufficient disk space"
}

// DefaultDiskCheckMB is the minimum required MB for safe operations
const DefaultDiskCheckMB = 100
