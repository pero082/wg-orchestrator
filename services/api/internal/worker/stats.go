package worker

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

// SystemStats represents the live system metrics
type SystemStats struct {
	CPUPercent     float64 `json:"cpu_percent"`
	RAMPercent     float64 `json:"ram_percent"`
	RAMUsedMB      int64   `json:"ram_used_mb"`
	RAMTotalMB     int64   `json:"ram_total_mb"`
	NetworkRX      int64   `json:"network_rx_bps"`
	NetworkTX      int64   `json:"network_tx_bps"`
	CPUTempC       float64 `json:"cpu_temp_c"`
	UptimeSeconds  int64   `json:"uptime_seconds"`
	DiskPercent    float64 `json:"disk_percent"`
}

var (
	currentStats SystemStats
	statsMutex   sync.RWMutex
	
	// Previous state for delta calculations
	prevIdle   int64
	prevTotal  int64
	prevRX     int64
	prevTX     int64
	firstRun   = true
)

// GetSystemStats returns the latest cached system stats safely
func GetSystemStats() SystemStats {
	statsMutex.RLock()
	defer statsMutex.RUnlock()
	return currentStats
}

// StatsWorker collects system metrics every second
func StatsWorker() {
	ticker := time.NewTicker(1 * time.Second)
	for range ticker.C {
		collectStats()
	}
}

func collectStats() {
	newStats := SystemStats{}

	// 1. CPU Usage (Stateful calculation)
	if data, err := os.ReadFile("/proc/stat"); err == nil {
		lines := strings.Split(string(data), "\n")
		if len(lines) > 0 {
			fields := strings.Fields(lines[0])
			if len(fields) >= 5 {
				var user, nice, system, idle int64
				fmt.Sscanf(fields[1], "%d", &user)
				fmt.Sscanf(fields[2], "%d", &nice)
				fmt.Sscanf(fields[3], "%d", &system)
				fmt.Sscanf(fields[4], "%d", &idle)
				
				total := user + nice + system + idle
				
				if !firstRun {
					deltaIdle := idle - prevIdle
					deltaTotal := total - prevTotal
					
					if deltaTotal > 0 {
						usage := 100.0 * (1.0 - float64(deltaIdle)/float64(deltaTotal))
						newStats.CPUPercent = usage
					}
				}
				
				prevIdle = idle
				prevTotal = total
			}
		}
	}

	// 2. RAM Usage
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		var memTotal, memAvailable int64
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				fmt.Sscanf(line, "MemTotal: %d kB", &memTotal)
			} else if strings.HasPrefix(line, "MemAvailable:") {
				fmt.Sscanf(line, "MemAvailable: %d kB", &memAvailable)
			}
		}
		if memTotal > 0 {
			memUsed := memTotal - memAvailable
			newStats.RAMPercent = float64(memUsed) / float64(memTotal) * 100
			newStats.RAMUsedMB = memUsed / 1024
			newStats.RAMTotalMB = memTotal / 1024
		}
	}

	// 3. Network Rate (Stateful calculation)
	if data, err := os.ReadFile("/proc/net/dev"); err == nil {
		var totalRX, totalTX int64
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			// Monitor common network interfaces: wg0, eth0, eno1, ens*, enp*
			if strings.HasPrefix(line, "wg0:") || 
			   strings.HasPrefix(line, "eth0:") || 
			   strings.HasPrefix(line, "eno1:") || 
			   strings.HasPrefix(line, "ens") || 
			   strings.HasPrefix(line, "enp") {
				fields := strings.Fields(line)
				if len(fields) >= 10 {
					var rx, tx int64
					fmt.Sscanf(fields[1], "%d", &rx)
					fmt.Sscanf(fields[9], "%d", &tx)
					totalRX += rx
					totalTX += tx
				}
			}
		}
		
		if !firstRun {
			// Bytes per second (since ticker is 1s)
			newStats.NetworkRX = totalRX - prevRX
			newStats.NetworkTX = totalTX - prevTX
			// Prevent negative spikes if counters reset
			if newStats.NetworkRX < 0 { newStats.NetworkRX = 0 }
			if newStats.NetworkTX < 0 { newStats.NetworkTX = 0 }
		}
		
		prevRX = totalRX
		prevTX = totalTX
	}

	// 4. CPU Temp
	// Try multiple common paths
	tempPaths := []string{
		"/sys/class/thermal/thermal_zone0/temp",
		"/sys/devices/virtual/thermal/thermal_zone0/temp",
	}
	for _, path := range tempPaths {
		if data, err := os.ReadFile(path); err == nil {
			var tempMilli int64
			fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &tempMilli)
			newStats.CPUTempC = float64(tempMilli) / 1000.0
			break
		}
	}

	// 5. Uptime
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		var uptimeSeconds float64
		fmt.Sscanf(strings.TrimSpace(string(data)), "%f", &uptimeSeconds)
		newStats.UptimeSeconds = int64(uptimeSeconds)
	}

	// 6. Disk Usage
	if data, err := os.ReadFile("/proc/mounts"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "/" {
				var statfs syscall.Statfs_t
				if syscall.Statfs("/", &statfs) == nil {
					total := statfs.Blocks * uint64(statfs.Bsize)
					free := statfs.Bfree * uint64(statfs.Bsize)
					if total > 0 {
						used := total - free
						newStats.DiskPercent = float64(used) / float64(total) * 100
					}
				}
				break
			}
		}
	}

	// Update atomically
	statsMutex.Lock()
	currentStats = newStats
	statsMutex.Unlock()
	
	firstRun = false
}
