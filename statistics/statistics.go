package statistics

import (
	"fmt"
	"sync"
	"time"
)

// Statistics for UI purpose (mostly).
type Statistics struct {
	StartTime        time.Time
	PacketsProcessed int
	PacketsDropped   int
	Size             float64
	Throughput       float64
	mu               sync.Mutex
}

// Initiate the Stats rendering goroutine.
// Updates after 1 second interval.
func StartUIRenderEngine(stats *Statistics) {

	var lastSize float64 // For throughput calculation.

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			stats.mu.Lock()

			// Throughput update.
			stats.Throughput = stats.Size - lastSize
			lastSize = stats.Size

			// Push to the terminal
			renderUI(stats)

			stats.mu.Unlock()
		}
	}()
}

// UpdateStatistics updates the 'Statistics' struct.
func UpdateStatistics(stats *Statistics, rawSize int, verdict bool) {
	stats.mu.Lock()
	defer stats.mu.Unlock()

	stats.PacketsProcessed++
	stats.Size += float64(rawSize)

	if !verdict {
		stats.PacketsDropped++
	}
}

// renderUI shows the general stats on the terminal. (clears the terminal completely first).
func renderUI(stats *Statistics) {
	fmt.Print("\033[H\033[2J\033[3J")
	fmt.Print("\033[H")
	fmt.Printf("=== [ SR79-FW LIVE MONITOR ] ===\n")
	fmt.Printf("Uptime: %s\n\n", time.Since(stats.StartTime).Round(time.Second))
	fmt.Printf("Total Packets: %-10d | 	Dropped: %-10d\n\n", stats.PacketsProcessed, stats.PacketsDropped)
	fmt.Printf("Throughput: %s/s\n\n", processBytes(stats.Throughput))
	fmt.Printf("Total Size: %s\n\n", processBytes(stats.Size))
	fmt.Printf("=================================\n")
	fmt.Printf("Press Ctrl+C to stop...\n")
}

// processBytes converts a raw byte count into a human-readable string
// with the appropriate unit (B, KB, MB, GB, TB).
func processBytes(size float64) string {
	switch {
	case size < 1000:
		return fmt.Sprintf("%.0f B", size)
	case size < 1000000:
		return fmt.Sprintf("%.2f KB", size/1000)
	case size < 1000000000:
		return fmt.Sprintf("%.2f MB", size/1000000)
	case size < 1000000000000:
		return fmt.Sprintf("%.2f GB", size/1000000000)
	case size < 1000000000000000:
		return fmt.Sprintf("%.2f TB", size/1000000000000)

	default:
		// No unit, just the number itself.
		return fmt.Sprintf("%.2f", size)
	}
}
