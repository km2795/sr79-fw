package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sr79-fw/analyzer"
	"sr79-fw/config"
	"sr79-fw/logger"
	"sr79-fw/responder"
	"sr79-fw/sniffer"
	"sync"
	"syscall"
	"time"
)

type Statistics struct {
	StartTime        time.Time
	PacketsProcessed int
	PacketsDropped   int
	Size             float64
	Throughput       float64
	mu               sync.Mutex
}

func main() {
	// Load configurations from file.
	config, err := config.Load("config.json")
	if err != nil {
		fmt.Printf("Error loading configurations: %v. Exiting...\n", err)
		return
	}

	if len(config.DeviceInterface) < 1 {
		fmt.Println("No Device Interface Configuration Entered. Exiting...")
		return
	}

	// ---- INITIATE SNIFFER. ---- //
	packetSource, err := sniffer.Start(config.DeviceInterface)
	if err != nil {
		fmt.Printf("Error Initiating Sniffer: %v. Exiting...", err)
		return
	}

	// ---- LOAD CLASSIFIER (RULE BASED CLASSIFIER) ---- //
	c := analyzer.RuleClassifier{}

	// ---- LOAD THREAT NET (ANN BASED CLASSIFIER) ---- //
	tnc := analyzer.NewThreatNetClassifier(config.Topology, config.Threshold)
	tnc.InitializeThreatNet(config.WeightsPath)

	// ---- PACKET RECEIVING CHANNEL LOOP ---- //
	packetChannel := sniffer.ProcessPackets(packetSource)

	// Initialize the logger.
	logger.StartLogger(true)

	// ---- GRACEFUL SHUTDOWN MECHANISM ---- //
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// To flush the last entries before closing the logger.
	done := make(chan struct{})

	go func() {
		<-sigChan
		fmt.Println("\nShutting down sr79-fw")
		packetSource.Close()
		close(done)
	}()

	// ---- UPDATE WEIGHTS USER SIGNAL ---- //
	updateWeightsChan := make(chan os.Signal, 1)
	signal.Notify(updateWeightsChan, syscall.SIGUSR1)

	go func() {
		for range updateWeightsChan {
			fmt.Printf("\n\nUpdating Model...\n\n")
			tnc.ReloadWeights(config.WeightsPath)
			log.Println("Model Successfully Updated.")
		}
	}()

	stats := &Statistics{StartTime: time.Now()}

	var lastSize float64 // For throughput calculation.

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			stats.mu.Lock()

			stats.Throughput = stats.Size - lastSize
			lastSize = stats.Size
			renderUI(stats)

			stats.mu.Unlock()
		}
	}()

	tracker := analyzer.NewConnectionTracker(5.0)

	// Loop over the gopacket.Packet channel and invoke Analyze() on the packet.
	for packet := range packetChannel {
		// Track size from raw packet (for statistics only).
		rawSize := packet.Metadata().CaptureInfo.CaptureLength

		finalPacket := analyzer.ConvertPacket(packet)
		verdict := analyzer.Analyze(&c, tracker, finalPacket)

		// If the Rule based classifier does not detect anomaly, let the packet pass through ThreatNet.
		if verdict == analyzer.Allow {
			verdict = analyzer.Analyze(tnc, tracker, finalPacket)
		}

		// Drop
		if verdict == analyzer.Drop {
			if err := responder.SendReset(packetSource.Handle(), packet); err != nil {
				log.Printf("RST injection failed: %v", err)
			}
		}

		updateStatistics(stats, rawSize, finalPacket, verdict == analyzer.Allow)
	}

	// End.
	<-done
}

func updateStatistics(stats *Statistics, rawSize int, packet *analyzer.Packet, verdict bool) {
	stats.mu.Lock()
	defer stats.mu.Unlock()

	stats.PacketsProcessed++
	stats.Size += float64(rawSize)

	if packet != nil && !verdict {
		stats.PacketsDropped++
	}

}

func renderUI(stats *Statistics) {
	fmt.Print("\033[H\033[2J\033[3J")
	fmt.Print("\033[H")
	fmt.Println("=== [ SR79-FW LIVE MONITOR ] ===")
	fmt.Printf("Uptime: %s\n", time.Since(stats.StartTime).Round(time.Second))
	fmt.Printf("Total Packets: %-10d | Dropped: %-10d\n", stats.PacketsProcessed, stats.PacketsDropped)
	fmt.Printf("Throughput: %s/s\n", processBytes(stats.Throughput))
	fmt.Printf("Total Size: %s\n", processBytes(stats.Size))
	fmt.Println("=================================")
	fmt.Println("Press Ctrl+C to stop...")
}

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
		return fmt.Sprintf("%.2f", size)
	}
}
