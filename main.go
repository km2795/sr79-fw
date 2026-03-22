package main

import (
	"fmt"
	"os"
	"os/signal"
	"sr79-fw/analyzer"
	"sr79-fw/config"
	"sr79-fw/logger"
	"sr79-fw/responder"
	"sr79-fw/sniffer"
	"sr79-fw/statistics"
	"syscall"
	"time"
)

func main() {

	// Load configurations from file.
	config, err := config.Load("config.json")
	if err != nil {
		fmt.Printf("Error loading configurations: %v. Exiting...\n", err)
		return
	}

	// Initialize the logger.
	logger.StartLogger()

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
	if err := tnc.InitializeThreatNet(config.WeightsPath); err != nil {
		fmt.Printf("Failed to load weights: %v. Exiting...\n", err)
		return
	}

	// ---- PACKET RECEIVING CHANNEL LOOP ---- //
	packetChannel := sniffer.ProcessPackets(packetSource)

	// ---- GRACEFUL SHUTDOWN MECHANISM ---- //
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nShutting down sr79-fw")
		packetSource.Close()
	}()

	// ---- UPDATE WEIGHTS USER SIGNAL ---- //
	updateWeightsChan := make(chan os.Signal, 1)
	signal.Notify(updateWeightsChan, syscall.SIGUSR1)

	go func() {
		for range updateWeightsChan {
			logger.Log(logger.LogEntry{
				LogCategory: logger.LogTypeSystem,
				Timestamp:   time.Now(),
				Level:       logger.INFO,
				LogText:     "Updating Model...",
			})
			tnc.ReloadWeights(config.WeightsPath)
			logger.Log(logger.LogEntry{
				LogCategory: logger.LogTypeSystem,
				Timestamp:   time.Now(),
				Level:       logger.INFO,
				LogText:     "Model Successfully Updated.",
			})
		}
	}()

	stats := &statistics.Statistics{StartTime: time.Now()}
	statistics.StartUIRenderEngine(stats)

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
				logger.Log(logger.LogEntry{
					LogCategory: logger.LogTypeSystem,
					Timestamp:   time.Now(),
					Level:       logger.ALERT,
					Verdict:     "DROP",
					LogText:     fmt.Sprintf("RST injection failed: %v", err),
				})
			}
		}

		statistics.UpdateStatistics(stats, rawSize, verdict == analyzer.Allow)
	}

	// Close the logger.
	logger.StopLogger()
}
