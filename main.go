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
	"sr79-fw/statserver"
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
	tnc := analyzer.NewThreatNetClassifier(config.Topology, config.LearningRate, config.Threshold)
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
			logger.LogSystem(logger.INFO, "Updating Model...")
			tnc.ReloadWeights(config.WeightsPath)
			logger.LogSystem(logger.INFO, "Model Successfully Updated.")
		}
	}()

	// Initialize the Statistics.
	stats := &statistics.Statistics{StartTime: time.Now()}

	// Stats for Terminal output.
	statistics.StartUIRenderEngine(stats)

	// Start the Statistics Server.
	statserver.StartStatServer(stats)

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
				logger.LogSystem(logger.ALERT, fmt.Sprintf("RST injection failed: %v", err))
			}
		}

		statistics.UpdateStatistics(stats, rawSize, verdict == analyzer.Allow)
	}

	// Close the logger.
	logger.StopLogger()
}
