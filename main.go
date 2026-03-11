package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sr79-fw/analyzer"
	"sr79-fw/config"
	"sr79-fw/responder"
	"sr79-fw/sniffer"
	"syscall"
)

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

	// ---- GRACEFUL SHUTDOWN MECHANISM ---- //
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nShutting down sr79-fw")
		packetSource.Close()
		os.Exit(0)
	}()

	// ---- UPDATE WEIGHTS USER SIGNAL ---- //
	updateWeightsChan := make(chan os.Signal, 1)
	signal.Notify(updateWeightsChan, syscall.SIGUSR1)

	go func() {
		<-updateWeightsChan
		fmt.Printf("\n\nUpdating Model...\n\n")
		tnc.ReloadWeights(config.WeightsPath)
		log.Println("Model Successfully Updated.")
	}()

	tracker := analyzer.NewConnectionTracker(5.0)

	// Loop over the gopacket.Packet channel and invoke Analyze() on the packet.
	for packet := range packetChannel {
		verdict := analyzer.Analyze(&c, tracker, packet)

		// If the Rule based classifier does not detect anomaly, let the packet pass through ThreatNet.
		if verdict == analyzer.Allow {
			verdict = analyzer.Analyze(tnc, tracker, packet)
		}

		// Drop
		if verdict == analyzer.Drop {
			if err := responder.SendReset(packetSource.Handle(), packet); err != nil {
				log.Printf("RST injection failed: %v", err)
			}
		}
	}

}
