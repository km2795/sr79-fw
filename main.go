package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sr79-fw/analyzer"
	"sr79-fw/responder"
	"sr79-fw/sniffer"
	"syscall"
)

func main() {
	// ---- HANDLING USER INPUT ---- //

	fmt.Println("Please Enter Network Interface Configuration: (eth0, wlp2s0, ...)")

	// Device Interface Configuration.
	var deviceInterface string

	// Accept user input for the dev interface configuration.
	fmt.Scan(&deviceInterface)

	if len(deviceInterface) < 1 {
		fmt.Println("No Device Interface Configuration Entered. Exiting...")
		return
	}

	// ---- INITIATE SNIFFER. ---- //
	packetSource, err := sniffer.Start(deviceInterface)
	if err != nil {
		fmt.Printf("Error Initiating Sniffer: %v. Exiting...", err)
		return
	}

	// ---- LOAD CLASSIFIER (RULE BASED CLASSIFIER) ---- //
	c := analyzer.RuleClassifier{}

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

	tracker := analyzer.NewConnectionTracker(5.0)

	// Loop over the gopacket.Packet channel and invoke Analyze() on the packet.
	for packet := range packetChannel {
		verdict := analyzer.Analyze(&c, tracker, packet)

		// Drop
		if verdict == analyzer.Drop {
			if err := responder.SendReset(packetSource.Handle(), packet); err != nil {
				log.Printf("RST injection failed: %v", err)
			}
		}
	}

}
