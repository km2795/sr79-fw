package main

import (
	"fmt"
	"sr79-fw/analyzer"
	"sr79-fw/sniffer"
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

	// Loop over the gopacket.Packet channel and invoke Analyze() on the packet.
	for packet := range packetChannel {
		verdict := analyzer.Analyze(&c, packet)

		// Drop
		if verdict == analyzer.Drop {

			// Allow.
		} else {
		}
	}

}
