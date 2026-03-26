package main

import (
	"fmt"
	"os"
	"os/signal"
	"sr79-fw/analyzer"
	"sr79-fw/logger"
	"sr79-fw/sniffer"
	"syscall"
)

// SetupSignal sets up and handles the signals for graceful shutdown and
// model update.
func SetupSignals(weightsPath string, classifier *analyzer.ThreatNetClassifier, packetSource *sniffer.PacketSource) {

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)

	go func() {
		for sig := range sigChan {
			switch sig {
			// ---- GRACEFUL SHUTDOWN ----
			case syscall.SIGTERM, syscall.SIGINT:
				fmt.Println("\nShutting down sr79-fw")
				packetSource.Close()

			// ---- MODEL UPDATE SIGNAL ----
			case syscall.SIGUSR1:
				logger.LogSystem(logger.INFO, "User Signal Received: Updating Model...")
				classifier.ReloadWeights(weightsPath)
				logger.LogSystem(logger.INFO, "Model Successfully Updated.")

			}
		}
	}()
}
