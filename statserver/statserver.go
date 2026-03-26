package statserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sr79-fw/logger"
	"sr79-fw/statistics"
)

const PORT string = ":8080"

// StartStatServer exposes statistics to a web based
// dashboard.
func StartStatServer(stats *statistics.Statistics) {

	go func() {
		server := http.NewServeMux()
		server.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
			// Get a safe copy of the statistics.
			statsCopy := stats.Snapshot()

			// JSON to be passed.
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(&statsCopy)
		})

		logger.LogSystem(logger.INFO, "Stats Server Started...")

		err := http.ListenAndServe(PORT, server)
		if err != nil {
			logger.LogSystem(logger.ALERT, fmt.Sprintf("Error Starting Stats Server: %v", err))
		}
	}()
}
