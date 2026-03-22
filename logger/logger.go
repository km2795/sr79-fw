package logger

import (
	"fmt"
	"log"
	"os"
	"time"
)

type LogLevel string
type LogType int

// Log levels.
const (
	LOG   LogLevel = "LOG"
	INFO  LogLevel = "INFO"
	ALERT LogLevel = "ALERT"
)

// Log Type.
const (
	LogTypePacket LogType = 0 // Recurring packet log.
	LogTypeSystem LogType = 1 // Ad-Hoc log. (non-recurring)
)

type LogEntry struct {
	LogCategory LogType // 0 for recurrent log; 1 for non-recurrent log.
	LogText     string  // non-recurrent log text.
	Timestamp   time.Time
	Level       LogLevel
	Classifier  string
	Source      string
	Destination string
	TCPFlags    string
	PacketRate  float64
	Verdict     string
}

var logChan = make(chan LogEntry, 1000)
var globalLogger *log.Logger

func StartLogger() {
	logFile, err := os.OpenFile("classifier.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	globalLogger = log.New(logFile, "", 0)

	go func() {
		for entry := range logChan {
			if entry.LogCategory == LogTypeSystem {
				globalLogger.Printf("[%s] [%s] %s",
					entry.Timestamp.Format("02-01-2006 15:04:05"),
					entry.Level,
					entry.LogText)
			} else {
				globalLogger.Printf("[%s] [%s] [%s] [%s -> %s] FLAGS: %s RATE: %.2f | VERDICT: %s\n",
					entry.Timestamp.Format("02-01-2006 15:04:05"),
					entry.Level,
					entry.Classifier,
					entry.Source,
					entry.Destination,
					entry.TCPFlags,
					entry.PacketRate,
					entry.Verdict)
			}
		}
	}()
}

func Log(entry LogEntry) {
	if globalLogger == nil {
		return
	}
	select {
	case logChan <- entry:
	default:
		fmt.Fprintf(os.Stderr, "WARN: log channel full, dropping entry\n")
	}
}
