package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

type LogLevel string

const (
	LOG   LogLevel = "LOG"
	INFO  LogLevel = "INFO"
	ALERT LogLevel = "ALERT"
)

type LogEntry struct {
	LogType     byte   // 0 for recurrent log; 1 for non-recurrent log.
	LogText     string // non-recurrent log text.
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

func StartLogger(toFile bool) {
	var writer io.Writer = os.Stdout

	if toFile {
		logFile, err := os.OpenFile("classifier.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		writer = io.MultiWriter(logFile)
	}

	globalLogger = log.New(writer, "", 0)

	go func() {
		for entry := range logChan {
			if entry.LogType == 1 {
				globalLogger.Printf("[%s] [%s] %s | VERDICT: [%s]",
					entry.Timestamp.Format("02-01-2006 15:04:05"),
					entry.Level,
					entry.LogText,
					entry.Verdict)
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
