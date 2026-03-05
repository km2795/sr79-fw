package logger

import (
	"fmt"
	"time"
)

type LogLevel string

const (
	LOG   LogLevel = "LOG"
	INFO  LogLevel = "INFO"
	ALERT LogLevel = "ALERT"
)

type LogEntry struct {
	Timestamp   time.Time
	Level       LogLevel
	Classifier  string
	Source      string
	Destination string
	TCPFlags    string
	PacketRate  float64
	Verdict     string
}

func Log(entry LogEntry) {
	fmt.Printf("[%s] [%s] [%s] [%s -> %s] FLAGS: %s RATE: %.2f VERDICT: %s\n",
		entry.Timestamp.Format("02-01-2006 15:04:05"),
		entry.Level,
		entry.Classifier,
		entry.Source,
		entry.Destination,
		entry.TCPFlags,
		entry.PacketRate,
		entry.Verdict)
}
