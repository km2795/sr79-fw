package analyzer

import (
	"fmt"
	"sync"
	"time"
)

// For each connection, its statistics.
type ConnectionState struct {
	Score    float64
	LastSeen time.Time
}

// Tracker, Actual.
// 'connections' are represented as "SrcIP:SrcPort -> DstIP:DstPort"
// 'threshold' is set once for the tracker, same for all the connections.
type ConnectionTracker struct {
	mu          sync.Mutex
	connections map[string]*ConnectionState
	threshold   float64
}

// Constructor for ConnectionTracker.
func NewConnectionTracker(threshold float64) *ConnectionTracker {
	return &ConnectionTracker{
		connections: make(map[string]*ConnectionState),
		threshold:   threshold,
	}
}

func (ct *ConnectionTracker) Track(packet *Packet, dropped bool) bool {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	connectionKey := fmt.Sprintf("%s:%d->%s:%d", packet.SrcIp, packet.SrcPort, packet.DestIp, packet.DestPort)

	// Fetch the connection requested.
	state, exists := ct.connections[connectionKey]

	// Create one, if not exists.
	if !exists {
		state = &ConnectionState{}
		ct.connections[connectionKey] = state
	}

	// Update the stats.
	if dropped {
		state.Score++
		state.LastSeen = time.Now()
	}

	// If the threshold for the tracker is reached or crossed, flag it back to caller.
	if state.Score >= ct.threshold {
		return true
	}

	// Otherwise, return false.
	return false
}

func (ct *ConnectionTracker) cleanup() {
}
