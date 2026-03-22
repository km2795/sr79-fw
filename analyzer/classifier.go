package analyzer

import "sync"

// Packet is the representation of a unit piece of network data.
type Packet struct {
	SrcIp      string  // Source IP Address
	DestIp     string  // Destination IP Address
	SrcPort    uint16  // Source Port Address
	DestPort   uint16  // Destination Port Address
	Protocol   string  // Packet Protocol
	Payload    []byte  // Raw Bytes in Packet.
	Size       int     // Total Packet Size (For Stats and Heuristics)
	PacketRate float64 // Packets per second on this connection (Heuristics)
	Flags      TCPFlags
}

// TCP / Control Flags of a packet.
type TCPFlags struct {
	SYN bool // Synchronize
	ACK bool // Acknowledgement
	FIN bool // Finish
	RST bool // Reset
	PSH bool // Push
	URG bool // Urgent
}

type Classifier interface {
	Classify(p *Packet) bool
}

type RuleClassifier struct {
}

func (r *RuleClassifier) Classify(p *Packet) bool {
	return p.Flags.SYN && !p.Flags.ACK
}

type ThreatNetClassifier struct {
	net *ThreatNet
	mu  sync.RWMutex
}

func (tnc *ThreatNetClassifier) InitializeThreatNet(weightsPath string) error {
	return tnc.net.LoadWeights(weightsPath)
}

func (tnc *ThreatNetClassifier) ReloadWeights(path string) {
	tnc.mu.Lock()
	defer tnc.mu.Unlock()

	tnc.net.LoadWeights(path)
}

func NewThreatNetClassifier(topology []int, learningRate float64, threshold float64) *ThreatNetClassifier {
	return &ThreatNetClassifier{
		net: NewThreatNet(topology, learningRate, threshold),
	}
}

func (tnc *ThreatNetClassifier) Classify(p *Packet) bool {
	tnc.mu.RLock()
	defer tnc.mu.RUnlock()

	// Normalize the input.
	input := packetToInputVector(p)

	// Feed-forward the network.
	output := tnc.net.forward(input)

	// Compare the result to the threshold
	return output >= tnc.net.threshold
}
