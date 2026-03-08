package analyzer

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
}

func NewThreatNetClassifier(topology []int, threshold float64) *ThreatNetClassifier {
	return &ThreatNetClassifier{
		net: NewThreatNet(topology, threshold),
	}
}

func (tnc *ThreatNetClassifier) Classify(p *Packet) bool {
	// Normalize the input.
	input := packetToInputVector(p)

	// Feed-forward the network.
	output := tnc.net.forward(input)

	// Compare the result to the threshold
	return output >= tnc.net.threshold
}
