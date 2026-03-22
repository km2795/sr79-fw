package analyzer

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"sr79-fw/logger"
	"time"
)

// Verdict is the action to perform on the packet.
type Verdict int

const (
	Allow Verdict = iota // 0
	Drop                 // 1
)

// convertPacket converts the gopacket.Packet implementation
// of a network packet and converts that into our own 'Packet'
// implementation.
func ConvertPacket(gp gopacket.Packet) *Packet {

	packet := &Packet{}

	ipv4Layer := gp.Layer(layers.LayerTypeIPv4)
	ipv6Layer := gp.Layer(layers.LayerTypeIPv6)

	// TCP Layer.
	tcpLayer := gp.Layer(layers.LayerTypeTCP)

	// UDP Layer.
	udpLayer := gp.Layer(layers.LayerTypeUDP)

	// Application Layer.
	applicationLayer := gp.ApplicationLayer()
	if applicationLayer != nil {
		packet.Payload = applicationLayer.Payload()
	}

	// ---- Assert IPV6, IPV4, TCP, UDP Layers and populate ----
	// ---- 'packet' with relevant fields on true. -------

	if ipv4Layer != nil {
		ipv4, ok := ipv4Layer.(*layers.IPv4)
		if !ok {
			return nil
		}
		packet.SrcIp = ipv4.SrcIP.String()
		packet.DestIp = ipv4.DstIP.String()
		packet.Protocol = ipv4.Protocol.String()
		packet.Size = int(ipv4.Length)
	} else if ipv6Layer != nil {
		ipv6, ok := ipv6Layer.(*layers.IPv6)
		if !ok {
			return nil
		}
		packet.SrcIp = ipv6.SrcIP.String()
		packet.DestIp = ipv6.DstIP.String()
		packet.Protocol = ipv6.NextHeader.String()
		packet.Size = int(ipv6.Length)
	} else {
		return nil // neither IPv4 nor IPv6
	}

	if packet.Protocol == "TCP" {
		tcp, ok := tcpLayer.(*layers.TCP)
		if ok {
			packet.SrcPort = uint16(tcp.SrcPort)
			packet.DestPort = uint16(tcp.DstPort)
			packet.Flags.SYN = tcp.SYN
			packet.Flags.ACK = tcp.ACK
			packet.Flags.FIN = tcp.FIN
			packet.Flags.RST = tcp.RST
			packet.Flags.PSH = tcp.PSH
			packet.Flags.URG = tcp.URG
		} else {
			return nil
		}
	} else {
		udp, ok := udpLayer.(*layers.UDP)
		if ok {
			packet.SrcPort = uint16(udp.SrcPort)
			packet.DestPort = uint16(udp.DstPort)
		} else {
			return nil
		}
	}

	// ---- Assertion and Population ends here. ----

	return packet
}

func Analyze(c Classifier, tracker *ConnectionTracker, packet *Packet) Verdict {

	// If convertor could not convert the packet, for now, we
	// may simply allow the packet to pass through, as the
	// convertor may not be sophisticated enough at this point.
	// NOT Logging Allowed packets here due to probable lack of
	// fields to populate while logging.
	if packet == nil {
		return Allow
	}

	// Create Logger Entry for pre-determined fields.
	var logEntry logger.LogEntry = logger.LogEntry{
		LogCategory: logger.LogTypePacket, // Recurring log.
		Timestamp:   time.Now(),
		Classifier:  fmt.Sprintf("%T", c),
		Source:      fmt.Sprintf("%s:%d", packet.SrcIp, packet.SrcPort),
		Destination: fmt.Sprintf("%s:%d", packet.DestIp, packet.DestPort),
		TCPFlags:    formatFlags(packet.Flags),
		PacketRate:  packet.PacketRate,
	}

	// If the classifier returns true, that means our packet
	// is malformed, hence drop it.
	verdict := c.Classify(packet)

	if tracker.Track(packet, verdict) || verdict {
		// Update the remaining fields.
		logEntry.Level = logger.ALERT
		logEntry.Verdict = "DROP"
		logger.Log(logEntry) // Push the log.

		return Drop
	}

	// For all other cases, allow the packet through.
	logEntry.Level = logger.INFO
	logEntry.Verdict = "ALLOW"

	return Allow
}

// formatFlags helps in formatting a string for feeding into the logger for
// flags specifically.
func formatFlags(flags TCPFlags) string {
	return fmt.Sprintf("SYN=%t ACK=%t FIN=%t RST=%t PSH=%t URG=%t", flags.SYN, flags.ACK, flags.FIN, flags.RST, flags.PSH, flags.URG)
}
