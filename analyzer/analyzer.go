package analyzer

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// convertPacket converts the gopacket.Packet implementation
// of a network packet and converts that into our own 'Packet'
// implementation.
func convertPacket(gp gopacket.Packet) *Packet {

	packet := &Packet{}

	// IPV4 Layer.
	ipv4Layer := gp.Layer(layers.LayerTypeIPv4)
	if ipv4Layer == nil {
		return nil
	}

	// TCP Layer.
	tcpLayer := gp.Layer(layers.LayerTypeTCP)

	// UDP Layer.
	udpLayer := gp.Layer(layers.LayerTypeUDP)

	// Application Layer.
	applicationLayer := gp.ApplicationLayer()
	if applicationLayer != nil {
		packet.Payload = applicationLayer.Payload()
	}

	// ---- Assert IPV4, TCP, UDP Layers and populate ----
	// ---- 'packet' with relevant fields on true. -------

	ipv4, ok := ipv4Layer.(*layers.IPv4)
	if ok {
		packet.SrcIp = ipv4.SrcIP.String()
		packet.DestIp = ipv4.DstIP.String()
		packet.Protocol = ipv4.Protocol.String()
		packet.Size = int(ipv4.Length)
	} else {
		return nil
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
