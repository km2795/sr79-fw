package responder

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// SendReset is used to terminate a connection by sending a fabricated
// (swapped field values) TCP RST packet to the PCAP handle to the
// destination.
func SendReset(handle *pcap.Handle, gp gopacket.Packet) error {

	// Ethernet Layer Extraction.
	ethernetLayer := gp.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return fmt.Errorf("no ethernet layer found")
	}

	// IPv4 Layer Extraction.
	ipv4Layer := gp.Layer(layers.LayerTypeIPv4)
	if ipv4Layer == nil {
		return fmt.Errorf("no IPv4 layer found")
	}

	// TCP Layer Extraction.
	tcpLayer := gp.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return fmt.Errorf("no TCP layer found")
	}

	// ---- Fabricate the details (swap the fields) ---- //
	ethernet, ok := ethernetLayer.(*layers.Ethernet)
	if ok {
		// Swap MAC addresses.
		ethTemp := ethernet.SrcMAC // For swapping.
		ethernet.SrcMAC = ethernet.DstMAC
		ethernet.DstMAC = ethTemp
	} else {
		return fmt.Errorf("assertion failed: Ethernet layer")
	}

	ipv4, ok := ipv4Layer.(*layers.IPv4)
	if ok {
		// Swap the IP addresses.
		ipTemp := ipv4.SrcIP // For swapping.
		ipv4.SrcIP = ipv4.DstIP
		ipv4.DstIP = ipTemp
	} else {
		return fmt.Errorf("assertion failed: IPv4 layer")
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if ok {
		// Swap the TCP ports.
		tcpTemp := tcp.SrcPort // For Swapping.
		tcp.SrcPort = tcp.DstPort
		tcp.DstPort = tcpTemp
		tcp.RST = true
		tcp.ACK = true
		tcp.Seq = tcp.Ack
		tcp.Window = 0
	} else {
		return fmt.Errorf("assertion failed: TCP layer")
	}

	// ---- Serialize the Packet for Transmission ---- //
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true, // For correct checksums
		FixLengths:       true,
	}

	// Direct the TCP layer to use IP layer for checksum calculations.
	tcp.SetNetworkLayerForChecksum(ipv4)

	// Serialize all the layers.
	err := gopacket.SerializeLayers(
		buffer,
		options,
		ethernet,
		ipv4,
		tcp,
	)
	if err != nil {
		return fmt.Errorf("error creating packet")
	}

	// Write packet (as bytes) to the handle.
	if handle.WritePacketData(buffer.Bytes()) != nil {
		return fmt.Errorf("error sending packet in to handle")
	}

	return nil
}
