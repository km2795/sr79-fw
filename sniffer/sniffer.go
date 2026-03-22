package sniffer

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type PacketSource struct {
	handle *pcap.Handle // Handle to the device
}

const BUFFER_SIZE int = 100 // Buffer Size for the Packet Sending Channel.

// Start fetches a handle to the network device through OpenLive()
// method of pcap library. Simultaenously sets the BPF Filter for
// IP traffic (customizable). It takes the device name as the input
// and returns the pcap.Handle wrapped in the PacketSource object for
// abstraction and modularity.
func Start(device string) (*PacketSource, error) {
	// TODO: Create a list of device configurations to compare against.
	// For now just check if something was passed.
	if len(device) < 1 {
		return nil, fmt.Errorf("invalid device configuration")
	}

	handle, err := pcap.OpenLive(device, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Error Opening Interface: %v\n", err)
		return nil, err
	}

	// BPF Filter for IP only traffic.
	if err := handle.SetBPFFilter("ip or ip6"); err != nil {
		log.Printf("Unable to Set BPF Filter for IP only packets: %v\n", err)
	}

	return &PacketSource{handle: handle}, nil
}

// ProcessPackets reads the packets from the handle (PacketSource)
// in a loop and sends them through a channel for the analyzer to
// process. It takes the PacketSource (handle) and returns the
// channel for sending packets.
func ProcessPackets(ps *PacketSource) chan gopacket.Packet {
	packetSource := gopacket.NewPacketSource(ps.handle, ps.handle.LinkType())
	packetChannel := make(chan gopacket.Packet, BUFFER_SIZE)

	// The loop will run in the background, the ProcessPacket
	// will return the channel to the caller.
	go func() {
		for packet := range packetSource.Packets() {
			packetChannel <- packet
		}

		close(packetChannel)
	}()

	return packetChannel
}

// Handle returns the underlying pcap.Handle for use by other packages
// (e.g. the responder).
func (ps *PacketSource) Handle() *pcap.Handle {
	return ps.handle
}

// Close finally cleans the pcap handle to the device when the analyzer
// sends the shutdown signal.
func (ps *PacketSource) Close() {
	if ps.handle != nil {
		ps.handle.Close()
	}
}
