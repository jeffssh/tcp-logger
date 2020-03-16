
package main

import (
	"fmt"
	"log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// payload: 
	// for port in {1..65535}; do echo -n "port: $port "; curl kali2.praetorianlabs.com:$port --connect-timeout .01; done;
	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	// tcpdump -i en0 -dd "ip and tcp"
	bpfInstructions := []pcap.BPFInstruction{
		{ 0x28, 0, 0, 0x0000000c },
		{ 0x15, 0, 3, 0x00000800 },
		{ 0x30, 0, 0, 0x00000017 },
		{ 0x15, 0, 1, 0x00000006 },
		{ 0x6, 0, 0, 0x00040000 },
		{ 0x6, 0, 0, 0x00000000 },
	}

	if err := handle.SetBPFInstructionFilter(bpfInstructions); err != nil {
		panic(err)
	}

	fmt.Print("Logging all TCP handshakes except to/from port 22\n")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	    ip, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		// capture first packet in TCP handshake excluding ssh traffic
		if tcp.SYN && tcp.SrcPort != 22 && tcp.DstPort != 22 {
			log.Printf("%s %s", ip.SrcIP, tcp.DstPort)
		}
	}
}
