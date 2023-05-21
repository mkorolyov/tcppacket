package main

import (
	"fmt"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func Test_test(t *testing.T) {
	bs := []byte{69, 0, 48, 0, 184, 4, 0, 0, 64, 4, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1}
	// Decode a packet
	packet := gopacket.NewPacket(bs, layers.LayerTypeIPv4, gopacket.Default)
	// Get the TCP layer from this packet
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		fmt.Println("This is a TCP packet!")
		// Get actual TCP data from this layer
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("From src port %d to dst port %d: %s\n", tcp.SrcPort, tcp.DstPort, string(tcp.Payload))
	}

	for _, layer := range packet.Layers() {
		fmt.Println("PACKET LAYER:", layer.LayerType())
	}

	if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
		fmt.Println("This is a IP Layer!")
		// Get actual TCP data from this layer
		ipLayer, _ := layer.(*layers.IPv4)
		fmt.Printf("layer %+v\n", ipLayer)
	}

	if failure := packet.Layer(gopacket.LayerTypeDecodeFailure); failure != nil {
		fmt.Println("PACKET FAILURE:", failure)
	}

}
