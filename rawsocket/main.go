package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	go receive()
	time.Sleep(time.Second)
	go send()
	time.Sleep(10 * time.Second)
}

func receive() {
	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_IPV4)
	f := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))

	log.Printf("Listening on %s\n", f.Name())

	for {
		buf := make([]byte, 1024)
		numRead, err := f.Read(buf)
		if err != nil {
			log.Printf("Received err: %v\n", err)
		}
		log.Printf("Received packet: %v\n", buf[:numRead])

		debugPacket(buf, numRead, "after read")
	}
}

func receive2() {
	ipAddr, err := net.ResolveIPAddr("ip4", "127.0.0.1")
	if err != nil {
		panic(err.Error())
	}

	ipConn, err := net.ListenIP("ip4:tcp", ipAddr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Listening on %s\n", ipConn.LocalAddr().String())

	for {
		buf := make([]byte, 1024)
		numRead, remoteAddr, err := ipConn.ReadFrom(buf)
		if err != nil {
			log.Printf("Received err: %v\n", err)
		}
		if remoteAddr.String() != "127.0.0.1" {
			log.Printf("Received packet from %s, ignoring\n", remoteAddr.String())
			continue
		}

		log.Printf("Received packet length %d from %s : \n% X\n", numRead, remoteAddr.String(), buf[:numRead])

		debugPacket(buf, numRead, "after read")
	}
}

func send() {
	var err error
	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_IPV4)
	log.Printf("fd: %d\n", fd)
	addr := syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{127, 0, 0, 1},
	}
	p := preparePacket()
	err = syscall.Sendto(fd, p, 0, &addr)
	if err != nil {
		log.Fatal("Sendto: ", err)
	}
	log.Printf("Sent packet %v \n", p)
}

func send2() {
	ipAddr, err := net.ResolveIPAddr("ip4", "127.0.0.1")

	conn, err := net.DialIP("ip4:tcp", nil, ipAddr)
	if err != nil {
		log.Fatal(err)
	}

	n, err := conn.Write([]byte("wuffwuff"))
	log.Printf("Sent %d bytes\n", n)
}

func debugPacket(buf []byte, numRead int, ctx string) {
	log.Println("context: ", ctx)
	// Decode a packet
	packet := gopacket.NewPacket(buf[:numRead], layers.LayerTypeIPv4, gopacket.Default)
	// Get the TCP layer from this packet
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		fmt.Println("This is a TCP packet!")
		// Get actual TCP data from this layer
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("From src port %d to dst port %d: %s\n", tcp.SrcPort, tcp.DstPort, string(tcp.Payload))
	}

	for _, layer := range packet.Layers() {
		fmt.Printf("PACKET LAYER: %#v\n", layer)
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

func preparePacket() []byte {
	var srcIP, dstIP net.IP
	var srcPstr string = "127.0.0.1"
	var dstPstr string = "127.0.0.1"

	srcIP = net.ParseIP(srcPstr)
	if srcIP == nil {
		panic("non ip source address")
	}
	srcIP = srcIP.To4()
	if srcIP == nil {
		panic("non ipv4 source address")
	}

	dstIP = net.ParseIP(dstPstr)
	if dstIP == nil {
		panic("non ip destination address")
	}
	dstIP = dstIP.To4()
	if dstIP == nil {
		panic("non ipv4 destination address")
	}

	localRand := rand.New(rand.NewSource(time.Now().UnixNano()))

	ipLayer := layers.IPv4{
		Version:    4,
		IHL:        5,  // internet header length in 32 bit words. 5 means min and it is 20bytes, as no options are set
		TOS:        0,  // type of service: BE(best effort), default
		Length:     0,  // will be filled as FixLenght opts is passed to the serializer
		Id:         0,  // id of the packet, will be filled by the kernel
		Flags:      0,  // no fragmentation
		FragOffset: 0,  // no fragmentation
		TTL:        64, // time to live
		Protocol:   layers.IPProtocolTCP,
		Checksum:   0, // will be filled by the serializer
		SrcIP:      srcIP,
		DstIP:      dstIP,
		Options:    nil, // no options
		Padding:    nil, // no padding as no options are set
	}

	// build tcp/ip packet
	tcpLayer := layers.TCP{
		SrcPort:    layers.TCPPort(0),
		DstPort:    layers.TCPPort(80),
		Seq:        uint32(localRand.Intn(65535)),
		Ack:        0,
		DataOffset: 0,
		FIN:        false,
		SYN:        true, // sync sequence numbers to initiate a connection
		RST:        false,
		PSH:        false,
		ACK:        false,
		URG:        false,
		ECE:        false,
		CWR:        false,
		NS:         false,
		Window:     1505,
		Checksum:   0,
		Urgent:     0,
		Options:    nil,
		Padding:    nil,
	}

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := tcpLayer.SetNetworkLayerForChecksum(&ipLayer); err != nil {
		log.Fatal(err)
	}

	buf := gopacket.NewSerializeBuffer()
	payload := gopacket.Payload("wuffwuff")
	if err := gopacket.SerializeLayers(buf, opts, &ipLayer, &tcpLayer, payload); err != nil {
		log.Fatal(err)
	}
	return buf.Bytes()
}
