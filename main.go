package main

import (
	"bufio"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/tcpassembly"
	"code.google.com/p/gopacket/tcpassembly/tcpreader"
	"flag"
	"io"
	"log"
	"net/http"
)

/* Command line arguments */
var iface = flag.String("i", "lo0", "Interface to get packets from")
var logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")

// httpStream will handle the actual decoding of http requests and responses.
type httpStream struct {
	netFlow, tcpFlow gopacket.Flow
	readStream       tcpreader.ReaderStream
}

/* This reads both HTTP requests and HTTP responses in two separate streams */
func (h *httpStream) run() {
	log.Printf("run")
	log.Println("reading stream", h.netFlow, h.tcpFlow)
	buf := bufio.NewReader(&h.readStream)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", h.netFlow, h.tcpFlow, ":", err)
		} else {
			bodyBytes := tcpreader.DiscardBytesToEOF(req.Body)
			req.Body.Close()
			log.Println("Received request from stream", h.netFlow, h.tcpFlow, ":", req, "with", bodyBytes, "bytes in request body")
		}
	}
}

/* httpStreamFactory implements tcpassembly.StreamFactory */
type httpStreamFactory struct{}

func (h *httpStreamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		netFlow:    netFlow,
		tcpFlow:    tcpFlow,
		readStream: tcpreader.NewReaderStream(),
	}
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.readStream
}

func main() {
	flag.Parse()
	log.Printf("starting capture on interface %q", *iface)

	handle, err := pcap.OpenLive(*iface, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("tcp and port 30080"); err != nil {
		panic(err)
	}

	// Set up assembly
	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	log.Println("reading in packets")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	for packet := range packets {

		if *logAllPackets {
			log.Println(packet)
		}

		tcp := packet.TransportLayer().(*layers.TCP)
		assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp,
			packet.Metadata().Timestamp)
	}
}
