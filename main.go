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
	"os"
	"os/signal"
)

/* Command line arguments */
var iface = flag.String("i", "lo0", "Interface to get packets from")
var logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")

type interval struct {
	req  *http.Request
	resp *http.Response
}

type bidiStream struct {
	key     uint64
	in, out *httpStream
}

// httpStream will handle the actual decoding of http requests and responses.
type httpStream struct {
	netFlow, tcpFlow gopacket.Flow
	readStream       tcpreader.ReaderStream
	storage          *Storage
}

/* This reads both HTTP requests and HTTP responses in two separate streams */
func (h *httpStream) runOut() {
	log.Printf("runOut")

	buf := bufio.NewReader(&h.readStream)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", h.netFlow, h.tcpFlow, ":", err)
		} else {
			//			bodyBytes := tcpreader.DiscardBytesToEOF(req.Body)
			req.Body.Close()
			h.storage.sentRequest(req)
			//			log.Println("Received request from stream", h.netFlow, h.tcpFlow,
			//				":", req, "with", bodyBytes, "bytes in request body")
		}
	}
}

func (h *httpStream) runIn() {
	log.Printf("runIn")

	buf := bufio.NewReader(&h.readStream)
	for {

		/* Don't start reading a response if no data is available */
		_, err := buf.Peek(1)
		if err == io.EOF {
			return
		}
		/* Data available, read response */
		resp, err := http.ReadResponse(buf, nil) // TODO: request
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			log.Println("EOF while reading stream", h.netFlow, h.tcpFlow, ":", err)
			return
		} else if err != nil {
			log.Println("Error reading stream", h.netFlow, h.tcpFlow, ":", err)
		} else {
			//			bodyBytes := tcpreader.DiscardBytesToEOF(resp.Body)
			resp.Body.Close()
			h.storage.receivedResponse(resp)
			//			log.Println("Received response from stream", h.netFlow, h.tcpFlow,
			//				":", resp, "with", bodyBytes, "bytes in response body")
		}

		/* Match the response with the next request */
	}

}

/* httpStreamFactory implements tcpassembly.StreamFactory */
type httpStreamFactory struct {
	bidiStreams map[uint64]*bidiStream
	storage     *Storage
}

func (h *httpStreamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {

	/* Can we find out if this is the outgoing or incoming stream? */
	/* First the outgoing stream, then the incoming stream */
	key := netFlow.FastHash() ^ tcpFlow.FastHash()

	hstream := &httpStream{
		netFlow:    netFlow,
		tcpFlow:    tcpFlow,
		readStream: tcpreader.NewReaderStream(),
		storage:    h.storage,
	}

	bds := h.bidiStreams[key]
	if bds == nil {
		log.Println("new stream", key)
		bds = &bidiStream{in: hstream, key: key}
		h.bidiStreams[key] = bds
		go hstream.runOut() // Important... we must guarantee that data from the reader stream is read.
	} else {
		bds.out = hstream
		log.Println("netflow: ", bds.in.netFlow)
		h.storage.newTCPConnection(key, bds.in.netFlow, bds.out.netFlow)
		go hstream.runIn() // Important... we must guarantee that data from the reader stream is read.
	}

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.readStream
}

func main() {
	flag.Parse()
	log.Printf("starting capture on interface %q", *iface)

	handle, err := pcap.OpenLive(*iface, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("tcp"); err != nil {
		panic(err)
	}

	storage, err := NewStorage()

	// Set up assembly
	streamFactory := &httpStreamFactory{bidiStreams: make(map[uint64]*bidiStream),
		storage: storage}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// Setup CTRL-C handler
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	log.Println("reading in packets. Press CTRL-C to end and report.")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	for {
		select {
		case packet := <-packets:
			if *logAllPackets {
				log.Println(packet)
			}

			if storage.packetInScope(packet) {
				tcp := packet.TransportLayer().(*layers.TCP)
				assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp,
					packet.Metadata().Timestamp)
			}
		case <-c:
			storage.report()
			//			pprof.StopCPUProfile()
			os.Exit(1)
		}
	}
}
