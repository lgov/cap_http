package main

import (
	"bufio"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/tcpassembly"
	"code.google.com/p/gopacket/tcpassembly/tcpreader"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
)

/* Command line arguments */
var iface = flag.String("i", "en0", "Interface to get packets from")
var logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")

type interval struct {
	req  *http.Request
	resp *http.Response
}

type BidiStream struct {
	key     uint64
	in, out *TCPStream
}

// TCPStream will handle the actual decoding of http requests and responses.
type TCPStream struct {
	netFlow, tcpFlow gopacket.Flow
	readStream       tcpreader.ReaderStream
	storage          *Storage
	bidikey          uint64
}

/* This reads both HTTP requests and HTTP responses in two separate streams */
func (h *TCPStream) runOut() {
	log.Printf("runOut")

	buf := bufio.NewReader(&h.readStream)
	var reqID int64
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", h.netFlow, h.tcpFlow, ":", err)
		} else {
			// bodyBytes := tcpreader.DiscardBytesToEOF(req.Body)
			req.Body.Close()
			err = h.storage.SentRequest(h.bidikey, reqID, time.Now(), req)
			if err != nil {
				log.Println("Error storing request", err)
			}

			reqID++
			fmt.Print(".")
			// log.Println("Received request from stream", h.netFlow, h.tcpFlow,
			// 	":", req, "with", bodyBytes, "bytes in request body")
		}
	}
}

func (h *TCPStream) runIn() {
	log.Printf("runIn")

	buf := bufio.NewReader(&h.readStream)
	var reqID int64
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
			err = h.storage.ReceivedResponse(h.bidikey, reqID, time.Now(), resp)
			if err != nil {
				log.Println("Error storing response", err)
			}
			reqID++
			fmt.Print(".")

			//			log.Println("Received response from stream", h.netFlow, h.tcpFlow,
			//				":", resp, "with", bodyBytes, "bytes in response body")
		}

		/* Match the response with the next request */
	}

}

/* httpStreamFactory implements tcpassembly.StreamFactory */
type httpStreamFactory struct {
	bidiStreams map[uint64]*BidiStream
	storage     *Storage
}

func (h *httpStreamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {

	/* First the outgoing stream, then the incoming stream */
	key := netFlow.FastHash() ^ tcpFlow.FastHash()

	hstream := &TCPStream{
		netFlow:    netFlow,
		tcpFlow:    tcpFlow,
		readStream: tcpreader.NewReaderStream(),
		storage:    h.storage,
		bidikey:    key,
	}

	bds := h.bidiStreams[key]
	if bds == nil {
		log.Println("new stream", key)
		bds = &BidiStream{in: hstream, key: key}
		h.bidiStreams[key] = bds
		// Start a coroutine per stream, to ensure that all data is read from
		// the reader stream
		go hstream.runOut()
	} else {
		bds.out = hstream
		err := h.storage.OpenTCPConnection(key, time.Now())
		if err != nil {
			log.Println("Error storing connection", err)
		}
		// Start a coroutine per stream, to ensure that all data is read from
		// the reader stream
		go hstream.runIn()
	}

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.readStream
}

type Assembler struct {
	assembler *tcpassembly.Assembler
}

func NewAssembler(streamPool *tcpassembly.StreamPool) *Assembler {
	return &Assembler{tcpassembly.NewAssembler(streamPool)}
}

func (a *Assembler) AssembleWithTimestamp(netFlow gopacket.Flow, t *layers.TCP,
	timestamp time.Time) {
	a.assembler.AssembleWithTimestamp(netFlow, t, timestamp)
}

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	log.Printf("starting capture on interface %q", *iface)

	// Setup packet capture
	handle, err := pcap.OpenLive(*iface, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("tcp and port 80"); err != nil {
		panic(err)
	}

	// Set up storage layer
	storage, err := NewStorage()
	if err != nil {
		panic(err)
	}

	// Set up assembly
	streamFactory := &httpStreamFactory{bidiStreams: make(map[uint64]*BidiStream),
		storage: storage}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := NewAssembler(streamPool)

	// Setup CTRL-C handler
	ctrlc := make(chan os.Signal, 1)
	signal.Notify(ctrlc, os.Interrupt)

	log.Println("reading in packets. Press CTRL-C to end and report.")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	for {
		select {
		case packet := <-packets:
			if *logAllPackets {
				log.Println(packet)
			}

			if storage.PacketInScope(packet) {
				tcp := packet.TransportLayer().(*layers.TCP)
				assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(),
					tcp, packet.Metadata().Timestamp)
			}
		case <-ctrlc:
			storage.Report()
			//			pprof.StopCPUProfile()
			os.Exit(1)
		}
	}
}
