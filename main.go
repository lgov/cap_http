// Copyright 2014 Lieven Govaerts. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	//	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"
)

/* Command line arguments */
var iface = flag.String("i", "en0", "Interface to get packets from")
var logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")
var launchCmd = flag.String("e", "", "Launches the command and logs its traffic")

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
			//			fmt.Print(".")
			// log.Println("Received request from stream", h.netFlow, h.tcpFlow,
			// 	":", req, "with", bodyBytes, "bytes in request body")
		}
	}
}

func (h *TCPStream) runIn() {
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
			_, err := tcpreader.DiscardBytesToFirstError(resp.Body)
			if err != nil && err != io.EOF {
				log.Println(err)
			}
			resp.Body.Close()
			err = h.storage.ReceivedResponse(h.bidikey, reqID, time.Now(), resp)
			if err != nil {
				log.Println("Error storing response", err)
			}
			reqID++
			// fmt.Print(".")
			//log.Println("Received response from stream", h.netFlow, h.tcpFlow,
			//	":", resp, "with", bodyBytes, "bytes in response body")
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
		log.Println("reading stream", netFlow, tcpFlow)
		bds = &BidiStream{out: hstream, key: key}
		h.bidiStreams[key] = bds
		// Start a coroutine per stream, to ensure that all data is read from
		// the reader stream
		go hstream.runOut()
	} else {
		bds.in = hstream
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

func (h *httpStreamFactory) LogPacketSize(packet gopacket.Packet) {
	netFlow := packet.NetworkLayer().NetworkFlow()
	tcpFlow := packet.TransportLayer().TransportFlow()
	key := netFlow.FastHash() ^ tcpFlow.FastHash()

	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	ipv4, _ := ipv4Layer.(*layers.IPv4)

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	tcp, _ := tcpLayer.(*layers.TCP)

	bds := h.bidiStreams[key]
	if bds == nil || bds.in == nil || bds.out == nil {
		return
	}

	payloadLength := uint32(ipv4.Length - uint16(ipv4.IHL)*4 - uint16(tcp.DataOffset)*4)

	if bds.in.netFlow == netFlow {
		/* incoming */
		err := h.storage.IncomingTCPPacket(key, payloadLength)
		if err != nil {
			panic(err)
		}
	} else {
		/* outgoing */
		err := h.storage.OutgoingTCPPacket(key, payloadLength)
		if err != nil {
			panic(err)
		}
	}
}

type Assembler struct {
	assembler *tcpassembly.Assembler
}

func NewAssembler(streamPool *tcpassembly.StreamPool) *Assembler {
	return &Assembler{tcpassembly.NewAssembler(streamPool)}
}

/* PFF, a lot of abstractions that make things more difficult then they should be! */
func (a *Assembler) AssembleWithTimestamp(netFlow gopacket.Flow, t *layers.TCP,
	timestamp time.Time) {
	a.assembler.AssembleWithTimestamp(netFlow, t, timestamp)
}

/* Wait for a couple of seconds, just enough to get the events handled by the
   main function. */
func wait_for_responses_to_arrive() (timeout chan bool) {
	timeout = make(chan bool, 1)
	go func() {
		time.Sleep(2 * time.Second)
		timeout <- true
	}()
	return timeout
}

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	//	log.SetOutput(ioutil.Discard)

	log.Printf("starting capture on interface %q", *iface)

	// Setup packet capture
	handle, err := pcap.OpenLive(*iface, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("tcp and port 80"); err != nil {
		panic(err)
	}

	/* TODO: we need a storage layer per goroutine! */
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

	pid := uint32(0)
	var cmd_done chan error
	var start_time time.Time
	if *launchCmd != "" {
		s := *launchCmd
		//		n := strings.Index(*launchCmd, " ")
		//		fmt.Println("Launching ", s[0:n], " --- ", s[n:])
		//		cmd := exec.Command(s[0:n], strings.Split(s[n:], " "))
		args := strings.Split(s, " ")
		cmd := exec.Command(args[0], args[1:]...)
		start_time = time.Now()
		err := cmd.Start()
		if err != nil {
			panic(err)
		}
		cmd_done = make(chan error, 1)
		go func() {
			cmd_done <- cmd.Wait()
		}()
		pid = uint32(cmd.Process.Pid)
		fmt.Println("PID: ", cmd.Process.Pid)
	}

	netDescSource := NewOSXNetDescSource()
	descriptors := netDescSource.Descriptors()

	log.Println("reading in packets. Press CTRL-C to end and report.")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	var timeout chan bool

	for {
		select {
		case netDesc := <-descriptors:
			if netDesc.Pid == pid {
				fmt.Println("event received ", netDesc)
			}
		case packet := <-packets:
			if *logAllPackets {
				log.Println(packet)
			}

			if storage.PacketInScope(packet) {
				streamFactory.LogPacketSize(packet)
				netFlow := packet.NetworkLayer().NetworkFlow()
				tcp := packet.TransportLayer().(*layers.TCP)

				assembler.AssembleWithTimestamp(netFlow, tcp,
					packet.Metadata().Timestamp)
			}
		case err := <-cmd_done:
			if err != nil {
				log.Printf("process done with error = %v\n", err)
			}
			log.Println("Process took: ", time.Now().Sub(start_time))

			log.Println("Waiting for the remaining responses to arrive.")

			/* Wait a couple of seconds here */
			timeout = wait_for_responses_to_arrive()

		case <-ctrlc:
			if err := storage.Report(); err != nil {
				log.Println(err)
			}

			//			pprof.StopCPUProfile()
			os.Exit(0)

		case <-timeout:
			if err = storage.Report(); err != nil {
				log.Panic(err)
			}

			os.Exit(0)
		}
	}
}
