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
	"io"
	"log"
	"net/http"
	"time"
)

type PacketLayer struct {
	assembler     *tcpassembly.Assembler
	streamFactory *httpStreamFactory
	storage       *Storage
}

func NewPacketLayer(s *Storage) *PacketLayer {
	pl := &PacketLayer{storage: s}

	// Set up assembly
	pl.streamFactory = newStreamFactory(pl.storage)
	streamPool := tcpassembly.NewStreamPool(pl.streamFactory)
	pl.assembler = tcpassembly.NewAssembler(streamPool)

	return pl
}

func (pl *PacketLayer) CreatePacketsChannel() (packets chan gopacket.Packet) {
	var handle *pcap.Handle
	var err error

	if *inputfile != "" {
		handle, err = pcap.OpenOffline(*inputfile)
	} else {
		log.Printf("starting capture on interface %q", *iface)
		// Setup packet capture
		handle, err = pcap.OpenLive(*iface, 1600, true, pcap.BlockForever)
	}

	if err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("tcp and port 80"); err != nil {
		panic(err)
	}
	log.Println("reading in packets. Press CTRL-C to end and report.")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets = packetSource.Packets()

	return
}

func (pl *PacketLayer) HandlePacket(packet gopacket.Packet) {
	if pl.storage.PacketInScope(packet) {
		pl.streamFactory.logPacketSize(packet)
		netFlow := packet.NetworkLayer().NetworkFlow()
		tcp := packet.TransportLayer().(*layers.TCP)

		pl.assembler.AssembleWithTimestamp(netFlow, tcp,
			packet.Metadata().Timestamp)
	}
}

func (pl *PacketLayer) Close() {

	// Cleanup the go routines
	// Ignore any http request/response parsing errors when closing the streams.
	pl.streamFactory.closed = true
	for _, v := range pl.streamFactory.bidiStreams {
		if v.in != nil {
			v.in.closed = true
		}
		if v.out != nil {
			v.out.closed = true
		}
	}

	pl.assembler.FlushAll()
}

type bidiStream struct {
	key      uint64
	in, out  *tcpStream
	requests chan *http.Request
}

// tcpStream will handle the actual decoding of http requests and responses.
type tcpStream struct {
	netFlow, tcpFlow gopacket.Flow
	readStream       tcpreader.ReaderStream
	storage          *Storage
	bidikey          uint64
	closed           bool
	reqInProgress    *http.Request
}

// runOut is a blocking function that reads HTTP requests from a stream.
func (h *tcpStream) runOut(bds *bidiStream) {
	buf := bufio.NewReader(&h.readStream)
	var reqID int64

	for {
		/*      _, err := buf.Peek(1)
		        if err == io.EOF {
		            return
		        }*/
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			//          log.Println("EOF while reading stream", h.netFlow, h.tcpFlow, ":", err)
			// We must read until we see an EOF... very important!
			err = h.storage.CloseTCPConnection(h.bidikey, time.Now())
			if err != nil {
				log.Println("Error storing connection close timestamp", err)
			}
			return
		} else if err != nil {
			tcpreader.DiscardBytesToFirstError(buf)

			if h.closed == true {
				// error occurred after stream was closed, ignore.
			} else {
				log.Println("Error reading stream", h.netFlow, h.tcpFlow, ":", err)
			}
		} else {
			// bodyBytes := tcpreader.DiscardBytesToEOF(req.Body)
			req.Body.Close()
			bds.requests <- req
			err = h.storage.SentRequest(h.bidikey, reqID, time.Now(), req)

			if err != nil {
				log.Println("Error storing request", err)
			}

			reqID++
			//          fmt.Print(".")
			// log.Println("Received request from stream", h.netFlow, h.tcpFlow,
			//  ":", req, "with", bodyBytes, "bytes in request body")
		}
	}
}

// runIn is a blocking function that reads HTTP responses from a stream.
func (h *tcpStream) runIn(bds *bidiStream) {
	buf := bufio.NewReader(&h.readStream)
	var reqID int64

	for {
		// Don't start reading a response if no data is available
		_, err := buf.Peek(1)
		if err == io.EOF {
			return
		}

		// Data available, read response.

		// Find the request to which this is the response.
		req := h.reqInProgress
		if req == nil {
			req = <-bds.requests
			h.reqInProgress = req
		}

		resp, err := http.ReadResponse(buf, req)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			//          log.Println("EOF while reading stream", h.netFlow, h.tcpFlow, ":", err)
			return
		} else if err != nil {
			tcpreader.DiscardBytesToFirstError(buf)
			if h.closed == true {
				// error occurred after stream was closed, ignore.
			} else {
				log.Println("Error reading stream", h.netFlow, h.tcpFlow, ":", err)
			}
		} else {
			_, err := tcpreader.DiscardBytesToFirstError(resp.Body)
			if err != nil && err != io.EOF {
				log.Println("Error discarding bytes ", err)
			}
			resp.Body.Close()
			err = h.storage.ReceivedResponse(h.bidikey, reqID, time.Now(), resp)
			if err != nil {
				log.Println("Error storing response", err)
			}

			reqID++
			h.reqInProgress = nil

			// fmt.Print(".")
			//log.Println("Received response from stream", h.netFlow, h.tcpFlow,
			//  ":", resp, "with", bodyBytes, "bytes in response body")
		}
	}

}

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct {
	bidiStreams map[uint64]*bidiStream
	storage     *Storage
	closed      bool
}

func newStreamFactory(s *Storage) *httpStreamFactory {
	return &httpStreamFactory{bidiStreams: make(map[uint64]*bidiStream),
		storage: s}
}

func (h *httpStreamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {

	// Watch out: this function can still get called even after all
	// streams were flushed (via FlushAll) and closed.
	/*  if h.closed == true {
	        return tcpreader.NewReaderStream()
	    }
	*/
	// First the outgoing stream, then the incoming stream
	key := netFlow.FastHash() ^ tcpFlow.FastHash()

	hstream := &tcpStream{
		netFlow:    netFlow,
		tcpFlow:    tcpFlow,
		readStream: tcpreader.NewReaderStream(),
		storage:    h.storage,
		bidikey:    key,
	}

	bds := h.bidiStreams[key]
	if bds == nil {
		//      log.Println("reading stream", netFlow, tcpFlow)
		bds = &bidiStream{out: hstream, key: key,
			requests: make(chan *http.Request, 100)}
		h.bidiStreams[key] = bds
		// Start a coroutine per stream, to ensure that all data is read from
		// the reader stream
		go hstream.runOut(bds)
	} else {
		//      log.Println("opening TCP conn", netFlow, tcpFlow)
		bds.in = hstream
		err := h.storage.OpenTCPConnection(key, time.Now())
		if err != nil {
			log.Println("Error storing connection", err)
		}
		// Start a coroutine per stream, to ensure that all data is read from
		// the reader stream
		go hstream.runIn(bds)
	}

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.readStream
}

// logPacketSize calculates the payload length of a TCP packet and stores it
// in the storage layer.
func (h *httpStreamFactory) logPacketSize(packet gopacket.Packet) {
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

	payloadLength := uint32(0)

	if ipv4 != nil {
		payloadLength += uint32(ipv4.Length - uint16(ipv4.IHL)*4)
	}
	if tcp != nil {
		payloadLength -= uint32(uint16(tcp.DataOffset) * 4)
	}

	if bds.in.netFlow == netFlow {
		// This is an incoming packet
		err := h.storage.IncomingTCPPacket(key, payloadLength)
		if err != nil {
			panic(err)
		}
	} else {
		// This is an outgoing packet
		err := h.storage.OutgoingTCPPacket(key, payloadLength)
		if err != nil {
			panic(err)
		}
	}
}
