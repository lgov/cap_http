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
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/aschepis/kernctl"
	"io"
	"log"
	"net"
)

const (
	// Providers
	NSTAT_PROVIDER_ROUTE = 1
	NSTAT_PROVIDER_TCP   = 2
	NSTAT_PROVIDER_UDP   = 3

	// generic response messages
	NSTAT_MSG_TYPE_SUCCESS = 0
	NSTAT_MSG_TYPE_ERROR   = 1

	// Requests
	NSTAT_MSG_TYPE_ADD_SRC      = 1001
	NSTAT_MSG_TYPE_ADD_ALL_SRCS = 1002
	NSTAT_MSG_TYPE_REM_SRC      = 1003
	NSTAT_MSG_TYPE_QUERY_SRC    = 1004
	NSTAT_MSG_TYPE_GET_SRC_DESC = 1005

	// Responses/Notfications
	NSTAT_MSG_TYPE_SRC_ADDED   = 10001
	NSTAT_MSG_TYPE_SRC_REMOVED = 10002
	NSTAT_MSG_TYPE_SRC_DESC    = 10003
	NSTAT_MSG_TYPE_SRC_COUNTS  = 10004

	NSTAT_SRC_REF_ALL     = 0xFFFFFFFF
	NSTAT_SRC_REF_INVALID = 0
)

const (
	TCPS_CLOSED       = 0 /* closed */
	TCPS_LISTEN       = 1 /* listening for connection */
	TCPS_SYN_SENT     = 2 /* active, have sent syn */
	TCPS_SYN_RECEIVED = 3 /* have send and received syn */
	/* states < TCPS_ESTABLISHED are those where connections not established */
	TCPS_ESTABLISHED = 4 /* established */
	TCPS_CLOSE_WAIT  = 5 /* rcvd fin, waiting for close */
	/* states > TCPS_CLOSE_WAIT are those where user has closed */
	TCPS_FIN_WAIT_1 = 6 /* have closed, sent fin */
	TCPS_CLOSING    = 7 /* closed xchd FIN; await FIN ACK */
	TCPS_LAST_ACK   = 8 /* had fin and close; await FIN ACK */
	/* states > TCPS_CLOSE_WAIT && < TCPS_FIN_WAIT_2 await ACK of FIN */
	TCPS_FIN_WAIT_2 = 9  /* have closed, fin is acked */
	TCPS_TIME_WAIT  = 10 /* in 2*msl quiet wait after close */
)

type nstat_msg_hdr struct {
	Context uint64
	HType   uint32
	Pad     uint32 // unused for now
}

/*****************************************************************************/
/* REQUESTS                                                                  */
/*****************************************************************************/

// Type nstat_msg_add_all_srcs, implements kernctl.Message for serialization.
type nstat_msg_add_all_srcs struct {
	Hdr      nstat_msg_hdr
	Provider uint32
}

func (msg *nstat_msg_add_all_srcs) Bytes() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, msg)
	return buf.Bytes()
}

type nstat_msg_query_src_req struct {
	Hdr    nstat_msg_hdr
	SrcRef uint32
}

func (msg *nstat_msg_query_src_req) Bytes() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, msg)
	return buf.Bytes()
}

type nstat_msg_get_src_description struct {
	Hdr    nstat_msg_hdr
	SrcRef uint32
}

/*****************************************************************************/
/* COMMANDS                                                                  */
/*****************************************************************************/
func addAllSources(conn *kernctl.Conn, provider uint32) {
	aasreq := &nstat_msg_add_all_srcs{
		Hdr: nstat_msg_hdr{
			HType:   NSTAT_MSG_TYPE_ADD_ALL_SRCS,
			Context: 3,
		},
		Provider: provider,
	}
	//	log.Println("addAllSources", provider)
	conn.SendCommand(aasreq)
}

func getSrcDescription(conn *kernctl.Conn, srcRef uint32) {
	qsreq := &nstat_msg_query_src_req{
		Hdr: nstat_msg_hdr{
			HType:   NSTAT_MSG_TYPE_GET_SRC_DESC,
			Context: 1005,
		},
		SrcRef: srcRef,
	}
	//	log.Println("getSrcDescription", srcRef)
	conn.SendCommand(qsreq)
}

/*****************************************************************************/
/* RESPONSES                                                                 */
/*****************************************************************************/
type nstat_msg_src_added struct {
	Hdr      nstat_msg_hdr
	Provider uint32
	SrcRef   uint32
}

type nstat_msg_src_removed struct {
	Hdr    nstat_msg_hdr
	SrcRef uint32
}

type nstat_msg_src_description struct {
	Hdr      nstat_msg_hdr
	SrcRef   uint32
	Provider uint32
	// u_int8_t  data[];
}

// The original C structures are #pragma pack(1), but here this isn't important,
// we let binary.Read map packed byte stream to unpacked go struct.
type nstat_counts struct {
	Rxpackets         uint64
	Rxbytes           uint64
	Txpackets         uint64
	Txbytes           uint64
	Rxduplicatebytes  uint32
	Rxoutoforderbytes uint32
	Txretransmit      uint32
	Connectattempts   uint32
	Connectsuccesses  uint32
	Min_rtt           uint32
	Avg_rtt           uint32
	Var_rtt           uint32
}

type nstat_msg_src_counts struct {
	Hdr     nstat_msg_hdr
	SrcRef  uint32
	Counts  nstat_counts
	TCPDesc nstat_tcp_descriptor
}

const (
	AF_INET  = 2
	AF_INET6 = 30
)

type in6_addr struct {
	S6_addr [16]uint8
}

type sockaddr_in6 struct {
	Sin6_len      uint8
	Sin6_family   uint8
	Sin6_port     uint16
	Sin6_flowinfo uint32
	Sin6_addr     [16]uint8
	Sin6_scope_id uint32
}

type sockaddr_in4 struct {
	Sin_len    uint8
	Sin_family uint8
	Sin_port   uint16
	Sin_addr   [4]uint8
	Sin_zero   [8]byte
}

func (s *sockaddr_in4) String() string {
	return fmt.Sprintf("%d.%d.%d.%d:%d", s.Sin_addr[0], s.Sin_addr[1],
		s.Sin_addr[2], s.Sin_addr[3], s.Sin_port)
}

// TODO: account for differences in OS X 8-10
type nstat_tcp_descriptor struct {
	Local      [28]byte // local IP address and port
	Remote     [28]byte // Remote IP address and port
	Ifindex    uint32
	State      uint32
	Sndbufsize uint32
	Sndbufused uint32
	Rcvbufsize uint32
	Rcvbufused uint32
	Txunacked  uint32
	Txwindow   uint32
	Txcwindow  uint32

	// This was added in 10_8, pushing the rest by four bytes
	Traffic_class uint32

	Upid  uint64
	Pid   uint32
	Pname [64]byte
}

// Read the sockaddr structures in network byte order!
func (d *nstat_tcp_descriptor) Local4() (sockaddr_in4, error) {
	var addr sockaddr_in4
	var tmp []byte
	tmp = d.Local[0:16]
	reader := bytes.NewReader(tmp)
	err := binary.Read(reader, binary.BigEndian, &addr)
	return addr, err
}

func (d *nstat_tcp_descriptor) Remote4() (sockaddr_in4, error) {
	var addr sockaddr_in4
	var tmp []byte
	tmp = d.Remote[0:16]
	reader := bytes.NewReader(tmp)
	err := binary.Read(reader, binary.BigEndian, &addr)
	return addr, err
}

func (d *nstat_tcp_descriptor) Family() uint8 {
	return uint8(d.Local[1])
}

func (d *nstat_tcp_descriptor) Name() string {
	n := bytes.Index(d.Pname[:], []byte{0})
	return string(d.Pname[:n])
}

func (d *nstat_tcp_descriptor) StateString() string {
	switch d.State {
	case TCPS_CLOSED:
		return ("CLOSED")
	case TCPS_LISTEN:
		return ("LISTENING")
	case TCPS_ESTABLISHED:
		return ("ESTABLISHED")
	case TCPS_CLOSING:
		return ("CLOSING")
	case TCPS_SYN_SENT:
		return ("SYN_SENT")
	case TCPS_LAST_ACK:
		return ("LAST_ACK")
	case TCPS_CLOSE_WAIT:
		return ("CLOSE_WAIT")
	case TCPS_TIME_WAIT:
		return ("TIME_WAIT")
	case TCPS_FIN_WAIT_1:
		return ("FIN_WAIT_1")
	case TCPS_FIN_WAIT_2:
		return ("FIN_WAIT_2")

	default:
		return ("?")
	}
}

type Descriptor struct {
	zzz     string
	Counts  nstat_counts
	TCPDesc *nstat_tcp_descriptor
}

var descriptors map[uint32]*Descriptor

/*****************************************************************************/

func readTCPDescriptor(msg nstat_msg_src_description,
	reader io.Reader) (*nstat_tcp_descriptor, error) {

	var tcpDesc nstat_tcp_descriptor

	// Read the remainder of the data in the nstat_tcp_descriptor struct
	err := binary.Read(reader, binary.LittleEndian, &tcpDesc)
	if err != nil {
		log.Println("binary.Read TCPDescriptor failed:", err)
		return nil, err
	}
	/*
		switch tcpDesc.Family() {
		case AF_INET:
			var laddr, raddr sockaddr_in4
			if laddr, err = tcpDesc.Local4(); err != nil {
				break
			}
			if raddr, err = tcpDesc.Remote4(); err != nil {
				break
			}

			log.Println("local: ", laddr, " remote: ", raddr)
		case AF_INET6:
			break
		}
	*/
	return &tcpDesc, err
}

/* Process the response we received from the system socket. */
func (s *OSXNetDescSource) ProcessNStatMsg(conn *kernctl.Conn,
	msg_hdr nstat_msg_hdr, buf []byte) error {

	err := error(nil)

	switch msg_hdr.HType {
	case NSTAT_MSG_TYPE_SRC_ADDED:
		var msg nstat_msg_src_added
		reader := bytes.NewReader(buf)
		err = binary.Read(reader, binary.LittleEndian, &msg)
		if err != nil {
			log.Println("binary.Read SRC_ADDED failed:", err)
			break
		}
		descriptors[msg.SrcRef] = &Descriptor{}
		/* New source added, now get its details */
		getSrcDescription(conn, msg.SrcRef)

	case NSTAT_MSG_TYPE_SRC_REMOVED:
		var msg nstat_msg_src_removed
		reader := bytes.NewReader(buf)
		err = binary.Read(reader, binary.LittleEndian, &msg)
		if err != nil {
			log.Println("binary.Read SRC_REMOVED failed:", err)
			break
		}
		delete(descriptors, msg.SrcRef)

	case NSTAT_MSG_TYPE_SRC_DESC:
		var msg nstat_msg_src_description
		reader := bytes.NewReader(buf)
		err = binary.Read(reader, binary.LittleEndian, &msg)
		if err != nil {
			log.Println("binary.Read SRC_DESCRIPTION failed:", err)
			break
		}
		switch msg.Provider {
		case NSTAT_PROVIDER_TCP:
			var tcpDesc *nstat_tcp_descriptor
			if tcpDesc, err = readTCPDescriptor(msg, reader); err != nil {
				break
			} else if laddr, err := tcpDesc.Local4(); err != nil {
				break
			} else if raddr, err := tcpDesc.Remote4(); err != nil {
				break
			} else {
				descriptors[msg.SrcRef].TCPDesc = tcpDesc
				//          log.Println("TCP descriptor received: ", msg)
				netDesc := &NetDescriptor{
					Pid: tcpDesc.Pid,
					LocalIPv4Addr: net.TCPAddr{
						IP: net.IPv4(laddr.Sin_addr[0], laddr.Sin_addr[1],
							laddr.Sin_addr[2], laddr.Sin_addr[3]),
						Port: int(laddr.Sin_port),
					},
					RemoteIPv4Addr: net.TCPAddr{
						IP: net.IPv4(raddr.Sin_addr[0], raddr.Sin_addr[1],
							raddr.Sin_addr[2], raddr.Sin_addr[3]),
						Port: int(raddr.Sin_port),
					}}
				s.channel <- *netDesc
			}
		case NSTAT_PROVIDER_UDP:
			//log.Println("UDP descriptor received: ", msg)
		}
		//		log.Println("description received: ", msg)
	}
	return err
}

const (
	STATE_INITIAL      = 0
	STATE_TCP_ADDED    = 2
	STATE_UDP_ADDED    = 4
	STATE_COUNTS_ADDED = 6
)

type NetDescriptor struct {
	Pid            uint32
	LocalIPv4Addr  net.TCPAddr
	RemoteIPv4Addr net.TCPAddr
}

type OSXNetDescSource struct {
	channel chan NetDescriptor
}

type NetDescSource interface {
	Descriptors() chan NetDescriptor
}

func NewOSXNetDescSource() *OSXNetDescSource {
	return &OSXNetDescSource{}
}

func (s *OSXNetDescSource) Descriptors() chan NetDescriptor {
	s.channel = make(chan NetDescriptor)
	go s.ListenForEvents()
	return s.channel
}

func (s *OSXNetDescSource) ListenForEvents() {
	conn := kernctl.NewConnByName("com.apple.network.statistics")
	if err := conn.Connect(); err != nil {
		panic(err)
	}

	descriptors = make(map[uint32]*Descriptor)

	var state = STATE_INITIAL
	for {
		// Subscribe to following events one by one:
		// 1. all TCP events
		// 2. descriptions
		switch state {
		case STATE_INITIAL:
			addAllSources(conn, NSTAT_PROVIDER_TCP)
			state++
		default:
			/* in one of the waiting states (uneven numbers) */
			break
		}

		if err, buf := conn.Select(2048); err != nil {
			panic(err)
		} else {
			var msg_hdr nstat_msg_hdr

			// we received a message. first read the header, based on the
			// HType field we can the decide how to interpret the complete
			// byte stream.
			reader := bytes.NewReader(buf)
			err := binary.Read(reader, binary.LittleEndian, &msg_hdr)
			if err != nil {
				log.Println("binary.Read failed:", err)
				//              break
				continue
			}
			//			log.Println("msg_hdr recvd:", msg_hdr)

			switch msg_hdr.HType {
			case NSTAT_MSG_TYPE_SUCCESS:
				{
					/* Previous requested action was successful, go to next. */
					state++
				}
			case NSTAT_MSG_TYPE_SRC_ADDED, NSTAT_MSG_TYPE_SRC_REMOVED,
				NSTAT_MSG_TYPE_SRC_DESC, NSTAT_MSG_TYPE_SRC_COUNTS:
				{
					ret := s.ProcessNStatMsg(conn, msg_hdr, buf)
					if ret != nil {
						break
					}
				}
			case NSTAT_MSG_TYPE_ERROR:
				//				log.Println("error")
			}
		}
	}

	conn.Close()
}
