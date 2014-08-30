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
	"code.google.com/p/go-sqlite/go1/sqlite3"
	"code.google.com/p/go.net/context"
	"code.google.com/p/gopacket"
	"fmt"
	"net/http"
	"time"
)

/* Storage
 *
 * This implements the persistence layer, storing all trace data (connections,
 * requests, responses). This layer does nothing more than storing data,
 * reporting happens offline.
 */

type Storage struct {
	done         chan bool /* <-true : close db connection */
	closing      chan bool /* <-true : read all events and close */
	queue        chan Event
	c            *sqlite3.Conn
	insConn      *sqlite3.Stmt
	closeConn    *sqlite3.Stmt
	inLenConn    *sqlite3.Stmt
	outLenConn   *sqlite3.Stmt
	inCountConn  *sqlite3.Stmt
	outCountConn *sqlite3.Stmt
	insReq       *sqlite3.Stmt
	insResp      *sqlite3.Stmt
}

// constructor
func NewStorage() (*Storage, error) {
	var storage *Storage

	ctx, _ := context.WithCancel(context.Background())
	storage = &Storage{}
	/* TODO: if this buffer isn't large enough we start to loose responses
	   when shutting down. */
	storage.queue = make(chan Event, 10000)
	storage.done = make(chan bool)
	storage.closing = make(chan bool)

	go storage.run(ctx)

	return storage, nil
}

func (s *Storage) Close() {
	/* Tell the storage goroutine to read all the remaining messages and stop */
	s.closing <- true

	/* Wait for all inserts to be handled. */
	<-s.done
}

func (s *Storage) initPreparedStmts() error {
	/* Create a new temporary SQLite database */
	c, err := sqlite3.Open("trace.db")
	if err != nil {
		return err
	}
	s.c = c

	s.c.Exec("CREATE TABLE conns(id INTEGER, opentimestamp INTEGER, " +
		"closetimestamp INTEGER, src_ip TEXT, src_port INTEGER, " +
		"dst_ip string, dst_port INTEGER, inLength INTEGER, outLength INTEGER, " +
		"inCount INTEGER, outCount INTEGER)")

	/* Create prepared statements */
	sql := "INSERT into conns VALUES (?, ?, 0, ?, ?, ?, ?, 0, 0, 0, 0)"
	if s.insConn, err = s.c.Prepare(sql); err != nil {
		return err
	}

	s.closeConn, err = s.c.Prepare("UPDATE conns SET closetimestamp = ? " +
		"where id = ?")
	if err != nil {
		return err
	}
	s.inLenConn, err = s.c.Prepare("UPDATE conns SET inLength = inLength + ? " +
		"WHERE id = ?")
	if err != nil {
		return err
	}
	s.inCountConn, err = s.c.Prepare("UPDATE conns SET inCount = inCount + 1 " +
		"WHERE id = ?")
	if err != nil {
		return err
	}
	s.outLenConn, err = s.c.Prepare("UPDATE conns SET outLength = outLength + ? " +
		"WHERE id = ?")
	if err != nil {
		return err
	}
	s.outCountConn, err = s.c.Prepare("UPDATE conns SET outCount = outCount + 1 " +
		"WHERE id = ?")
	if err != nil {
		return err
	}
	s.c.Exec("CREATE TABLE reqresps(connID INTEGER, reqtimestamp INTEGER, reqId INTEGER," +
		"method TEXT, url TEXT, resptimestamp INTEGER, status INTEGER)")

	s.insReq, err = s.c.Prepare("INSERT into reqresps VALUES (" +
		"?, ?, ?, ?, ?, 0, 0)")
	if err != nil {
		return err
	}
	s.insResp, err = s.c.Prepare("UPDATE reqresps set resptimestamp = ?, " +
		"status = ? WHERE reqID = ? AND connID = ?")
	if err != nil {
		return err
	}
	return nil
}

func (s *Storage) cleanup() {
	close(s.queue)
	s.c.Close()
}

func (s *Storage) run(ctx context.Context) {
	_ = s.initPreparedStmts()
	defer s.cleanup()

	closing := false
	for {
		select {
		case event := <-s.queue:
			if err := event.Execute(s); err != nil {
				panic(err)
			}
			/* When we're closing, read until the queue is empty.
			   This assumes that the senders will stop queueing events
			   eventually. */
			if len(s.queue) == 0 && closing {
				s.done <- true
				return
			}
		case <-s.closing:
			// remaining := len(s.queue)
			//			fmt.Println("Cancelling storage, remaining on queue:", remaining)
			closing = true
		}
	}
}

func (s *Storage) PacketInScope(gopacket.Packet) bool {
	return true
}

func (s *Storage) queueEvent(e Event) {
	s.queue <- e
}

type Event interface {
	Execute(s *Storage) error
}

type OpenTCPConnectionEvent struct {
	connID    int64
	timestamp time.Time
}

func (e *OpenTCPConnectionEvent) Execute(s *Storage) error {
	return s.insConn.Exec(e.connID, e.timestamp.UnixNano(), "", 2, "", 3)
}

/* This is the API of the Storage object.
   These functions can be called from multiple goroutines, but serialize access
   to the database via a channel and one goroutine responsible for executing
   the queries */

/* TODO: fix ports */
func (s *Storage) OpenTCPConnection(connID uint64, timestamp time.Time) error {
	/* SQLite doesn't support uint64, convert to int64 */
	s.queueEvent(&OpenTCPConnectionEvent{int64(connID), timestamp})
	return nil
}

type IncomingTCPPacketEvent struct {
	connID        int64
	payloadLength int64
}

func (e *IncomingTCPPacketEvent) Execute(s *Storage) error {
	if err := s.inLenConn.Exec(e.payloadLength, e.connID); err != nil {
		return err
	} else if err = s.inCountConn.Exec(e.connID); err != nil {
		return err
	}
	return nil
}
func (s *Storage) IncomingTCPPacket(connID uint64, payloadLength uint32) error {
	s.queueEvent(&IncomingTCPPacketEvent{int64(connID), int64(payloadLength)})
	return nil
}

type OutgoingTCPPacketEvent struct {
	connID        int64
	payloadLength int64
}

func (e *OutgoingTCPPacketEvent) Execute(s *Storage) error {
	if err := s.outLenConn.Exec(e.payloadLength, e.connID); err != nil {
		return err
	} else if err = s.outCountConn.Exec(e.connID); err != nil {
		return err
	}
	return nil
}
func (s *Storage) OutgoingTCPPacket(connID uint64, payloadLength uint32) error {
	s.queueEvent(&OutgoingTCPPacketEvent{int64(connID), int64(payloadLength)})
	return nil
}

type SentRequestEvent struct {
	connID    int64
	reqID     int64
	timestamp time.Time
	method    string
	URL       string
}

func (e *SentRequestEvent) Execute(s *Storage) error {
	return s.insReq.Exec(e.connID, e.timestamp.UnixNano(), e.reqID,
		e.method, e.URL)
}

func (s *Storage) SentRequest(connID uint64, reqID int64, timestamp time.Time,
	req *http.Request) error {
	s.queueEvent(&SentRequestEvent{int64(connID), reqID, timestamp, req.Method,
		req.URL.String()})
	return nil
}

type ReceivedResponseEvent struct {
	connID     int64
	reqID      int64
	timestamp  time.Time
	statusCode int
}

func (e *ReceivedResponseEvent) Execute(s *Storage) error {
	return s.insResp.Exec(e.timestamp.UnixNano(), e.statusCode, e.reqID, e.connID)
}
func (s *Storage) ReceivedResponse(connID uint64, reqID int64, timestamp time.Time,
	resp *http.Response) error {
	s.queueEvent(&ReceivedResponseEvent{int64(connID), reqID, timestamp, resp.StatusCode})
	return nil
}
