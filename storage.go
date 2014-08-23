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
	"code.google.com/p/gopacket"
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
	c          *sqlite3.Conn
	insConn    *sqlite3.Stmt
	closeConn  *sqlite3.Stmt
	inLenConn  *sqlite3.Stmt
	outLenConn *sqlite3.Stmt
	insReq     *sqlite3.Stmt
	insResp    *sqlite3.Stmt
}

// constructor
func NewStorage() (*Storage, error) {
	var storage *Storage

	/* Create a new temporary SQLite database */
	c, err := sqlite3.Open("trace.db")
	if err != nil {
		return nil, err
	}

	storage = &Storage{c: c}

	c.Exec("CREATE TABLE conns(id INTEGER, opentimestamp INTEGER, " +
		"closetimestamp INTEGER, src_ip TEXT, src_port INTEGER, " +
		"dst_ip string, dst_port INTEGER, inLength INTEGER, outLength INTEGER)")

	/* Create prepared statements */
	sql := "INSERT into conns VALUES (?, ?, 0, ?, ?, ?, ?, 0, 0)"
	if storage.insConn, err = c.Prepare(sql); err != nil {
		return nil, err
	}

	storage.closeConn, err = c.Prepare("UPDATE conns SET closetimestamp = ? " +
		"where id = ?")
	if err != nil {
		return nil, err
	}
	storage.inLenConn, err = c.Prepare("UPDATE conns SET inLength = inLength + ? " +
		"WHERE id = ?")
	if err != nil {
		return nil, err
	}
	storage.outLenConn, err = c.Prepare("UPDATE conns SET outLength = outLength + ? " +
		"WHERE id = ?")
	if err != nil {
		return nil, err
	}

	c.Exec("CREATE TABLE reqresps(connID INTEGER, reqtimestamp INTEGER, reqId INTEGER," +
		"method TEXT, url TEXT, resptimestamp INTEGER, status INTEGER)")
	storage.insReq, err = c.Prepare("INSERT into reqresps VALUES (" +
		"?, ?, ?, ?, ?, 0, 0)")
	if err != nil {
		return nil, err
	}
	storage.insResp, err = c.Prepare("UPDATE reqresps set resptimestamp = ?, " +
		"status = ? WHERE reqID = ? AND connID = ?")
	if err != nil {
		return nil, err
	}

	return storage, err
}

func (s *Storage) PacketInScope(gopacket.Packet) bool {
	return true
}

/* TODO: fix ports */
func (s *Storage) OpenTCPConnection(connID uint64, timestamp time.Time) error {
	/* SQLite doesn't support uint64, convert to int64 */
	return s.insConn.Exec(int64(connID), timestamp.UnixNano(), "",
		2, "", 3)
}
func (s *Storage) IncomingTCPPacket(connID uint64, payloadLength uint32) error {
	return s.inLenConn.Exec(int64(payloadLength), int64(connID))
}
func (s *Storage) OutgoingTCPPacket(connID uint64, payloadLength uint32) error {
	return s.outLenConn.Exec(int64(payloadLength), int64(connID))
}
func (s *Storage) SentRequest(connID uint64, reqID int64, timestamp time.Time,
	req *http.Request) error {
	return s.insReq.Exec(int64(connID), timestamp.UnixNano(), reqID,
		req.Method, req.URL.String())
}

func (s *Storage) ReceivedResponse(connID uint64, reqID int64, timestamp time.Time,
	resp *http.Response) error {
	return s.insResp.Exec(timestamp.UnixNano(), resp.StatusCode, reqID, int64(connID))
}
