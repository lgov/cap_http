package main

import (
	"code.google.com/p/go-sqlite/go1/sqlite3"
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
	c         *sqlite3.Conn
	insConn   *sqlite3.Stmt
	closeConn *sqlite3.Stmt
	insReq    *sqlite3.Stmt
	insResp   *sqlite3.Stmt
}

// constructor
func NewStorage() (*Storage, error) {
	var storage *Storage

	/* Create a new temporary SQLite database */
	c, err := sqlite3.Open("trace.db")
	if err != nil {
		return nil, err
	}

	storage = &Storage{c, nil, nil, nil, nil}

	c.Exec("CREATE TABLE conns(id INTEGER, opentimestamp INTEGER, " +
		"closetimestamp INTEGER, src_ip TEXT, src_port INTEGER, " +
		"dst_ip string, dst_port INTEGER)")
	storage.insConn, err = c.Prepare("INSERT into conns VALUES (?, ?, 0, ?, ?, ?, ?)")
	if err != nil {
		return nil, err
	}
	storage.closeConn, err = c.Prepare("UPDATE conns SET closetimestamp = ? " +
		"where id = ?")
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
		"status = ? WHERE reqID = ?")
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

func (s *Storage) SentRequest(connID uint64, reqID int64, timestamp time.Time,
	req *http.Request) error {
	return s.insReq.Exec(int64(connID), timestamp.UnixNano(), reqID,
		req.Method, req.URL.String())
}

func (s *Storage) ReceivedResponse(connID uint64, reqID int64, timestamp time.Time,
	resp *http.Response) error {
	return s.insResp.Exec(timestamp.UnixNano(), resp.StatusCode, reqID)
}

func (s *Storage) avgWaitingTime(connID int64) (float64, error) {
	var stmt *sqlite3.Stmt
	var err error

	var avgWaitingTimeNS float64
	sql := "SELECT AVG(resptimestamp - reqtimestamp) FROM reqresps WHERE connID=? " +
		" AND status != 0"
	if stmt, err = s.c.Query(sql, connID); err != nil {
		return 0.0, err
	}
	stmt.Scan(&avgWaitingTimeNS)

	return avgWaitingTimeNS, nil
}

func (s *Storage) arrivalRate(connID int64) (float64, error) {
	var stmt *sqlite3.Stmt
	var err error

	var nrOfRequests int64
	sql := "SELECT count(*) FROM reqresps WHERE connID=?"
	if stmt, err = s.c.Query(sql, connID); err != nil {
		return 0.0, err
	}
	stmt.Scan(&nrOfRequests)

	var minReqTS, maxReqTS int64
	sql = "SELECT MIN(reqtimestamp), MAX(reqtimestamp) from reqresps WHERE connID=?"
	if stmt, err = s.c.Query(sql, connID); err != nil {
		return 0.0, err
	}
	stmt.Scan(&minReqTS, &maxReqTS)
	reqTimeRangeNS := maxReqTS - minReqTS

	/* If there was only one request, set the arrival rate to 0. */
	if reqTimeRangeNS == 0 {
		return 0.0, nil
	}

	arrivalRatePerNS := float64(nrOfRequests) / float64(reqTimeRangeNS)
	return arrivalRatePerNS, nil
}

func (s *Storage) avgQueueLength(connID int64) (float64, error) {

	var err error

	/* Arrival rate */
	var arrivalRatePerNS float64
	if arrivalRatePerNS, err = s.arrivalRate(connID); err != nil {
		return 0.0, err
	}

	/* Average waiting time */
	var avgWaitingTimeNS float64
	if avgWaitingTimeNS, err = s.avgWaitingTime(connID); err != nil {
		return 0.0, err
	}

	avgQueueSize := arrivalRatePerNS * avgWaitingTimeNS
	return avgQueueSize, nil
}

/* TODO: This function will probably need to move to another layer. */
func (s *Storage) Report() error {
	fmt.Println()

	var stmt *sqlite3.Stmt
	sql := "SELECT id, opentimestamp FROM conns"
	i := 0

	fmt.Printf("Conn\t# reqs\t# noresp  avg queue  per method\t\n")
	for connstmt, err := s.c.Query(sql); err == nil; err = connstmt.Next() {
		i++

		var connID int64
		var nsec int64
		connstmt.Scan(&connID, &nsec)

		fmt.Printf("%4d\t", i)
		var nrOfRequests int64
		sql = "SELECT count(*) FROM reqresps WHERE connID=?"
		if stmt, err = s.c.Query(sql, connID); err != nil {
			return err
		}
		stmt.Scan(&nrOfRequests)
		fmt.Printf("%6d\t", nrOfRequests)

		var nrOfRequestsNoResp int64
		sql = "SELECT count(*) FROM reqresps where status = 0 AND connID=?"
		if stmt, err = s.c.Query(sql, connID); err != nil {
			return err
		}
		stmt.Scan(&nrOfRequestsNoResp)
		fmt.Printf("%8d  ", nrOfRequestsNoResp)

		var avgQueueLength float64
		if avgQueueLength, err = s.avgQueueLength(connID); err != nil {
			return err
		}
		fmt.Printf("%9.1f  ", avgQueueLength)

		sql = "SELECT method, count(method) FROM reqresps WHERE connID=? GROUP BY method " +
			" ORDER BY reqtimestamp "
		for stmt, err = s.c.Query(sql, connID); err == nil; err = stmt.Next() {
			var method string
			var nrOfRequestsPerMethod int64
			stmt.Scan(&method, &nrOfRequestsPerMethod)
			fmt.Printf("%s:%d ", method, nrOfRequestsPerMethod)
		}

		fmt.Printf("\t\n")
	}

	/* Average response time for each request */
	sql = "SELECT "
	return nil
}
