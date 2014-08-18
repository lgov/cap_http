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

	/* If there was no or only one request, set the arrival rate to 0.0 . */
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

func (s *Storage) payloadLength(connID int64) (int64, int64, error) {
	var stmt *sqlite3.Stmt
	var err error
	var inLength, outLength int64
	sql := "SELECT inLength, outLength from conns WHERE id=?"
	if stmt, err = s.c.Query(sql, connID); err != nil {
		return 0, 0, err
	}
	stmt.Scan(&inLength, &outLength)
	return inLength, outLength, nil
}

func (s *Storage) bandwidthUsage(connID int64) (float64, float64, error) {
	var stmt *sqlite3.Stmt
	var err error

	/* Not ideal. TODO: track request bandwidth and response bandwidth separately. */
	var minReqTS, maxRespTS int64
	sql := "SELECT MIN(reqtimestamp), MAX(resptimestamp) from reqresps WHERE connID=?"
	if stmt, err = s.c.Query(sql, connID); err != nil {
		return 0.0, 0.0, err
	}
	stmt.Scan(&minReqTS, &maxRespTS)
	reqTimeRangeNS := maxRespTS - minReqTS

	/* If there was no or only one request, set the arrival rate to 0.0 . */
	if reqTimeRangeNS == 0 {
		return 0.0, 0.0, nil
	}

	var inLength, outLength int64
	if inLength, outLength, err = s.payloadLength(connID); err != nil {
		return 0.0, 0.0, err
	}

	var inMiBs, outMiBs float64
	inMiBs = (float64(inLength) / (1024 * 1024)) / (float64(reqTimeRangeNS) / 1000000000)
	outMiBs = (float64(outLength) / (1024 * 1024)) / (float64(reqTimeRangeNS) / 1000000000)

	return inMiBs, outMiBs, nil
}

/* TODO: This function will probably need to move to another layer. */
func (s *Storage) Report() error {
	fmt.Println()

	var stmt *sqlite3.Stmt
	sql := "SELECT id, opentimestamp FROM conns"
	i := 0

	fmt.Printf("Conn\t# reqs\t# noresp  avg queue  in MiB  out MiB  in MiB/s   out MiB/s  per method\t\n")
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
		fmt.Printf("%9.1f ", avgQueueLength)

		var inLength, outLength int64
		if inLength, outLength, err = s.payloadLength(connID); err != nil {
			return err
		}

		fmt.Printf("%7.1f  ", (float64(inLength) / (1024 * 1024)))
		fmt.Printf("%7.1f      ", (float64(outLength) / (1024 * 1024)))

		var inMiBs, outMiBs float64
		if inMiBs, outMiBs, err = s.bandwidthUsage(connID); err != nil {
			return err
		}
		fmt.Printf("%4.1f        ", inMiBs)
		fmt.Printf("%4.1f  ", outMiBs)

		/* requests per method type */
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
