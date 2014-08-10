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
	c       *sqlite3.Conn
	insConn *sqlite3.Stmt
	insReq  *sqlite3.Stmt
	insResp *sqlite3.Stmt
}

// constructor
func NewStorage() (*Storage, error) {
	var storage *Storage

	/* Create a new temporary SQLite database */
	c, err := sqlite3.Open("trace.db")
	if err != nil {
		return nil, err
	}

	storage = &Storage{c, nil, nil, nil}

	c.Exec("CREATE TABLE conns(id INTEGER, src_ip TEXT, src_port INTEGER, " +
		"dst_ip string, dst_port INTEGER)")
	storage.insConn, err = c.Prepare("INSERT into conns VALUES (?, ?, ?, ?, ?)")
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

func (s *Storage) packetInScope(gopacket.Packet) bool {
	return true
}

func (s *Storage) newTCPConnection(connID uint64) error {
	/* SQLite doesn't support uint64, convert to int64 */
	return s.insConn.Exec(int64(connID), "", 2, "", 3)
}

func (s *Storage) sentRequest(connID uint64, reqID int64, timestamp time.Time,
	req *http.Request) error {
	return s.insReq.Exec(int64(connID), time.Time.UnixNano(timestamp), reqID,
		req.Method, req.URL.String())
}

func (s *Storage) receivedResponse(connID uint64, reqID int64, timestamp time.Time,
	resp *http.Response) error {
	return s.insResp.Exec(time.Time.UnixNano(timestamp), resp.StatusCode, reqID)
}

/* TODO: This function will probably need to move to another layer. */
func (s *Storage) report() error {
	fmt.Println()

	var nrOfConnections int
	var stmt *sqlite3.Stmt
	var err error
	sql := "SELECT count(*) from conns"
	if stmt, err = s.c.Query(sql); err != nil {
		return err
	}
	stmt.Scan(&nrOfConnections)
	fmt.Printf("NrOfConnections: %d\n", nrOfConnections)

	var nrOfRequests int
	sql = "SELECT count(*) from reqresps"
	if stmt, err = s.c.Query(sql); err != nil {
		return err
	}
	stmt.Scan(&nrOfRequests)
	fmt.Printf("NrOfRequests: %d\n", nrOfRequests)

	var nrOfRequestsNoResp int
	sql = "SELECT count(*) from reqresps where status = 0"
	if stmt, err = s.c.Query(sql); err != nil {
		return err
	}
	stmt.Scan(&nrOfRequestsNoResp)
	fmt.Printf("  %d without response.\n", nrOfRequestsNoResp)

	sql = "SELECT method, count(method) FROM reqresps GROUP BY method;"
	for stmt, err = s.c.Query(sql); err == nil; err = stmt.Next() {
		var method string
		var nrOfRequestsPerMethod int
		stmt.Scan(&method, &nrOfRequestsPerMethod)
		fmt.Printf("  %d with method %s.\n", nrOfRequestsPerMethod, method)
	}

	/* Average response time for each request */
	sql = "SELECT "
	return nil
}
