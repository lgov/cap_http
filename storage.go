package main

import (
	"code.google.com/p/go-sqlite/go1/sqlite3"
	"code.google.com/p/gopacket"
	"fmt"
	"net/http"
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
}

// constructor
func NewStorage() (*Storage, error) {
	var storage *Storage

	/* Create a new temporary SQLite database */
	c, err := sqlite3.Open("")
	if err != nil {
		return nil, err
	}

	storage = &Storage{c, nil}

	c.Exec("CREATE TABLE conns(id int64, src_ip string, src_port int, " +
		"dst_ip string, dst_port int)")
	storage.insConn, err = c.Prepare("INSERT into conns VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		return nil, err
	}

	return storage, err
}

func (s *Storage) packetInScope(gopacket.Packet) bool {
	return true
}

func (s *Storage) newTCPConnection(id uint64, inFlow, outFlow gopacket.Flow) error {
	s.insConn.Exec(id, "", 2, "", 3)
	return nil
}

func (s *Storage) sentRequest(req *http.Request) error {
	return nil
}

func (s *Storage) receivedResponse(resp *http.Response) error {
	return nil
}

/* TODO: This function will probably need to move to another layer. */
func (s *Storage) report() error {
	fmt.Println()

	sql := "SELECT count(*) from conns"
	stmt, err := s.c.Query(sql)
	if err != nil {
		return err
	}
	var nrOfConnections int
	stmt.Scan(&nrOfConnections)
	fmt.Printf("NrOfConnections: %d\n", nrOfConnections)

	return nil
}
