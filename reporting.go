// Copyright 2014 Lieven Govaertr. All Rights Reserved.
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
	"fmt"
	"io"
)

type Reporting struct {
	c *sqlite3.Conn
}

// constructor
func NewReporting() (*Reporting, error) {
	// Open a connection to the sqlite db used for storage
	c, err := sqlite3.Open("trace.db")
	if err != nil {
		return nil, err
	}

	reporting := &Reporting{c: c}
	return reporting, nil
}

func (r *Reporting) avgWaitingTime(connID int64) (float64, error) {
	var stmt *sqlite3.Stmt
	var err error

	var avgWaitingTimeNS float64
	sql := "SELECT AVG(resptimestamp - reqtimestamp) FROM reqresps WHERE connID=? " +
		" AND status != 0"
	if stmt, err = r.c.Query(sql, connID); err != nil {
		return 0.0, err
	}
	stmt.Scan(&avgWaitingTimeNS)

	return avgWaitingTimeNS, nil
}

func (r *Reporting) arrivalRate(connID int64) (float64, error) {
	var stmt *sqlite3.Stmt
	var err error

	var nrOfRequests int64
	sql := "SELECT count(*) FROM reqresps WHERE connID=?"
	if stmt, err = r.c.Query(sql, connID); err != nil {
		return 0.0, err
	}
	stmt.Scan(&nrOfRequests)

	var reqTimeRangeNS int64
	sql = "SELECT MAX(reqtimestamp) - MIN(reqtimestamp) from reqresps WHERE connID=?"
	if stmt, err = r.c.Query(sql, connID); err != nil {
		return 0.0, err
	}
	stmt.Scan(&reqTimeRangeNS)

	/* If there was no or only one request, set the arrival rate to 0.0 . */
	if reqTimeRangeNS == 0 {
		return 0.0, nil
	}

	arrivalRatePerNS := float64(nrOfRequests) / float64(reqTimeRangeNS)
	return arrivalRatePerNS, nil
}

func (r *Reporting) avgQueueLength(connID int64) (float64, error) {

	var err error

	/* Arrival rate */
	arrivalRatePerNS, err := r.arrivalRate(connID)
	if err != nil {
		return 0.0, err
	}

	/* Average waiting time */
	avgWaitingTimeNS, err := r.avgWaitingTime(connID)
	if err != nil {
		return 0.0, err
	}

	avgQueueSize := arrivalRatePerNS * avgWaitingTimeNS
	return avgQueueSize, nil
}

func (r *Reporting) payloadLength(connID int64) (int64, int64, error) {

	var inLength, outLength int64

	sql := "SELECT inLength, outLength from conns WHERE id=?"
	stmt, err := r.c.Query(sql, connID)
	if err != nil {
		return 0, 0, err
	}

	stmt.Scan(&inLength, &outLength)

	return inLength, outLength, nil
}

func (r *Reporting) bandwidthUsage(connID int64) (inByteS float64, outByteS float64, err error) {

	/* Not ideal. TODO: track request bandwidth and response bandwidth separately. */
	var reqTimeRangeNS int64

	sql := "SELECT MAX(resptimestamp) - MIN(reqtimestamp) from reqresps WHERE connID=?"
	stmt, err := r.c.Query(sql, connID)
	if err != nil {
		return 0.0, 0.0, err
	}
	stmt.Scan(&reqTimeRangeNS)

	/* If there was no or only one request, set the arrival rate to 0.0 . */
	if reqTimeRangeNS == 0 {
		return 0.0, 0.0, nil
	}

	inLength, outLength, err := r.payloadLength(connID)
	if err != nil {
		return 0.0, 0.0, err
	}

	inByteS = float64(inLength) / (float64(reqTimeRangeNS) / (1000 * 1000 * 1000))
	outByteS = float64(outLength) / (float64(reqTimeRangeNS) / 1000000000)

	return inByteS, outByteS, nil
}

/* TODO: This function will probably need to move to another layer. */
func (r *Reporting) ReportConnSummary() error {
	fmt.Println()

	sql := "SELECT id, opentimestamp FROM conns"
	i := 0

	fmt.Printf("Conn\t# reqs\t# noresp  avg resp  avg queue  in MiB  out MiB  in KiB/s   out KiB/s  per method\t\n")
	for connstmt, err := r.c.Query(sql); err == nil; err = connstmt.Next() {
		i++

		var connID int64
		var nsec int64
		connstmt.Scan(&connID, &nsec)

		fmt.Printf("%4d\t", i)

		var nrOfRequests int64
		sql := "SELECT count(*) FROM reqresps WHERE connID=?"
		stmt, err := r.c.Query(sql, connID)
		if err != nil {
			return err
		}
		stmt.Scan(&nrOfRequests)
		fmt.Printf("%6d\t", nrOfRequests)

		var nrOfRequestsNoResp int64
		sql = "SELECT count(*) FROM reqresps where status = 0 AND connID=?"
		stmt, err = r.c.Query(sql, connID)
		if err != nil {
			return err
		}
		stmt.Scan(&nrOfRequestsNoResp)
		fmt.Printf("%8d  ", nrOfRequestsNoResp)

		/* Average waiting time */
		avgWaitingTimeNS, err := r.avgWaitingTime(connID)
		if err != nil {
			return err
		}
		fmt.Printf("%9.1f ", avgWaitingTimeNS/1000000000)

		avgQueueLength, err := r.avgQueueLength(connID)
		if err != nil {
			return err
		}
		fmt.Printf("%9.1f ", avgQueueLength)

		inLength, outLength, err := r.payloadLength(connID)
		if err != nil {
			return err
		}
		fmt.Printf("%7.2f  ", (float64(inLength) / (1024 * 1024)))
		fmt.Printf("%7.2f    ", (float64(outLength) / (1024 * 1024)))

		inByteS, outByteS, err := r.bandwidthUsage(connID)
		if err != nil {
			return err
		}
		fmt.Printf("%6.2f      ", inByteS/1024)
		fmt.Printf("%6.2f  ", outByteS/1024)

		/* requests per method type */
		sql = "SELECT method, count(method) FROM reqresps WHERE connID=? GROUP BY method " +
			" ORDER BY reqtimestamp "
		for stmt, err := r.c.Query(sql, connID); err == nil; err = stmt.Next() {
			var method string
			var nrOfRequestsPerMethod int64
			stmt.Scan(&method, &nrOfRequestsPerMethod)
			fmt.Printf("%s:%d ", method, nrOfRequestsPerMethod)
		}

		fmt.Printf("\t\n")
	}

	/* Average response time for each request */

	return nil
}

/* Note:
   sqlite uses a floor function when dividing a large number by 100000000000.
*/
func (r *Reporting) ReportReqsChart() error {
	fmt.Println()

	fmt.Println("Requests per second")

	var minReqTSns, maxReqTSns int64
	sql := "SELECT MIN(reqtimestamp), MAX(reqtimestamp) FROM reqresps"
	stmt, err := r.c.Query(sql)
	if err != nil {
		return err
	}
	stmt.Scan(&minReqTSns, &maxReqTSns)
	minReqTS := int64(minReqTSns / 1000000000)
	maxReqTS := int64(maxReqTSns / 1000000000)

	/* Print the report header */
	fmt.Printf("Conn\t")
	for i := minReqTS; i <= maxReqTS; i++ {
		fmt.Printf("%4d", i-minReqTS+1)
	}
	fmt.Println("   t(s)")

	sql = "SELECT id FROM conns"
	connnr := 0
	for connstmt, err := r.c.Query(sql); err == nil; err = connstmt.Next() {
		var connID int64
		connstmt.Scan(&connID)

		connnr++
		fmt.Printf("%4d\t", connnr)

		args := sqlite3.NamedArgs{"$connID": connID, "$ref": minReqTSns, "$conv": 1000000000}
		sql = "SELECT ((reqtimestamp-$ref) / $conv), " +
			"COUNT((reqtimestamp-$ref) / $conv) " +
			"FROM reqresps WHERE connID = $connID GROUP BY ((reqtimestamp-$ref) / $conv) " +
			"ORDER BY reqtimestamp"

		i := int64(0)
		tsstmt, err := r.c.Query(sql, args)
		if err == io.EOF {
			fmt.Println("- n/a -")
			continue
		}
		for ; err == nil; err = tsstmt.Next() {
			var reqsTS, reqCount int64
			tsstmt.Scan(&reqsTS, &reqCount)

			for ; i < reqsTS; i++ {
				fmt.Printf("    ")
			}
			fmt.Printf("%4d", reqCount)
			i++
		}
		fmt.Println()
	}
	return nil
}

func (r *Reporting) ReportRespsChart() error {
	fmt.Println()

	fmt.Println("Responses per second")

	var minReqTSns, maxRespTSns int64
	// Start counting from when the first request was sent, so the report is
	// lined out with the request report.
	sql := "SELECT MIN(reqtimestamp), MAX(resptimestamp) FROM reqresps"
	stmt, err := r.c.Query(sql)
	if err != nil {
		return err
	}
	stmt.Scan(&minReqTSns, &maxRespTSns)
	minReqTS := int64(minReqTSns / 1000000000)
	maxRespTS := int64(maxRespTSns / 1000000000)

	/* Print the report header */
	fmt.Printf("Conn\t")
	var i int64
	for i = 1; i <= maxRespTS-minReqTS+1; i++ {
		fmt.Printf("%4d", i)
	}
	fmt.Println("   t(s)")

	sql = "SELECT id FROM conns"
	connnr := 0
	for connstmt, err := r.c.Query(sql); err == nil; err = connstmt.Next() {
		var connID int64
		connstmt.Scan(&connID)

		connnr++
		fmt.Printf("%4d\t", connnr)

		args := sqlite3.NamedArgs{"$connID": connID, "$ref": minReqTSns, "$conv": 1000000000}
		sql = "SELECT ((resptimestamp-$ref)/$conv), COUNT((resptimestamp-$ref)/$conv) " +
			"FROM reqresps WHERE connID=$connID AND resptimestamp != 0 " +
			"GROUP BY ((resptimestamp-$ref)/$conv) ORDER BY resptimestamp"

		i := int64(0)
		tsstmt, err := r.c.Query(sql, args)
		if err == io.EOF {
			fmt.Println("- n/a -")
			continue
		}
		for ; err == nil; err = tsstmt.Next() {
			var respsTS, respCount int64
			tsstmt.Scan(&respsTS, &respCount)

			for ; i < respsTS; i++ {
				fmt.Printf("    ")
			}
			fmt.Printf("%4d", respCount)
			i++
		}
		fmt.Println()
	}
	return nil
}

func (r *Reporting) ReportPipelinedReqsChart() error {
	fmt.Println()

	fmt.Println("Requests pipelined per second")

	var minReqTSns, maxRespTSns int64
	// Start counting from when the first request was sent, so the report is
	// lined out with the request report.
	sql := "SELECT MIN(reqtimestamp), MAX(resptimestamp) FROM reqresps"
	stmt, err := r.c.Query(sql)
	if err != nil {
		return err
	}
	stmt.Scan(&minReqTSns, &maxRespTSns)
	minReqTS := int64(minReqTSns / 1000000000)
	maxRespTS := int64(maxRespTSns / 1000000000)

	/* Print the report header */
	fmt.Printf("Conn\t")
	var i int64
	for i = 1; i <= maxRespTS-minReqTS+1; i++ {
		fmt.Printf("%4d", i)
	}
	fmt.Println("   t(s)")

	sql = "SELECT id FROM conns"
	connnr := 0
	MAXINT64 := int64(^uint64(0) >> 1)
	for connstmt, err := r.c.Query(sql); err == nil; err = connstmt.Next() {
		var connID int64
		connstmt.Scan(&connID)

		connnr++
		fmt.Printf("%4d\t", connnr)

		args := sqlite3.NamedArgs{"$connID": connID, "$ref": minReqTSns, "$conv": 1000000000}
		sql = "SELECT ((reqtimestamp-$ref) / $conv), " +
			"COUNT((reqtimestamp-$ref) / $conv) " +
			"FROM reqresps WHERE connID = $connID GROUP BY ((reqtimestamp-$ref) / $conv) " +
			"ORDER BY reqtimestamp"
		reqstmt, err := r.c.Query(sql, args)
		if err != nil && err != io.EOF {
			return err
		}

		args = sqlite3.NamedArgs{"$connID": connID, "$ref": minReqTSns, "$conv": 1000000000}
		sql = "SELECT ((resptimestamp-$ref)/$conv), COUNT((resptimestamp-$ref)/$conv) " +
			"FROM reqresps WHERE connID=$connID AND resptimestamp != 0 " +
			"GROUP BY ((resptimestamp-$ref)/$conv) ORDER BY resptimestamp"
		respstmt, err := r.c.Query(sql, args)
		if err != nil && err != io.EOF {
			return err
		}
		if reqstmt == nil || respstmt == nil {
			fmt.Println("- n/a -")
			continue
		}

		/* Create a table with the actual nr of outstanding requests per
		   timestamp. The table only contains those timestamps where the
		   counts change. */
		var reqCount, respCount int64
		reqsTS := MAXINT64
		respsTS := MAXINT64
		reqsAtTS := make(map[int64]int64)
		curReqs := int64(0)
		nextTS := int64(0)
		err = reqstmt.Scan(&reqsTS, &reqCount)
		if err != nil && err != io.EOF {
			return err
		}
		err = respstmt.Scan(&respsTS, &respCount)
		if err != nil && err != io.EOF {
			return err
		}

		for { /* reqsTS < ^int64(0) && respsTS < ^int64(0) */
			usedReqTS := false
			usedRespTS := false
			if reqsTS == respsTS {
				nextTS = reqsTS
				curReqs += (reqCount - respCount)
				usedReqTS = true
				usedRespTS = true
			} else if reqsTS < respsTS {
				nextTS = reqsTS
				curReqs += reqCount
				usedReqTS = true
			} else {
				nextTS = respsTS
				curReqs -= respCount
				usedRespTS = true
			}
			reqsAtTS[nextTS] = curReqs

			/* Find the next request timestamp */
			if usedReqTS {
				if err = reqstmt.Next(); err == nil {
					reqstmt.Scan(&reqsTS, &reqCount)
				} else if err == io.EOF {
					reqsTS = MAXINT64
				} else {
					return err
				}
			}

			/* Find the next response timestamp */
			if usedRespTS {
				if err = respstmt.Next(); err == nil {
					respstmt.Scan(&respsTS, &respCount)
				} else if err == io.EOF {
					respsTS = MAXINT64
				} else {
					return err
				}
			}

			if reqsTS == MAXINT64 && respsTS == MAXINT64 {
				break
			}
		}

		//      fmt.Println(reqsAtTS)
		curReqs = int64(0)
		prevReqs := int64(0)
		connOpen := false
		for i := int64(0); i <= maxRespTS-minReqTS; i++ {
			if curReqs, ok := reqsAtTS[i]; ok {
				fmt.Printf("%4d", curReqs)
				prevReqs = curReqs
				connOpen = true
			} else {
				if !connOpen {
					fmt.Printf("    ")
				} else {
					fmt.Printf("%4d", prevReqs)
				}
			}
		}
		fmt.Println()
	}
	return nil
}

func (r *Reporting) Report() error {
	err := r.ReportConnSummary()
	if err != nil {
		return err
	}

	err = r.ReportReqsChart()
	if err != nil {
		return err
	}

	err = r.ReportRespsChart()
	if err != nil {
		return err
	}

	err = r.ReportPipelinedReqsChart()
	if err != nil {
		return err
	}

	return nil
}
