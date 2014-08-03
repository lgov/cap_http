package main

import (
	"code.google.com/p/gopacket"
	"fmt"
)

type Analyser struct {
	nrOfConnections uint
}

// constructor
func NewAnalyser() *Analyser {
	return &Analyser{}
}

func (a *Analyser) packetInScope(gopacket.Packet) bool {
	return true
}

func (a *Analyser) newTCPConnection() {
	a.nrOfConnections++
}

func (a *Analyser) receivedResponse() {

}

func (a *Analyser) report() {
	fmt.Printf("NrOfConnections: %d\n", a.nrOfConnections)
}
