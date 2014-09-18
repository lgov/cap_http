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
	"flag"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"
)

// Command line arguments
var iface = flag.String("ifce", "en0", "Interface to get packets from")
var inputfile = flag.String("infile", "", "read packets from file")
var logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")
var launchCmd = flag.String("e", "", "Launches the command and logs its traffic")
var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")

// createProcessEndedChannel creates and returns a channel that will be used
// to return the exit code of command CMD after it's finished.
func createProcessEndedChannel(cmd *exec.Cmd) (cmd_done chan error) {
	cmd_done = make(chan error, 1)
	go func() {
		cmd_done <- cmd.Wait()
	}()
	return cmd_done
}

// createCtrlCchannel creates and returns a channel that will be used to signal
// the user typing CTRL-C.
func createCtrlCchannel() (ctrlc chan os.Signal) {
	ctrlc = make(chan os.Signal, 1)
	signal.Notify(ctrlc, os.Interrupt)
	return
}

// createTimeoutChannel creates and returns a channel, starts a timer of
// duration T and send TRUE over the channel when that durations passes.
func createTimeoutChannel(t time.Duration) (timeout chan bool) {
	timeout = make(chan bool, 1)
	go func() {
		time.Sleep(t * time.Second)
		timeout <- true
	}()
	return
}

func createNetDescChannel() (netDescs chan NetDescriptor) {
	netDescSource := NewOSXNetDescSource()
	netDescs = netDescSource.Descriptors()
	return
}

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	//	log.SetOutput(ioutil.Discard)

	// run the http reader goroutines on all available CPU cores
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Setup profiler
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer f.Close()
		defer pprof.StopCPUProfile()
	}

	// Set up storage layer
	storage, err := NewStorage()
	if err != nil {
		panic(err)
	}

	// Setup CTRL-C handler channel
	ctrlc := createCtrlCchannel()

	// Setup channel that reports all socket kernel events (Mac OS X only)
	//	netDescs := createNetDescChannel()

	packetLayer := NewPacketLayer(storage)
	packets := packetLayer.CreatePacketsChannel()

	// Run the external command
	//	pid := uint32(0)
	var cmd_done chan error
	var start_time time.Time
	if *launchCmd != "" {
		s := *launchCmd
		args := strings.Split(s, " ")
		cmd := exec.Command(args[0], args[1:]...)
		start_time = time.Now()
		cmd_stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Fatal(err)
		}
		err = cmd.Start()
		if err != nil {
			panic(err)
		}
		go io.Copy(os.Stdout, cmd_stdout)
		// Create the channel that listens for the end of the command.
		cmd_done = createProcessEndedChannel(cmd)
		//		pid = uint32(cmd.Process.Pid)
	}

	var timeout chan bool
loop:
	for {
		select {
		/*		case netDesc := <-netDescs:
				if netDesc.Pid == pid {
					log.Println("event received ", netDesc)
				}*/
		case packet, ok := <-packets:
			if !ok {
				log.Println("All data read")
				packets = nil
				timeout = createTimeoutChannel(0)
				break
			}

			if packet == nil {
				break
			}

			if *logAllPackets {
				log.Println(packet)
			}

			packetLayer.HandlePacket(packet)
		case err := <-cmd_done:
			if err != nil {
				log.Printf("process done with error = %v\n", err)
			}

			log.Println("Process took: ", time.Now().Sub(start_time))

			// Wait for a couple of seconds, just enough to get the events
			// handled by the main function.
			log.Println("Waiting for the remaining responses to arrive.")
			timeout = createTimeoutChannel(10)
		case <-ctrlc:
			// Don't wait.
			timeout = createTimeoutChannel(0)
		case <-timeout:
			break loop
		}
	}

	signal.Stop(ctrlc)

	packetLayer.Close()

	// Close the storage layer. This will block until all pending inserts in
	// the db are handled.
	storage.Close()

	reporting, err := NewReporting()
	if err != nil {
		panic(err)
	}

	if err = reporting.Report(); err != nil {
		log.Panic(err)
	}

	os.Exit(0)

}
