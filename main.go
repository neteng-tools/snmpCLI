package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Device struct {
	Hostname string
	Version  string
}

func readCSV(filename string) ([][]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return [][]string{}, err
	}
	defer f.Close()

	// Read File into a Variable
	lines, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return [][]string{}, err
	}
	deviceMap := make(map[string][]Device)
	for _, element := range lines {
		deviceMap[element[0]] = append(deviceMap[element[0]], Device{
			Hostname: element[1],
			Version:  element[2],
		})
	}
	fmt.Println(deviceMap)
	os.Exit(1)

	return lines, err
}

// var columns = []string{"1.3.6.1.4.1.868.2.80.2.1.1.1.1.2.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.43.11.1.1.8.1.1", "1.3.6.1.2.1.16.19.2.0", "1.3.6.1.4.1.868.2.80.2.1.1.1.1.2.1"}

//[]string{"10.230.254.20"}

type snmpCreds struct {
	Username *string
	Priv     *string
	Auth     *string
}
type snmpInput struct {
	Method   *string
	Version  *string
	AuthType *string
	PrivType *string
	Oid      *string
	Verbose  *bool
}

func main() {
	var creds snmpCreds
	var input snmpInput
	ipAdd := flag.String("t", "", "Define target devices. (-t 10.0.0.1 or -t 10.0.0.1-100 or -t 10.0.0.1,10.0.0.2)")

	input.Method = flag.String("m", "Get", "Set snmp method. -m Get or -m Walk.")
	input.Version = flag.String("v", "3", "Set snmp version. -v 1, -v 2c, -v 3")
	input.PrivType = flag.String("pt", "AES", "Enter SNMPv3 Priv Type. -pt AES, -pt AES192, -pt AES256")
	input.AuthType = flag.String("at", "SHA", "Enter SNMPv3 Auth Type. -at SHA, -at SHA256, -at SHA512")
	input.Oid = flag.String("o", "1.3.6.1.2.1.1.1.0", "Enter OIDs to grab separated by a comma. You can also use this for a Walk (Ex. 1.3.6)")
	input.Verbose = flag.Bool("vv", false, "Enable verbose output")

	creds.Username = flag.String("c", "public", "Set snmp community string or v3 User Name")
	creds.Auth = flag.String("a", "", "Provide Authentication Password")
	creds.Priv = flag.String("p", "", "Provide Privacy Password")

	flag.Parse()
	start := time.Now()
	var waitGroup sync.WaitGroup
	count := 0
	ipList := strings.Split(*ipAdd, ",")

	for _, ipGate := range ipList {
		netID := strings.Split(ipGate, ".")
		netRangeSlice := strings.Split(netID[3], "-")
		var netRangeEnd int
		netRangeStart, err := strconv.Atoi(netRangeSlice[0])
		if err != nil {
			log.Fatalf("Starting IP not valid: %v", err)
		}
		if len(netRangeSlice) == 1 {
			netRangeEnd, err = strconv.Atoi(netRangeSlice[0])
			if err != nil {
				log.Fatalf("Ending IP not valid: %v", err)
			}
		} else {
			netRangeEnd = netRangeStart
		}

		for i := netRangeStart; i <= netRangeEnd; i++ {
			ipAddr := netID[0] + "." + netID[1] + "." + netID[2] + "." + strconv.Itoa(i)
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				snmpScan(ipAddr, creds, input)
			}()
			if count > 200 { //only allows 200 routines at once. TODO: Needs replaced with real logic at some point to manage snmp connections.
				time.Sleep(time.Duration(500 * time.Millisecond))
				count = 0
			}
			count++
		}
	}
	waitGroup.Wait()
	duration := time.Since(start)
	if *input.Verbose {
		log.Print(duration)
	}
}
