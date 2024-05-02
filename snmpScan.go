package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	//"github.com/Rldeckard/aesGenerate256/authGen"
	"github.com/go-ping/ping"
	g "github.com/gosnmp/gosnmp"
)

func snmpScan(target string, creds snmpCreds, input snmpInput) {

	var m sync.Mutex

	pinger, pingErr := ping.NewPinger(target)
	if pingErr != nil {
		fmt.Println("timed out: " + pingErr.Error())
	}
	pinger.Count = 3
	pinger.SetPrivileged(true)
	pinger.Timeout = 2000 * time.Millisecond //times out after 500 milliseconds
	pinger.Run()                             // blocks until finished
	stats := pinger.Statistics()
	// get send/receive/rtt stats
	if stats.PacketsRecv == 0 {
		return
	}
	// build our own GoSNMP struct, rather than using g.Default
	params := g.GoSNMP{
		Target:        target,
		Port:          161,
		SecurityModel: g.UserSecurityModel,
		MsgFlags:      g.AuthPriv,
		Timeout:       1 * time.Second,
	}
	if *input.Verbose {
		fmt.Println("SNMP Version: " + *input.Version)
	}
	if *input.Version == "3" {
		params.Version = g.Version3
		privVar := map[string]g.SnmpV3PrivProtocol{
			"AES":    g.AES,
			"AES192": g.AES192,
			"AES256": g.AES256C,
		}
		authVar := map[string]g.SnmpV3AuthProtocol{
			"SHA":    g.SHA,
			"SHA256": g.SHA256,
			"SHA512": g.SHA512,
		}

		params.SecurityParameters = &g.UsmSecurityParameters{
			UserName:                 *creds.Username,
			AuthenticationProtocol:   authVar[*input.AuthType],
			AuthenticationPassphrase: *creds.Auth,
			PrivacyProtocol:          privVar[*input.PrivType],
			PrivacyPassphrase:        *creds.Priv,
		}
	} else if *input.Version == "2c" {
		params.Version = g.Version2c
		params.Community = *creds.Username
	} else {
		params.Version = g.Version1
		params.Community = *creds.Username
	}

	err := params.Connect()
	if err != nil {
		m.Lock()
		defer m.Unlock()
		fmt.Println(target + ": error connecting " + err.Error())
		return
	}
	if *input.Verbose {
		fmt.Println("connected to: " + target)
	}
	defer params.Conn.Close()
	if *input.Method == "Walk" {
		//basically says to change default if not specified. This OID is currently the default for a Get request. Probably needs to be done better
		if *input.Oid == "1.3.6.1.2.1.1.1.0" {
			*input.Oid = "1.3.6"
		}
		if *input.Verbose {
			fmt.Println("Walking devices from: " + *input.Oid)
		}
		var count int
		var walkPayLoad bytes.Buffer
		err := params.Walk(*input.Oid, func(pdu g.SnmpPDU) error {
			switch v := pdu.Value.(type) {
			case []byte:
				decodedString := hex.EncodeToString(v)
				var macString string
				if len(decodedString) == 12 {
					for i := 0; i < len(decodedString); i++ {
						if i%2 == 0 && i != 0 {
							macString += ":"
						}
						macString += strings.ToUpper(string(decodedString[i]))

					}
					walkPayLoad.WriteString(pdu.Name)
					walkPayLoad.WriteString(": ")
					walkPayLoad.WriteString(macString)
					walkPayLoad.WriteString("\n")
				} else {
					walkPayLoad.WriteString(pdu.Name + ": " + string(v) + "\n")
				}
			case string:
				walkPayLoad.WriteString(pdu.Name)
				walkPayLoad.WriteString(": ")
				walkPayLoad.WriteString(v)
				walkPayLoad.WriteString("\n")
			case uint, uint16, uint64, uint32, int:
				walkPayLoad.WriteString(pdu.Name)
				walkPayLoad.WriteString(": ")
				walkPayLoad.WriteString(fmt.Sprint(v) + "\n")
			default:
				walkPayLoad.WriteString("*" + pdu.Name)
				walkPayLoad.WriteString(": ")
				walkPayLoad.WriteString(fmt.Sprint(v))
				walkPayLoad.WriteString(reflect.TypeOf(v).Name() + "\n")
			}
			if count > *input.LineSize {
				fmt.Println(walkPayLoad.String())
				count = 0
				walkPayLoad.Reset()
			}
			count++
			return nil
		})
		if err != nil {
			fmt.Println("Error walking device: " + err.Error())
			return
		}
		return
	}
	if *input.Method == "Get" {
		oids := strings.Split(*input.Oid, ",")
		result, err := params.Get(oids)
		if err != nil {
			//ignore devices that aren't needed.
			return
		}
		var rows []string
		for _, variable := range result.Variables {
			if variable.Value != nil {
				switch v := variable.Value.(type) {
				case string:
					rows = append(rows, variable.Value.(string))
				case []uint8:
					decodedString, err := hex.DecodeString(string(v))
					if err != nil {
						rows = append(rows, string(v))
					} else {
						fmt.Println(hex.EncodeToString(decodedString))
					}
				case int:
					rows = append(rows, fmt.Sprint(v))
				default:
					fmt.Println(v)
					rows = append(rows, "Unhandled SNMP output")
				}
			}

		}
		if len(rows) == 1 {
			fmt.Println(rows[0])
		} else {
			m.Lock()
			fmt.Printf("%s,[%v],[%s]\n", target, strings.Join(rows, ":::"), strings.Join(oids, ":::"))
			m.Unlock()
		}
	}

}
