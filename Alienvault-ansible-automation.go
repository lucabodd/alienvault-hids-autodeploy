package main

import (
	"flag"
	//"os"
	"fmt"
    "time"
    "context"
    "net"
	//ansibler "github.com/apenella/go-ansible"
	//"bytes"
	//"strings"
	//"github.com/tidwall/gjson"
    "github.com/Ullaakut/nmap"

)

func main() {
	subnet := flag.String("subnet-cidr", "", "Specify subnet to be scanned")
    ports := flag.String("p","22","Specify port to be scanned")
    flag.Parse()

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    defer cancel()

    // setup nmap scanner
    scanner, err := nmap.NewScanner(
        nmap.WithTargets(*subnet),
        nmap.WithPorts(*ports),
        nmap.WithContext(ctx),
    )
    check(err)

    result, warnings, err := scanner.Run()
    check(err)

    if warnings != nil {
        fmt.Printf("Warnings: \n %v", warnings)
    }

    // Use the results to print an example output
    for _, host := range result.Hosts {
        if len(host.Ports) == 0 || len(host.Addresses) == 0 {
            continue
        }

        fmt.Printf("Host %q:\n", host.Addresses[0])
        ptr, _ := net.LookupAddr(fmt.Sprintf("%q",host.Addresses[0]))
        fmt.Printf("%+v", ptr)

        for _, port := range host.Ports {
            fmt.Printf("\tPort %+v\n", port)
        }
    }

    fmt.Printf("Nmap done: %d hosts up scanned in %3f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}

func check(e error) {
	if e != nil {
		fmt.Println(e)
		panic(e)
	}
}
