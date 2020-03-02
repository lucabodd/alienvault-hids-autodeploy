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
	"log"
	"strings"
)

func main() {
	subnet := flag.String("subnet-cidr", "", "Specify subnet to be scanned")
    ports := flag.String("p","22","Specify on wich ports SSH migt be listening on")
	username := flag.String("u","root","Specify an username that has access to all machines")
	password := flag.String("password","","Set a password for defined username")
    flag.Parse()

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    defer cancel()

    // setup nmap scanner
    scanner, err := nmap.NewScanner(
        nmap.WithTargets(*subnet),
        nmap.WithPorts(*ports),
        nmap.WithContext(ctx),
		nmap.WithOSScanGuess(),
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

		host_ipv4 := fmt.Sprintf("%s", host.Addresses[0])
        ptr, _ := net.LookupAddr(host_ipv4)
        fmt.Println("%s", ptr)

		fmt.Println(host_ipv4)
        for _, port := range host.Ports {
            if(port.Status() == "open") {
				port_str := fmt.Sprintf("%d",port.ID)
				scanner, err := nmap.NewScanner(
			        nmap.WithTargets(host_ipv4),
			        nmap.WithContext(ctx),
					nmap.WithPorts(port_str),
					nmap.WithScripts("./nse/ssh-run-uname"),
					nmap.WithScriptArguments(
						map[string]string{
							"ssh-run.port": port_str,
							"ssh-run.username": *username,
							"ssh-run.password": *password,
						}),
			    )
				result, warnings, err := scanner.Run()
			    check(err)

			    if warnings != nil {
			        fmt.Printf("Warnings: \n %v", warnings)
			    }
				nmap_hostname := result.Hosts[0].Ports[0].Scripts[0].Output
				if(strings.Contains(nmap_hostname, "Authentication Failed")){
					log.Println("[-] Login failed for host: "+ host_ipv4 + nmap_hostname)
				}
				fmt.Printf("[+] Ok: "+host_ipv4 + nmap_hostname)
				//fmt.Printf("%+v", result.Hosts[0].Ports[0].Scripts[0].Output)
			}
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
