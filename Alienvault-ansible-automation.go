package main

import (
	"flag"
	"os"
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

type Host struct {
	Hostname string
	Port string
}

func main() {
	//vars
	var assets = make(map[string]*Host)
	subnet := flag.String("subnet-cidr", "", "Specify subnet to be scanned")
    ports := flag.String("p","22","Specify on wich ports SSH migt be listening on")
	username := flag.String("u","root","Specify an username that has access to all machines")
	password := flag.String("password","","Set a password for defined username")
    flag.Parse()

    // setup nmap scanner
	log.Println("[+] Setting Up NSE engine")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    defer cancel()
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

	//retrive hostnames and insert into a map
    for _, host := range result.Hosts {
		//host down
        if len(host.Ports) == 0 || len(host.Addresses) == 0 {
            continue
        }

		//init loop vars
		host_ipv4 := fmt.Sprintf("%s", host.Addresses[0])
        ptr, _ := net.LookupAddr(host_ipv4)
		assets[host_ipv4] = &Host{}

        for _, port := range host.Ports {
			port_str := fmt.Sprintf("%d",port.ID)
            if(port.Status() == "open") {
				if ptr != nil {
					hostname_ptr_recon := ""
					hostname_ptr_recon = strings.Split(ptr[0], ".")[0]
					assets[host_ipv4].Hostname = hostname_ptr_recon
					assets[host_ipv4].Port = port_str
				} else {
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
					//refreshing port number after nmap manipulation
					port_str = fmt.Sprintf("%d",port.ID)

					if(result.Hosts != nil) {
					    if warnings != nil {
					        fmt.Printf("[!] \n %v", warnings)
					    }
						nmap_hostname := result.Hosts[0].Ports[0].Scripts[0].Output
						if(strings.Contains(nmap_hostname, "Authentication Failed")){
							log.Println("[-] Login failed for host: "+ host_ipv4 + " could not determine hostname, to scan host consider to add a PTR record or provide valid host credentials")
						} else {
							nmap_hostname = strings.Replace(nmap_hostname, "output:", "", -1)
							nmap_hostname = strings.Replace(nmap_hostname, "\n", "", -1)
							nmap_hostname = strings.Replace(nmap_hostname, "\r", "", -1)
							nmap_hostname = strings.Replace(nmap_hostname, " ", "", -1)
							nmap_hostname = strings.Split(nmap_hostname, ".")[0]
							assets[host_ipv4].Hostname = nmap_hostname
							assets[host_ipv4].Port = port_str
						}
					}
				}
        	}
		}
	}
	// deleting elements with SSH problems
	for ip, host := range assets {
		if host.Port == "" && host.Hostname == "" {
			delete(assets, ip)
			log.Println("[-] SSH seems not to be listening on", ip, "at specified ports, and hostname cannot be determined by scanning PTR. Escluding host from inventory")
		}
	}


}

func check(e error) {
	if e != nil {
		log.Println(e)
		panic(e)
	}
}

//ssh config sshConfigGenerator
// ansible Inventory
//deploy
func sshConfigGenerator(assets map[string]*Host, user string) {
	for ip, host := range assets {
		log.Println("[*] Generating ssh config")
		//vars
		bt := 0
		f, err := os.Create("~/.ssh/config.test")
		check(err)
		defer f.Close()
	   	bc, err := f.WriteString("Host "+host.Hostname+"\n")
	   	bt += bc
	   	check(err)
	   	bc, err = f.WriteString("    User "+user+"\n")
	   	bt += bc
	   	check(err)
	   	bc, err = f.WriteString("    HostName "+ip+"\n")
	   	bt += bc
	   	check(err)
	   	bc, err = f.WriteString("    Port "+host.Port+"\n")
	   	bt += bc
	   	check(err)
	   	bc, err = f.WriteString("\n")
	   	bt += bc
	   	check(err)
		f.Sync()
		log.Println("[+] SSH config generated according to scanned hosts")
}
}
