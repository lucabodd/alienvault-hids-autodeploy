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
	//vars
	var assets = make(map[string]string)
	subnet := flag.String("subnet-cidr", "", "Specify subnet to be scanned")
    ports := flag.String("p","22","Specify on wich ports SSH migt be listening on")
	username := flag.String("u","root","Specify an username that has access to all machines")
	password := flag.String("password","","Set a password for defined username")
    flag.Parse()

    // setup nmap scanner
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

	//iterate trough scanned hosts
    for _, host := range result.Hosts {
		//host down
        if len(host.Ports) == 0 || len(host.Addresses) == 0 {
            continue
        }

		host_ipv4 := fmt.Sprintf("%s", host.Addresses[0])
        ptr, _ := net.LookupAddr(host_ipv4)

		if(ptr != nil){
			hostname_ptr_recon := ""
			hostname_ptr_recon = strings.Split(ptr[0], ".")[0]
			assets[host_ipv4] = hostname_ptr_recon
		} else {
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

					if(result.Hosts != nil) {
					    if warnings != nil {
					        fmt.Printf("Warnings: \n %v", warnings)
					    }
						nmap_hostname := result.Hosts[0].Ports[0].Scripts[0].Output
						if(strings.Contains(nmap_hostname, "Authentication Failed")){
							log.Println("[-] Login failed for host: "+ host_ipv4 + " could not determine hostname, to scan host consider to add a PTR record or provide valid host credentials")
						} else {
							nmap_hostname = strings.Replace(nmap_hostname, "output:", "", -1)
							nmap_hostname = strings.Replace(nmap_hostname, "\n", "", -1)
							nmap_hostname = strings.Replace(nmap_hostname, " ", "", -1)
							assets[host_ipv4] = nmap_hostname
						}
					}
				}
	        }
		}
    }

	for key, value := range assets {
        fmt.Println("Hex value of", key, "is", value)
    }

}

func check(e error) {
	if e != nil {
		fmt.Println(e)
		panic(e)
	}
}

//ssh config sshConfigGenerator
func sshConfigGenerator(mdb *mongo.Client, mongo_instance string, skdc_user string){
	log.Println("[*] Generating ssh config")
	//vars
	bt := 0
	f, err := os.Create("/home/"+skdc_user+"/.ssh/config")
	check(err)
	defer f.Close()

	//Define collections
	hosts := mdb.Database(mongo_instance).Collection("hosts")

	findOptProj := options.Find().SetProjection(bson.M{"hostname": 1,"proxy":1, "port":1, "ip":1})
	cur, err := hosts.Find(context.TODO(), bson.D{{}}, findOptProj)
	check(err)
	defer cur.Close(context.TODO())
	for cur.Next(context.TODO()) {
	   var host Host
	   err := cur.Decode(&host)
	   check(err)
	   bc, err := f.WriteString("Host "+host.Hostname+"\n")
	   bt += bc
	   check(err)
	   bc, err = f.WriteString("    User "+skdc_user+"\n")
	   bt += bc
	   check(err)
	   if(host.Proxy == "none") {
		   bc, err = f.WriteString("    HostName "+host.Ip+"\n")
		   bt += bc
		   check(err)
		   bc, err = f.WriteString("    Port "+host.Port+"\n")
		   bt += bc
		   check(err)
	   } else {
		   bc, err = f.WriteString("    HostName "+host.Hostname+"\n")
		   bt += bc
		   check(err)
		   bc, err = f.WriteString("    ProxyCommand ssh "+host.Proxy+" -W "+host.Ip+":"+host.Port+" \n")
		   bt += bc
		   check(err)
	   }
	   bc, err = f.WriteString("\n")
	   bt += bc
	   check(err)
	}
	f.Sync()
	log.Println("    |- bytes written:", bt)
	log.Println("[+] SSH config generated according to MongoDB")
}
