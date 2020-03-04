package main

import (
	"errors"
	"flag"
	"os"
	"os/user"
	"fmt"
    "time"
    "context"
	"io/ioutil"
	//ansibler "github.com/apenella/go-ansible"
	//"bytes"
	//"strings"
	"github.com/tidwall/gjson"
    "github.com/Ullaakut/nmap"
	"log"
	"net"
	"net/http"
	"strings"
)

type Host struct {
	Hostname string
	Port string
}

func main() {
	//Ansible setup env
	os.Setenv("ANSIBLE_STDOUT_CALLBACK", "json")
	os.Setenv("ANSIBLE_HOST_KEY_CHECKING", "False")
	//vars
	var assets = make(map[string]*Host)
	var subnet string
	var ports string
	var ssh_username string
	var ssh_password string
	var latitude string
	var longitude string
	var sensor string
	var sensor_port string
	var sensor_ssh_username string
	var sensor_ssh_password string
	var help bool

	flag.StringVar(&subnet, "subnet-cidr", "", "Specify subnet to be scanned")
    flag.StringVar(&ports, "p", "22", "Specify on wich ports SSH migt be listening on")
	flag.StringVar(&latitude, "site-lat", "", "Override latitude discovery for a site")
	flag.StringVar(&longitude, "site-long", "","Override longitude discovery for a site")
	flag.StringVar(&sensor, "sensor", "","Sensor IP ossec-hids should connect to")
	flag.StringVar(&sensor_port, "sensor-port", "22","Sensor IP ossec-hids should connect to")
	flag.BoolVar(&help, "help", false, "prints this help message")
	//below vars must be replaced by prompt
	flag.StringVar(&ssh_username, "u", "root", "Specify an username that has access to all machines")
	flag.StringVar(&ssh_password, "password", "", "Set a password for defined username")
	flag.StringVar(&sensor_ssh_username, "sensor-ssh-username", "root","Sensor IP ossec-hids should connect to")
	flag.StringVar(&sensor_ssh_password, "sensor-ssh-password", "","Sensor IP ossec-hids should connect to")
    flag.Parse()
	if subnet == "" || ssh_password == "" || sensor == "" || sensor_ssh_username == "" || help {
		fmt.Println("[-] ERROR: Not enough arguments")
		fmt.Println("Usage: Alienvault-ansible-automation [OPTIONS]")
		fmt.Println("One ore more required flag has not been prodided.")
		fmt.Println("Note that using less flag than defined could lead program into errors (not required flags are site-*). \nOmit flags only if you are aware of what are you doin'")
		flag.PrintDefaults()
		kill("ERR: NOT ENAUGH ARGS")
	}

    // setup nmap scanner in order to discover active hosts
	log.Println("[*] Setting Up NSE engine")
	log.Println("[*] Scanning network")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    defer cancel()
    scanner, err := nmap.NewScanner(
        nmap.WithTargets(subnet),
        nmap.WithPorts(ports),
        nmap.WithContext(ctx),
    )
	check(err)
    result, warnings, err := scanner.Run()
    check(err)
    if warnings != nil {
        fmt.Printf("Warnings: \n %v", warnings)
    }
	log.Println("[+] Detected network's alive hosts ... diggin' deeper ...")

	//retrive hostnames and insert into a map and perform more accurate scan
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
				} else {
					assets[host_ipv4].Hostname, err = sshRunUname(host_ipv4, port_str, ssh_username, ssh_password)
					check(err)
				}
				assets[host_ipv4].Port = port_str
        	}
		}
	}
	// deleting hosts with undefined hostname PTR&SSH fail
	for ip, host := range assets {
		if host.Port == "" && host.Hostname == "" {
			delete(assets, ip)
			log.Println("[-] Cannot determine hostname of", ip, "PTR Query returns null and could not connect to SSH. Escluding host from Assets.csv")
		}
	}
	// generate .csv that needs to be imported in alienvault
	alienvaultAssets(assets, latitude, longitude)
	// deleting hosts that could not be managed via ssh
	for ip, host := range assets {
		if host.Port == "" {
			delete(assets, ip)
			log.Println("[-] SSH seems not to be listening on", ip, "at specified ports. Escluding host from hids-deploy")
		}
	}
	//checking if sensor is in the same subnet of assets and is reachable
	if _, hit := assets[sensor]; !hit {
		log.Println("[!] Providen sensor ip",sensor,"has not been scanned. That's fine but please make sure that host is reachable via SSH")
		assets[sensor] = &Host{}
	}
	log.Println("[*] scanning host", sensor)
	//Expecting sensor listening for SSH on std 22
	//recheck sensor hostname in order to verify if ssh connection is working properly even if PTR for sensor has been discovered
	assets[sensor].Hostname, err = sshRunUname(sensor, sensor_port, sensor_ssh_username, sensor_ssh_password)
	assets[sensor].Port = sensor_port
	check(err)
	if (assets[sensor].Hostname == "") {
		log.Println("[-] could not establish a connection in order to retrive sensor informations, program cannot continue.\n On Next run check for providen creds")
		kill("ERR: COULD NOT CONNECT TO SENSOR")
	}
	//assets map now is ready for ssh config and ansible
	log.Println("[*] Generating ssh config")
	sshConfig(assets, ssh_username, sensor_ssh_username, sensor)
	//now do all the ansible magic
	log.Println("[*] Generating ansible inventory")
	ansibleInventory(assets, sensor)
}

//retrive hostname for a providen ipv4 address
func sshRunUname(ip string, port string, ssh_username string, ssh_password string) (hostname string,err error)  {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    defer cancel()
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(ip),
		nmap.WithContext(ctx),
		nmap.WithPorts(port),
		nmap.WithScripts("./sbin/nmap/nse/ssh-run-uname"),
		nmap.WithScriptArguments(
			map[string]string{
				"ssh-run.port": port,
				"ssh-run.username": ssh_username,
				"ssh-run.password": ssh_password,
			}),
	)
	result, warnings, err := scanner.Run()
	check(err)

	if(result.Hosts != nil) {
		if warnings != nil {
			fmt.Printf("[!] \n %v", warnings)
			return "", errors.New("Error occurred in sshRunUname, please refer to warning")
		}
		nmap_hostname := result.Hosts[0].Ports[0].Scripts[0].Output
		if(strings.Contains(nmap_hostname, "Authentication Failed")){
			return "", nil
		} else {
			nmap_hostname = strings.Replace(nmap_hostname, "output:", "", -1)
			nmap_hostname = strings.Replace(nmap_hostname, "\n", "", -1)
			nmap_hostname = strings.Replace(nmap_hostname, "\r", "", -1)
			nmap_hostname = strings.Replace(nmap_hostname, " ", "", -1)
			nmap_hostname = strings.Split(nmap_hostname, ".")[0]
			return nmap_hostname, nil
		}
	} else {
		return "", errors.New("Could not retrive informations on this host")
	}
}

//Generate Assets.csv for alienvault
func alienvaultAssets(assets map[string]*Host, user_latitude string, user_longitude string) {
	var latitude string
	var longitude string
	log.Println("[*] Retriveing site coordinates...")
	url := "https://freegeoip.app/json/"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("accept", "application/json")
	req.Header.Add("content-type", "application/json")
	res, _ := http.DefaultClient.Do(req)
	defer res.Body.Close()
	geoloc, _ := ioutil.ReadAll(res.Body)

	if (user_latitude != "") {
		latitude = user_latitude
	} else {
		log.Println("[*] Detecting latitude...")
		value := gjson.Get(string(geoloc), "latitude")
		latitude = value.String()
		log.Println("[+] LAT: "+latitude)
	}
	if (user_longitude != ""){
		longitude = user_longitude
	} else {
		log.Println("[*] Detecting longitude...")
		value := gjson.Get(string(geoloc), "longitude")
		longitude = value.String()
		log.Println("[+] LNG: "+longitude)
	}

	log.Println("[*] Generating Assets.csv")
	bt := 0
	f, err := os.Create("Assets.csv")
	check(err)
	defer f.Close()
	bc, err := f.WriteString("\"IPs\";\"Hostname\";\"FQDNs\";\"Description\";\"Asset Value\";\"Operating System\";\"Latitude\";\"Longitude\";\"Host ID\";\"External Asset\";\"Device Type\"")
	bt += bc
	check(err)
	for ip, host := range assets {
	   	bc, err := f.WriteString("\n\""+ip+"\";\""+host.Hostname+"\";\"\";\"\";\"2\";\"\";\""+latitude+"\";\""+longitude+"\";\"\";\"\";\"\"")
		bt += bc
	   	check(err)
	}
	f.Sync()
	log.Printf("[+] Alienvault Assets.csv generated in working dir. %d bytes written", bt)
}

func sshConfig(assets map[string]*Host, ssh_username string, sensor_ssh_username string, sensor string) {
	usr, err := user.Current()
	check(err)
    home := usr.HomeDir
	createDirIfNotExist(home+"/.ssh")

	//vars
	bt := 0
	f, err := os.Create(home+"/.ssh/config.test")
	check(err)
	defer f.Close()

	for ip, host := range assets {
	   	bc, err := f.WriteString("Host "+host.Hostname+"\n")
	   	bt += bc
	   	check(err)
		if ip == sensor {
			bc, err = f.WriteString("    User "+sensor_ssh_username+"\n")
		   	bt += bc
		   	check(err)
		} else {
			bc, err = f.WriteString("    User "+ssh_username+"\n")
		   	bt += bc
		   	check(err)
		}

	   	bc, err = f.WriteString("    HostName "+ip+"\n")
	   	bt += bc
	   	check(err)
	   	bc, err = f.WriteString("    Port "+host.Port+"\n")
	   	bt += bc
	   	check(err)
	   	bc, err = f.WriteString("\n")
	   	bt += bc
	   	check(err)
	}
	f.Sync()
	log.Printf("[+] SSH config generated %d bytes written", bt)
}

func createDirIfNotExist(dir string) {
      if _, err := os.Stat(dir); os.IsNotExist(err) {
              err = os.MkdirAll(dir, 0700)
              if err != nil {
                      panic(err)
              }
      }
}

func ansibleInventory(assets map[string]*Host, sensor string) {
	bt := 0
	f, err := os.Create("./dc/auto/Inventory")
	check(err)
	defer f.Close()
	bc, err := f.WriteString("[sensor]\n")
	bt += bc
	check(err)
	bc, err = f.WriteString(assets[sensor].Hostname+"\n\n")
	bt += bc
	check(err)
	bc, err = f.WriteString("[assets]\n")
	bt += bc
	check(err)
	for ip, host := range assets {
		if ip != sensor {
			bc, err := f.WriteString(host.Hostname)
			bt += bc
			check(err)
		}
	}
	f.Sync()
	log.Printf("[+] Ansible inventory generated %d bytes written", bt)
}

func check(e error) {
	if e != nil {
		log.Println(e)
		panic(e)
	}
}

func kill(reason string) {
	fmt.Println(reason)
	os.Exit(0)
}
