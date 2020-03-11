package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/Ullaakut/nmap"
	ansibler "github.com/apenella/go-ansible"
	"github.com/tidwall/gjson"
	"go/build"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"strings"
	"syscall"
	"time"
)

type Host struct {
	Hostname string
	Port     string
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
	var no_copy_id bool
	var help bool

	flag.BoolVar(&help, "help", false, "prints this help message")
	flag.StringVar(&latitude, "site-lat", "", "Override latitude discovery for a site")
	flag.StringVar(&longitude, "site-long", "", "Override longitude discovery for a site")
	flag.BoolVar(&no_copy_id, "no-copy-id", false, "Copy ssh public key to scanned assets. Set to false if you store public keys not in ~/.ssh/authorized_keys. If this flag is set to false password will be written CLEARTEXT in ansible inventory file")
	flag.StringVar(&sensor, "sensor-ip", "", "Sensor IP ossec-hids should connect to")
	flag.StringVar(&sensor_port, "sensor-port", "22", "Sensor IP ossec-hids should connect to")
	flag.StringVar(&ports, "p", "22", "Specify on wich ports SSH migt be listening on")
	flag.StringVar(&subnet, "subnet-cidr", "", "Specify subnet to be scanned")

	flag.Parse()
	if subnet == "" || sensor == "" || help {
		fmt.Println("[-] ERROR: Not enough arguments")
		fmt.Println("Usage: Alienvault-hids-deploy [OPTIONS]")
		fmt.Println("One ore more required flag has not been prodided.")
		fmt.Println("Note that using less flag than defined could lead program into errors (not required flags are site-*). \nOmit flags only if you are aware of what are you doin'")
		flag.PrintDefaults()
		kill("ERR: NOT ENAUGH ARGS")
	}

	ssh_username, ssh_password = credentials("Username for "+subnet+" ↴", "Password ↴")
	sensor_ssh_username, sensor_ssh_password = credentials("Username for sensor "+sensor+" ↴", "Password ↴")

	gopath := os.Getenv("GOPATH")
    if gopath == "" {
        gopath = build.Default.GOPATH
    }
	datadir := gopath+"/src/github.com/lucabodd/Alienvault-hids-autodeploy"

	// setup nmap scanner in order to discover active hosts
	log.Println("[*] Setting Up nmap NSE engine")
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
		assets[host_ipv4] = &Host{"", ""}

		for _, port := range host.Ports {
			if port.Status() == "open" {
				port_str := fmt.Sprintf("%d", port.ID)
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

	// deleting hosts with undefined PTR & SSH connection fail
	for ip, host := range assets {
		if host.Hostname == "" {
			if host.Port == "" {
				log.Println("[-] Cannot determine hostname of", ip, "PTR Query returns null and SSH is not listening on specified ports. Escluding", ip, "host from Assets.csv")
				delete(assets, ip)
			}
			if host.Port != "" {
				log.Println("[-] Cannot connect to", ip, "via SSH, service is listening on provided ports but cannot login. Escluding", ip, "host from hids-deploy")
				delete(assets, ip)
			}
		}
	}
	// generate .csv that needs to be imported in alienvault
	alienvaultAssets(assets, latitude, longitude)
	// deleting hosts wiyh defined PTR & closed ssh
	for ip, host := range assets {
		if host.Port == "" {
			log.Println("[-] Altrough PTR is defined cannot connect to", ip, "via SSH, service is not listening on provided ports. Escluding", ip, "host from hids-deploy")
			delete(assets, ip)
		}
	}
	//checking if sensor is in the same subnet of assets and is reachable
	if _, hit := assets[sensor]; !hit {
		log.Println("[!] Providen sensor ip", sensor, "has not been scanned. this may occur if PTR is defined or if sensor is out of scanned set")
		assets[sensor] = &Host{"", ""}
	}
	log.Println("[*] scanning host", sensor)
	//Expecting sensor listening for SSH on std 22
	//recheck sensor hostname in order to verify if ssh connection is working properly even if PTR for sensor has been discovered
	assets[sensor].Hostname, err = sshRunUname(sensor, sensor_port, sensor_ssh_username, sensor_ssh_password)
	assets[sensor].Port = sensor_port
	check(err)
	if assets[sensor].Hostname == "" {
		log.Println("[-] could not establish a connection in order to retrive sensor informations, program cannot continue.\n On Next run check for sensor's providen creds")
		kill("ERR: COULD NOT CONNECT TO SENSOR")
	}
	//assets map now is ready for ssh config and ansible
	log.Println("[*] Generating ssh config")
	sshConfig(assets, ssh_username, sensor_ssh_username, sensor)
	//now do all the ansible magic
	log.Println("[*] Generating ansible inventory")
	if !no_copy_id {
		ansibleInventory(assets, sensor)
		pubKey, err := makeSSHKeyPair("~/.ssh/deploy_temporary_key_2048")
		check(err)
		for ip, host := range assets {
			status := ""
			if ip != sensor {
				status, err = sshCopyId(ip, host.Port, ssh_username, ssh_password, pubKey)
			} else {
				status, err = sshCopyId(ip, host.Port, sensor_ssh_username, sensor_ssh_password, pubKey)
			}
			check(err)
			if status == "" {
				log.Println("[-] Cannot copy public key due to login failure. Escluding", host.Hostname, "from hids-deploy")
				delete(assets, ip)
			}
		}
	} else {
		ansibleUnsafeInventory(assets, ssh_username, ssh_password, sensor_ssh_username, sensor_ssh_password, sensor)
	}

	//ossec-hids deploy
	log.Println("[*] Deploying ossec-hids to discovered assets")
	ansiblePlaybookConnectionOptions := &ansibler.AnsiblePlaybookConnectionOptions{}
	ansiblePlaybookOptions := &ansibler.AnsiblePlaybookOptions{
		Inventory: datadir+"/inventory/auto",
		ExtraVars: map[string]interface{}{
			"sensor": sensor,
		},
	}

	stdout_buf := new(bytes.Buffer)
	playbook := &ansibler.AnsiblePlaybookCmd{
		Playbook:          datadir+"/playbooks/ossec-hids-deploy.yml",
		ConnectionOptions: ansiblePlaybookConnectionOptions,
		Options:           ansiblePlaybookOptions,
		ExecPrefix:        "",
		Writer:            stdout_buf,
	}
	_ = playbook.Run()
	stdout := stdout_buf.String()
	stdout = strings.Replace(stdout, "=>", "", -1)
	//json contains counts about status of tasks, attributes are: changed, failures, ignored, ok, rescued, skipped, unreachable
	for ip, host := range assets {
		ansible_host_stats_failures := gjson.Get(stdout, "stats."+host.Hostname+".failures")
		ansible_host_stats_unreachable := gjson.Get(stdout, "stats."+host.Hostname+".unreachable")
		errors := ansible_host_stats_failures.Int()
		unreachable := ansible_host_stats_unreachable.Int()
		if errors > 0 || unreachable > 0 {
			fmt.Println("[-] Deploy failed on " + host.Hostname + " skipping host")
			delete(assets, ip)
		}
	}
	//refreshing ansible inventory according to deployed agents and write all deployed agents list
	ansibleInventory(assets, sensor)
	alienvaultAgents(assets, sensor)
	//ossec-hids deploy
	log.Println("[*] Adding deployed Agents to sensor and export keys")
	ansiblePlaybookConnectionOptions = &ansibler.AnsiblePlaybookConnectionOptions{}
	ansiblePlaybookOptions = &ansibler.AnsiblePlaybookOptions{
		Inventory: datadir+"/inventory/auto",
	}

	stdout_buf = new(bytes.Buffer)
	playbook = &ansibler.AnsiblePlaybookCmd{
		Playbook:          datadir+"/playbooks/sensor-agent-deploy.yml",
		ConnectionOptions: ansiblePlaybookConnectionOptions,
		Options:           ansiblePlaybookOptions,
		ExecPrefix:        "",
		Writer:            stdout_buf,
	}
	_ = playbook.Run()
	stdout = stdout_buf.String()
	stdout = strings.Replace(stdout, "=>", "", -1)
	ansible_host_stats_failures := gjson.Get(stdout, "stats."+assets[sensor].Hostname+".failures")
	ansible_host_stats_unreachable := gjson.Get(stdout, "stats."+assets[sensor].Hostname+".unreachable")
	errors := ansible_host_stats_failures.Int()
	unreachable := ansible_host_stats_unreachable.Int()
	if errors > 0 || unreachable > 0 {
		fmt.Println("[-] Error occurred while adding deployed Agents to alienvault sensor")
		kill("FATAL: could not export Agents keys from sensor")
	}

	log.Println("[*] cleaning up files")
	ansiblePlaybookConnectionOptions = &ansibler.AnsiblePlaybookConnectionOptions{}
	ansiblePlaybookOptions = &ansibler.AnsiblePlaybookOptions{
		Inventory: datadir+"/inventory/auto",
	}

	stdout_buf = new(bytes.Buffer)
	playbook = &ansibler.AnsiblePlaybookCmd{
		Playbook:          datadir+"/playbooks/remove-ssh-id.yml",
		ConnectionOptions: ansiblePlaybookConnectionOptions,
		Options:           ansiblePlaybookOptions,
		ExecPrefix:        "",
		Writer:            stdout_buf,
	}
	_ = playbook.Run()
	err = os.Remove("~/.ssh/deploy_temporary_key_2048")
	check(err)
	err = os.Remove(datadir+"/inventory/auto")
	check(err)
	err = os.Remove(datadir+"/roles/sensor-agent-deploy/files/Agents.list")
	check(err)
	log.Println("[+] Done! deploy completed successfully, please consider the exceptions above.")
}

//retrive hostname for a providen ipv4 address
func sshRunUname(ip string, port string, ssh_username string, ssh_password string) (hostname string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	gopath := os.Getenv("GOPATH")
    if gopath == "" {
        gopath = build.Default.GOPATH
    }
	datadir := gopath+"/src/github.com/lucabodd/Alienvault-hids-autodeploy"

	check(err)
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(ip),
		nmap.WithContext(ctx),
		nmap.WithPorts(port),
		nmap.WithScripts(datadir+"/sbin/nmap/nse/ssh-run-uname"),
		nmap.WithScriptArguments(
			map[string]string{
				"ssh-run.port":     port,
				"ssh-run.username": ssh_username,
				"ssh-run.password": ssh_password,
			}),
	)
	result, warnings, err := scanner.Run()
	check(err)

	if result.Hosts != nil {
		if warnings != nil {
			fmt.Printf("[!] \n %v", warnings)
			return "", errors.New("Error occurred in sshRunUname, please refer to warning")
		}
		nmap_hostname := result.Hosts[0].Ports[0].Scripts[0].Output
		if strings.Contains(nmap_hostname, "Authentication Failed") {
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

//retrive hostname for a providen ipv4 address
func sshCopyId(ip string, port string, ssh_username string, ssh_password string, pubKey string) (status string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	gopath := os.Getenv("GOPATH")
    if gopath == "" {
        gopath = build.Default.GOPATH
    }
	datadir := gopath+"/src/github.com/lucabodd/Alienvault-hids-autodeploy"

	scanner, err := nmap.NewScanner(
		nmap.WithTargets(ip),
		nmap.WithContext(ctx),
		nmap.WithPorts(port),
		nmap.WithScripts(datadir+"/sbin/nmap/nse/ssh-copy-id"),
		nmap.WithScriptArguments(
			map[string]string{
				"ssh-run.port":     port,
				"ssh-run.username": ssh_username,
				"ssh-run.password": ssh_password,
				"ssh-run.id":       pubKey,
			}),
	)
	result, warnings, err := scanner.Run()
	check(err)

	if result.Hosts != nil {
		if warnings != nil {
			fmt.Printf("[!] \n %v", warnings)
			return "", errors.New("Error occurred in sshRunUname, please refer to warning")
		}
		nmap_stat := result.Hosts[0].Ports[0].Scripts[0].Output
		if strings.Contains(nmap_stat, "Authentication Failed") {
			return "", nil
		} else {
			nmap_stat = strings.Replace(nmap_stat, "output:", "", -1)
			nmap_stat = strings.Replace(nmap_stat, "\n", "", -1)
			nmap_stat = strings.Replace(nmap_stat, "\r", "", -1)
			nmap_stat = strings.Replace(nmap_stat, "  ", "", -1)
			nmap_stat = strings.Split(nmap_stat, ".")[0]
			return nmap_stat, nil
		}
	} else {
		return "", errors.New("Could not retrive informations on this host")
	}
}

//Generate Assets.csv for alienvault
func alienvaultAssets(assets map[string]*Host, user_latitude string, user_longitude string) {
	var latitude string
	var longitude string
	log.Println("[*] geolocation not defined in command line, retriveing site geogrphic cordinates...")
	url := "https://freegeoip.app/json/"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("accept", "application/json")
	req.Header.Add("content-type", "application/json")
	res, _ := http.DefaultClient.Do(req)
	defer res.Body.Close()
	geoloc, _ := ioutil.ReadAll(res.Body)

	if user_latitude != "" {
		latitude = user_latitude
	} else {
		log.Println("[*] Detecting site latitude...")
		value := gjson.Get(string(geoloc), "latitude")
		latitude = value.String()
		log.Println("[+] LAT: " + latitude)
	}
	if user_longitude != "" {
		longitude = user_longitude
	} else {
		log.Println("[*] Detecting site longitude...")
		value := gjson.Get(string(geoloc), "longitude")
		longitude = value.String()
		log.Println("[+] LNG: " + longitude)
	}

	log.Println("[*] Generating Alienvault Assets.csv")
	bt := 0
	f, err := os.Create("Assets.csv")
	check(err)
	defer f.Close()
	bc, err := f.WriteString("\"IPs\";\"Hostname\";\"FQDNs\";\"Description\";\"Asset Value\";\"Operating System\";\"Latitude\";\"Longitude\";\"Host ID\";\"External Asset\";\"Device Type\"")
	bt += bc
	check(err)
	for ip, host := range assets {
		bc, err := f.WriteString("\n\"" + ip + "\";\"" + host.Hostname + "\";\"\";\"\";\"2\";\"\";\"" + latitude + "\";\"" + longitude + "\";\"\";\"\";\"\"")
		bt += bc
		check(err)
	}
	f.Sync()
	log.Printf("[+] Alienvault Assets.csv generated in working dir. %d bytes written", bt)
}

func alienvaultAgents(assets map[string]*Host, sensor string) {
	log.Println("[*] Generating Alienvault Agents.list")
	gopath := os.Getenv("GOPATH")
    if gopath == "" {
        gopath = build.Default.GOPATH
    }
	datadir := gopath+"/src/github.com/lucabodd/Alienvault-hids-autodeploy"

	bt := 0
	f, err := os.Create(datadir+"/roles/sensor-agent-deploy/files/Agents.list")
	check(err)
	defer f.Close()
	for ip, host := range assets {
		if ip != sensor {
			bc, err := f.WriteString(ip + "," + host.Hostname + "\n")
			bt += bc
			check(err)
		}
	}
	f.Sync()
	log.Printf("[+] Alienvault Agents.list generated. %d bytes written", bt)
}

func makeSSHKeyPair(privateKeyPath string) (string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	check(err)

	// generate and write private key as PEM
	privateKeyFile, err := os.Create(privateKeyPath)
	defer privateKeyFile.Close()
	check(err)
	err = os.Chmod(privateKeyPath, 0600)
	check(err)
	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	err = pem.Encode(privateKeyFile, privateKeyPEM)
	check(err)

	// generate and write public key
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	check(err)
	key := strings.Replace(string(ssh.MarshalAuthorizedKey(pub)), "\n", " deploy_temporary_key_2048\n", -1)
	return key, nil
}

func sshConfig(assets map[string]*Host, ssh_username string, sensor_ssh_username string, sensor string) {
	usr, err := user.Current()
	check(err)
	home := usr.HomeDir
	createDirIfNotExist(home + "/.ssh")

	//vars
	bt := 0
	f, err := os.Create(home + "/.ssh/config.test")
	check(err)
	defer f.Close()

	for ip, host := range assets {
		bc, err := f.WriteString("Host " + host.Hostname + "\n")
		bt += bc
		check(err)
		if ip == sensor {
			bc, err = f.WriteString("    User " + sensor_ssh_username + "\n")
			bt += bc
			check(err)
		} else {
			bc, err = f.WriteString("    User " + ssh_username + "\n")
			bt += bc
			check(err)
		}

		bc, err = f.WriteString("    HostName " + ip + "\n")
		bt += bc
		check(err)
		bc, err = f.WriteString("    Port " + host.Port + "\n")
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
	gopath := os.Getenv("GOPATH")
    if gopath == "" {
        gopath = build.Default.GOPATH
    }
	datadir := gopath+"/src/github.com/lucabodd/Alienvault-hids-autodeploy"

	f, err := os.Create(datadir+"/inventory/auto")
	check(err)
	defer f.Close()
	bc, err := f.WriteString("[sensor]\n")
	bt += bc
	check(err)
	bc, err = f.WriteString(assets[sensor].Hostname + "\n\n")
	bt += bc
	check(err)
	bc, err = f.WriteString("[assets]\n")
	bt += bc
	check(err)
	for ip, host := range assets {
		if ip != sensor {
			bc, err := f.WriteString(host.Hostname + "\n")
			bt += bc
			check(err)
		}
	}
	f.Sync()
	log.Printf("[+] Ansible inventory generated, %d bytes written", bt)
}

func ansibleUnsafeInventory(assets map[string]*Host, ssh_username string, ssh_password string, sensor_ssh_username string, sensor_ssh_password string, sensor string) {
	bt := 0
	gopath := os.Getenv("GOPATH")
    if gopath == "" {
        gopath = build.Default.GOPATH
    }
	datadir := gopath+"/src/github.com/lucabodd/Alienvault-hids-autodeploy"

	f, err := os.Create(datadir+"/inventory/auto")
	check(err)
	defer f.Close()
	bc, err := f.WriteString("[sensor]\n")
	bt += bc
	check(err)
	bc, err = f.WriteString(assets[sensor].Hostname + " ansible_ssh_user=" + sensor_ssh_username + " ansible_ssh_pass=" + sensor_ssh_password + "\n\n")
	bt += bc
	check(err)
	bc, err = f.WriteString("[assets]\n")
	bt += bc
	check(err)
	for ip, host := range assets {
		if ip != sensor {
			bc, err := f.WriteString(host.Hostname + " ansible_ssh_user=" + ssh_username + " ansible_ssh_pass=" + ssh_password + "\n")
			bt += bc
			check(err)
		}
	}
	f.Sync()
	log.Printf("[+] Ansible UNSAFE inventory generated, %d bytes written", bt)
}

func credentials(prompt1 string, prompt2 string) (string, string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println(prompt1)
	username, _ := reader.ReadString('\n')

	fmt.Println(prompt2)
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	check(err)
	password := string(bytePassword)

	return strings.TrimSpace(username), strings.TrimSpace(password)
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
