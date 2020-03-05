package main
import (
    "log"
    "os"
    "crypto/rsa"
    "crypto/x509"
    "crypto/rand"
    "encoding/pem"
    "fmt"
    "golang.org/x/crypto/ssh"
    ansibler "github.com/apenella/go-ansible"
    //"github.com/tidwall/gjson"
    "bytes"
    "errors"

)
func main() {
    log.Println("[*] cleaning up files")
	ansiblePlaybookConnectionOptions := &ansibler.AnsiblePlaybookConnectionOptions{}
    ansiblePlaybookOptions := &ansibler.AnsiblePlaybookOptions{
        Inventory: "./inventory/auto",
    }

    stdout_buf := new(bytes.Buffer)
    playbook := &ansibler.AnsiblePlaybookCmd{
        Playbook:          "./playbooks/remove-ssh-id.yml",
        ConnectionOptions: ansiblePlaybookConnectionOptions,
        Options:           ansiblePlaybookOptions,
        ExecPrefix:        "",
        Writer:				stdout_buf,
    }
    _ = playbook.Run()
    stdout := stdout_buf.String()
    fmt.Println(stdout)
}


func MakeSSHKeyPair(privateKeyPath string) (pubKey string, err error) {
    privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
    check(err)


    // generate and write private key as PEM
    privateKeyFile, err := os.Create(privateKeyPath)
    defer privateKeyFile.Close()
    check(err)
    privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
    if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
        return "", errors.New("Could not write RSA PEM cert")
    }

    // generate and write public key
    pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
    check(err)
    return string(ssh.MarshalAuthorizedKey(pub)), nil
}

func check(e error) {
	if e != nil {
		log.Println(e)
		panic(e)
	}
}
