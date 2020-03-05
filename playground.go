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
    //ansibler "github.com/apenella/go-ansible"
    //"github.com/tidwall/gjson"
    "strings"
    //"bytes"
    "errors"

    "syscall"
    "bufio"
    "golang.org/x/crypto/ssh/terminal"
)
func main() {
    credentials("Username: ", "Password: ")

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
