package main
import (
    "os/user"
    "fmt"
    "log"
)
func main() {
    keyFile, err := os.Open(filename)
    if err != nil {
    log.Fatal(err)
    }

    cmd := exec.Command("ssh", "user@host", "cat >> ~/.ssh/authorized_keys")
    cmd.Stdin = keyFile

    // run the command however you want
    out, err := cmd.CombinedOutput()
    if err != nil {
        fmt.Println(string(out))
        log.Fatal(err)
    }
}
