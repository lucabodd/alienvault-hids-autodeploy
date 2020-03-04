package main
import (
    "os/user"
    "fmt"
    "log"
)
func main() {
    usr, err := user.Current()
    if err != nil {
        log.Fatal( err )
    }
    fmt.Println( usr.HomeDir )
}
