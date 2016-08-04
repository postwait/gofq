package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/postwait/gofq"
	"io"
	"os"
)

var host = flag.String("host", "localhost", "Fq Host")
var port = flag.Int("port", 8765, "Fq Port")
var user = flag.String("user", "guest", "Fq User (and queue)")
var pass = flag.String("pass", "guest", "Fq Pass")
var exchange = flag.String("exchange", "", "Target Exchange")
var route = flag.String("route", "", "Target Route")

func main() {
	flag.Parse()
	if *exchange == "" || *route == "" {
		fmt.Fprintln(os.Stderr, "exchange and route both required")
		os.Exit(-2)
	}
	fqc := fq.NewClient()
	fqc.Creds(*host, uint16(*port), *user, *pass)
	fqc.Connect()
	reader := bufio.NewReader(os.Stdin)
	for {
		if text, err := reader.ReadString('\n'); err != nil {
			if err == io.EOF {
				break
			}
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			break
		} else {
			payload := []byte(text)
			chomp := payload[0 : len(payload)-1]
			msg := fq.NewMessage(*exchange, *route, chomp)
			fqc.Publish(msg)
		}
	}
	fqc.Shutdown()
}
