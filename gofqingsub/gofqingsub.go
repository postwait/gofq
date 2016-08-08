package main

import (
	"flag"
	"fmt"
	"github.com/postwait/gofq"
	"os"
	"strings"
)

var host = flag.String("host", "localhost", "Fq Host")
var port = flag.Int("port", 8765, "Fq Port")
var user = flag.String("user", "guest", "Fq User (and queue)")
var pass = flag.String("pass", "guest", "Fq Pass")
var exchange = flag.String("exchange", "", "Exchange")
var program = flag.String("route", "prefix:\"\"", "Program")

func main() {
	flag.Parse()
	if *exchange == "" {
		fmt.Fprintln(os.Stderr, "exchange required")
		os.Exit(-2)
	}
	hooks := fq.NewTSHooks()
	hooks.AddBinding(*exchange, *program)
	fqc := fq.NewClient()
	fqc.SetHooks(&hooks)
	fqc.Creds(*host, uint16(*port), *user, *pass)
	fqc.Connect()
	for {
		select {
		case msg := <-hooks.MsgsC:
			sender_ip := "unknown"
			if msg.Hops != nil && len(msg.Hops) > 0 {
				a := msg.Hops[len(msg.Hops)-1]
				sender_ip = fmt.Sprintf("%d.%d.%d.%d", byte(a>>24), byte(a>>16), byte(a>>8), byte(a))
			}
			lf := "\n"
			payload := string(msg.Payload)
			if strings.HasSuffix(payload, "\n") {
				lf = ""
			}
			fmt.Printf("[%s@%s] [%s] %s%s", msg.Sender.ToString(),
				sender_ip, msg.Route.ToString(), payload, lf)
		case err := <-hooks.ErrorsC:
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		}
	}
}
