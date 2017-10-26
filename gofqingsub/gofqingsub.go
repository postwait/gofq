package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/postwait/gofq"
	"os"
	"strings"
	"unicode"
	"unsafe"
)

var host = flag.String("host", "localhost", "Fq Host")
var port = flag.Int("port", 8765, "Fq Port")
var user = flag.String("user", "guest", "Fq User (and queue)")
var pass = flag.String("pass", "guest", "Fq Pass")
var exchange = flag.String("exchange", "", "Exchange")
var program = flag.String("route", "prefix:\"\"", "Program")

func getNativeEndian() binary.ByteOrder {
	// We need to encode integers are byte buffers... as they are.
	// So we use Go's standard native byte order... oh wait, Go sucks.
	// we have to do this unsavory shit instead.
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

var ne = getNativeEndian()

func IsAsciiPrintable(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

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
				ipbuf := make([]byte, 4)
				binary.BigEndian.PutUint32(ipbuf, a)
				a = ne.Uint32(ipbuf)
				sender_ip = fmt.Sprintf("%d.%d.%d.%d", byte(a>>24), byte(a>>16), byte(a>>8), byte(a))
			}
			lf := "\n"
			payload := string(msg.Payload)
			if strings.HasSuffix(payload, "\n") {
				lf = ""
			}
			if !IsAsciiPrintable(payload) {
				payload = "[binary data]"
			}
			fmt.Printf("[%s@%s] [%s] %s%s", msg.Sender.ToString(),
				sender_ip, msg.Route.ToString(), payload, lf)
		case err := <-hooks.ErrorsC:
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		}
	}
}
