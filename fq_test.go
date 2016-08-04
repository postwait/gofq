package fq_test

import (
	"bytes"
	"github.com/postwait/gofq"
	"log"
	"testing"
	"time"
)

type MyFqHooks struct {
	test  *testing.T
	bound chan uint32
	msgs  chan *fq.Message
	stats map[string]uint32
}

func (h *MyFqHooks) AuthHook(c *fq.Client, err error) {
	if err != nil {
		h.test.Errorf("Failed auth")
		return
	}
	breq := fq.BindReq{
		Exchange: fq.Rk("logging"),
		Flags:    fq.FQ_BIND_TRANS,
		Program:  "prefix:\"test.gotest.oneoff\"",
	}
	c.Bind(&breq)
}
func (h *MyFqHooks) BindHook(c *fq.Client, breq *fq.BindReq) {
	h.bound <- breq.OutRouteId
}
func (h *MyFqHooks) UnbindHook(c *fq.Client, breq *fq.UnbindReq) {
}
func (h *MyFqHooks) DisconnectHook(c *fq.Client) {
	h.test.Errorf("Unexpected disconnect")
}
func (h *MyFqHooks) ErrorLogHook(c *fq.Client, err string) {
	log.Print(err)
}
func (h *MyFqHooks) StatusHook(c *fq.Client, stats map[string]uint32) {
	h.stats = stats
}
func (h *MyFqHooks) MessageHook(c *fq.Client, msg *fq.Message) bool {
	h.msgs <- msg
	return true
}

func TestSendRcv(t *testing.T) {
	hooks := &MyFqHooks{
		test:  t,
		bound: make(chan uint32, 1),
		msgs:  make(chan *fq.Message, 1),
	}
	fqclient := fq.NewClient()
	fqclient.SetHooks(hooks)
	fqclient.Creds("localhost", 8765, "gotest", "nopass")
	fqclient.Connect()

	routeid := uint32(0xffffffff)
	select {
	case routeid = <-hooks.bound:
	case <-time.NewTimer(time.Second).C:
		t.Errorf("Bind request timed out")
	}
	if routeid == 0xffffffff {
		t.Errorf("Failed binding")
	}

	time.Sleep(250 * time.Millisecond)
	msg := fq.NewMessage("logging", "test.gotest.oneoff", []byte("BOO"))
	fqclient.Publish(msg)

	fqclient.Status()

	select {
	case nmsg := <-hooks.msgs:
		if !bytes.Equal(nmsg.Payload, msg.Payload) {
			t.Errorf("payload corrupted")
		}
	case <-time.NewTimer(2 * time.Second).C:
		t.Errorf("Message recv timed out")
	}

	time.Sleep(250 * time.Millisecond)

	if hooks.stats == nil {
		t.Errorf("statistics requested, but not found")
	} else {
		if _, ok := hooks.stats["routed"]; !ok {
			t.Errorf("statistic 'routed' missing")
		}
		if _, ok := hooks.stats["dropped"]; !ok {
			t.Errorf("statistic 'dropped' missing")
		}
	}
}

func TestTSHook(t *testing.T) {
	tsh := fq.NewTSHooks()
	tsh.AddBinding("logging", "prefix:\"test.gotest.tsh\"")
	fqclient := fq.NewClient()
	fqclient.SetHooks(&tsh)
	fqclient.Creds("localhost", 8765, "gotest", "nopass")
	fqclient.Connect()

	time.Sleep(250 * time.Millisecond)
	msg := fq.NewMessage("logging", "test.gotest.tsh", []byte("HELLO"))
	fqclient.Publish(msg)
	for {
		select {
		case nmsg := <-tsh.MsgsC:
			if !bytes.Equal(nmsg.Payload, msg.Payload) {
				t.Errorf("payload corrupted")
			}
			goto OUT
		case err := <-tsh.ErrorsC:
			t.Errorf("Error: " + err.Error())
		case <-time.NewTimer(2 * time.Second).C:
			t.Errorf("timeout")
			goto OUT
		}
	}
OUT:
}

func TestNonBlocking(t *testing.T) {
	fqclient := fq.NewClient()
	if fqclient.SetBacklog(1) != 1 {
		t.Errorf("failed to set backlog down")
	}
	fqclient.SetNonBlocking(true)
	fqclient.Creds("localhost", 8765, "gotest", "nopass")
	fqclient.Connect()
	dropped := false
	for i := 0; i < 10; i++ {
		msg := fq.NewMessage("logging", "test.overflow", []byte("HELLO"))
		dropped = dropped || !fqclient.Publish(msg)
	}
	if !dropped {
		t.Errorf("should have dropped some messages")
	}
}

func TestHeartbeat(t *testing.T) {
	tsh := fq.NewTSHooks()
	fqclient := fq.NewClient()
	fqclient.SetHooks(&tsh)
	fqclient.Creds("localhost", 8765, "gotest", "nopass")
	fqclient.SetHeartBeat(250 * time.Millisecond)
	fqclient.Connect()

	time.Sleep(time.Second)
	fqclient.SetHeartBeatMaxAge(time.Millisecond)
	passed := false
	for {
		select {
		case err := <-tsh.ErrorsC:
			if err.Error() == "dead: missing heartbeat" {
				passed = true
				goto OUT
			}
		case <-time.NewTimer(3 * time.Second).C:
			goto OUT
		}
	}
OUT:
	if !passed {
		t.Errorf("Failed to notice stopped heartbeat")
	}
}
