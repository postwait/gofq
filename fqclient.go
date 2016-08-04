// Pacakge fq provides a client for Fq (https://github.com/circonus-labs/fq)
package fq

/*
 * Copyright (c) 2016 Circonus, Inc.
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

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
var be = binary.BigEndian
var rng = rand.New(rand.NewSource(time.Now().Unix() * int64(os.Getpid())))

type peeringMode uint32

const (
	fq_PROTO_CMD_MODE      = peeringMode(0xcc50cafe)
	fq_PROTO_DATA_MODE     = peeringMode(0xcc50face)
	fq_PROTO_PEER_MODE     = peeringMode(0xcc50feed)
	fq_PROTO_OLD_PEER_MODE = peeringMode(0xcc50fade)
)
const (
	FQ_DEFAULT_QUEUE_TYPE = "mem"

	FQ_BIND_PEER    = uint16(0x00000001)
	FQ_BIND_PERM    = uint16(0x00000110)
	FQ_BIND_TRANS   = uint16(0x00000100)
	FQ_BIND_ILLEGAL = uint32(0xffffffff)

	FQ_MAX_RK_LEN = 127
)

type protoCommand uint16

const (
	fq_PROTO_ERROR      = protoCommand(0xeeee)
	fq_PROTO_AUTH_CMD   = protoCommand(0xaaaa)
	fq_PROTO_AUTH_PLAIN = protoCommand(0)
	fq_PROTO_AUTH_RESP  = protoCommand(0xaa00)
	fq_PROTO_HBREQ      = protoCommand(0x4848)
	fq_PROTO_HB         = protoCommand(0xbea7)
	fq_PROTO_BINDREQ    = protoCommand(0xb170)
	fq_PROTO_BIND       = protoCommand(0xb171)
	fq_PROTO_UNBINDREQ  = protoCommand(0x071b)
	fq_PROTO_UNBIND     = protoCommand(0x171b)
	fq_PROTO_STATUS     = protoCommand(0x57a7)
	fq_PROTO_STATUSREQ  = protoCommand(0xc7a7)

	fq_MAX_HOPS = 32
)

type hookType int

const (
	fq_AUTH_HOOK_TYPE = hookType(iota)
	fq_CMD_HOOK_TYPE  = hookType(iota)
)

type BindReq struct {
	Exchange   fq_rk
	Flags      uint16
	Program    string
	OutRouteId uint32
}

type UnbindReq struct {
	Exchange   fq_rk
	RouteId    uint32
	OutSuccess uint32
}

type fq_rk struct {
	Name [FQ_MAX_RK_LEN]byte
	Len  uint8
}

type fq_msgid struct {
	d [16]byte
}

type Message struct {
	Hops                    []uint32
	Route, Sender, Exchange fq_rk
	Sender_msgid            fq_msgid
	Arrival_time            uint64
	Payload                 []byte
}

// Hooks is the interface one implements to drive an fq session.
//
// If the Client has been set to synchronous mode via SetSynchronous
// the hooks are invoked causally from invocations of Receive.
// Otherwise hooks are called as response to commands arrive or
// actions happen (in another go routine).
//
// AuthHook is called upon response to an authentication attempt
// caused by Connect (and any subsequent automatic reconnections).
// If err is nil, authentication was successful.
//
// BindHook is called upon response to a Bind request.  The same
// BindReq passed to Bind will be presented here and OutRouteId
// will be set.  If OutRouteId is FQ_BIND_ILLEGAL, the bind failed.
//
// UnbindHook is called upon response to an Unbind request. The
// OutSuccess indicates whether the request was handled successfully.
//
// MessageHook is called upon reception of a message from the fq
// server.  If true is returned, the message will not be enqueued
// for delivery via Receive().
//
// DisconnectHook is called when the client disconnects. Nothing
// is required on the programmers part to reconnect; it is automastic.
//
// StatusHook is invoked upon response to a Status request.
//
// ErrorLogHook is invoked when the client encouters any sort of error.
// All typicaly runtime errors are fully recoverably without special
// action by the programmer.  Exceptions include malformed requests
// such as invalid Bind requests or invalid Creds.
type Hooks interface {
	AuthHook(c *Client, err error)
	BindHook(c *Client, req *BindReq)
	UnbindHook(c *Client, req *UnbindReq)
	MessageHook(c *Client, msg *Message) bool
	DisconnectHook(c *Client)
	StatusHook(c *Client, stats map[string]uint32)
	ErrorLogHook(c *Client, error string)
}

type fq_cmd_instr struct {
	cmd  protoCommand
	data struct {
		heartbeat struct {
			interval time.Duration
		}
		status struct {
			vals map[string]uint32
		}
		bind   *BindReq
		unbind *UnbindReq
		auth   struct {
			err error
		}
		return_value int
	}
}
type hookReq struct {
	htype hookType
	entry *fq_cmd_instr
}
type backMessage struct {
	msg  *Message
	hreq *hookReq
}
type Client struct {
	host                          string
	port                          uint16
	last_resolve                  time.Time
	Error                         *string
	user, pass, queue, queue_type string
	key                           fq_rk
	cmd_conn, data_conn           net.Conn
	stop                          bool
	cmd_hb_needed                 bool
	cmd_hb_interval               time.Duration
	cmd_hb_max_age                time.Duration
	cmd_hb_last                   time.Time
	peermode                      bool
	qmaxlen                       int
	non_blocking                  bool
	connected                     bool
	data_ready                    bool
	sync_hooks                    bool
	cmdq                          chan *fq_cmd_instr
	q                             chan *Message
	backq                         chan *backMessage
	hooks                         Hooks
	enqueue_mu                    sync.Mutex
	signal, done_cmd, done_data   chan bool
}

// Rk will take an input string and build an fq_rk that is used
// extensively throughout the fq system.  This should be used to
// assign to Exchange and Route in various objects.
func Rk(str string) fq_rk {
	input := []byte(str)
	inlen := len(input)
	if inlen > FQ_MAX_RK_LEN {
		inlen = FQ_MAX_RK_LEN
	}
	rk := fq_rk{}
	copy(rk.Name[:], input[:inlen])
	rk.Len = uint8(inlen)
	return rk
}

// ToString is a convenience function to stringify the
// Name within the fq_rk
func (rk *fq_rk) ToString() string {
	return string(rk.Name[:rk.Len])
}

// SetUint32 allows the caller to set the first 8 bytes of the 16 bytes
// fq_msgid with two uint32 arguments.  The last 8 bytes are controlled
// upstream.
func (id *fq_msgid) SetUint32(u1, u2 uint32) {
	ne.PutUint32(id.d[0:], u1)
	ne.PutUint32(id.d[4:], u2)
}

// SetUint64 allows the caller to set the first 8 bytes of the 16 bytes
// fq_msgid with one uint64 arguments.  The last 8 bytes are controlled
// upstream.
func (id *fq_msgid) SetUint64(u1 uint64) {
	ne.PutUint64(id.d[0:], u1)
}

// GetUint32 will return the 16 bytes of fq_msgid as four uint32 values.
func (id *fq_msgid) GetUint32() (uint32, uint32, uint32, uint32) {
	return ne.Uint32(id.d[0:]), ne.Uint32(id.d[4:]), ne.Uint32(id.d[8:]), ne.Uint32(id.d[12:])
}

// GetUint64 will return the 16 bytes of msgid as two uint64 values.
func (id *fq_msgid) GetUint64() (uint64, uint64) {
	return ne.Uint64(id.d[0:]), ne.Uint64(id.d[8:])
}

// NewMessage composes a new fq Message with the supplied exchange, route
// and payload.
func NewMessage(exchange, route string, payload []byte) *Message {
	msg := &Message{}
	msg.Exchange = Rk(exchange)
	msg.Route = Rk(route)
	if payload != nil {
		msg.Payload = payload
	}
	rand.Read(msg.Sender_msgid.d[0:8])
	return msg
}

func (c *Client) error(err error) {
	var errorstr string = err.Error()
	c.Error = &errorstr
	if c.hooks != nil {
		c.hooks.ErrorLogHook(c, errorstr)
	}
}

func internalClient(peermode bool) Client {
	conn := Client{}
	conn.qmaxlen = 10000
	conn.peermode = peermode
	conn.SetHeartBeat(time.Second)
	return conn
}

// NewClient creates a new (regular) fq client
func NewClient() Client {
	conn := internalClient(false)
	return conn
}

// NewClient creates a new fq client in peering mode
func NewPeer() Client {
	conn := internalClient(true)
	return conn
}

// SetSynchronous will cause any hooks to be executed
// only in the context of the Receive method (thus
// local to the go thread calling Receive.  One should
// use this method if the Hooks implemented are not
// safe for concurrent calling.
func (c *Client) SetSynchronous(synchronous bool) {
	c.sync_hooks = synchronous
}

// SetHooks sets the set of hooks to be used by the
// connection to control interaction.  It is safe to
// interact with the Client inside the hooks.  A standard
// pattern would be to invoke a c.Bind(...) from within
// the AuthHook implementation.
func (c *Client) SetHooks(hooks Hooks) {
	c.hooks = hooks
}

// Creds configures the Client for connection.
// This must be called before publishing messages via
// Publish.  The sender argument follows the compound
// fq connection string convention that concatenates
// user/queue/properties
func (c *Client) Creds(host string, port uint16, sender, pass string) error {
	if c.user != "" {
		return fmt.Errorf("Creds already called")
	}
	sparts := strings.SplitN(sender, "/", 3)
	c.user = sparts[0]
	if len(sparts) > 1 {
		c.queue = sparts[1]
		if len(sparts) > 2 {
			c.queue_type = sparts[2]
		}
	} else {
		myname, err := os.Hostname()
		if err != nil {
			myname = "unknown"
		}
		parts := strings.SplitN(myname, ".", 2)
		myname = parts[0]
		pid := os.Getpid()
		var rndb [4]byte
		rand.Read(rndb[:])
		rnd := hex.EncodeToString(rndb[:])
		c.queue = "q-" + myname + "-" + strconv.Itoa(pid) + "-" + rnd
	}
	if c.queue_type == "" {
		c.queue_type = FQ_DEFAULT_QUEUE_TYPE
	}
	c.pass = pass

	c.cmdq = make(chan *fq_cmd_instr, 1000)
	c.q = make(chan *Message, c.qmaxlen)
	c.backq = make(chan *backMessage, c.qmaxlen)
	c.signal = make(chan bool, 1)

	c.host = host
	c.port = port
	return nil
}

// SetHeartBeat will set the Duration of the heartbeating.
// By default the max allowable silence is three times the
// provided value.  It can be changed *after* this call via
// SetHeartBeatMaxAge.
func (c *Client) SetHeartBeat(interval time.Duration) {
	if interval > time.Second {
		interval = time.Second
	}
	c.cmd_hb_interval = interval
	c.cmd_hb_max_age = 3 * interval
	if c.data_ready {
		c.HeartBeat()
	}
}

// SetHeartBeatMaxAge sets the max allowable silence before
// the connection is connection is considered dead.  Silence
// in this case is considered the time since the last heartbeat.
func (c *Client) SetHeartBeatMaxAge(interval time.Duration) {
	c.cmd_hb_max_age = interval
}

// Heartbeat will send a heartbeart request upstream.  This
// is automatically invoked after normal successful authentication.
func (c *Client) HeartBeat() {
	if c.cmdq == nil {
		return
	}
	e := &fq_cmd_instr{cmd: fq_PROTO_HBREQ}
	e.data.heartbeat.interval = c.cmd_hb_interval
	c.cmdq <- e
}

// Bind will request an fq ruleset to route messages on a
// specified Exchange with the provided Program.  Once the
// binding has completed, the BindHook will be called with
// the same BindReq, but the OutRouteId will be filled in.
func (c *Client) Bind(req *BindReq) {
	if c.cmdq == nil {
		return
	}
	e := &fq_cmd_instr{cmd: fq_PROTO_BINDREQ}
	e.data.bind = req
	c.cmdq <- e
}

// Unbind will request fq to unbind a specified route.
// The RouteId should be a route handed back from a successful
// Bind request. The UnbindHook will be called with OutSuccess
// filled in.
func (c *Client) Unbind(req *UnbindReq) {
	if c.cmdq == nil {
		return
	}
	e := &fq_cmd_instr{cmd: fq_PROTO_UNBINDREQ}
	e.data.unbind = req
	c.cmdq <- e
}

// Status will sent a connection status request to the server.
// Responses to this request will be handed back via the StatusHook.
func (c *Client) Status() {
	if c.cmdq == nil {
		return
	}
	e := &fq_cmd_instr{cmd: fq_PROTO_STATUSREQ}
	c.cmdq <- e
}

// SetBacklog controls the channel capacity of the internal message
// queue.  The deault it 10000, this must be called prior to Creds.
// If it is called subsequent to Creds, it has no effect.  SetBacklog
// returns the capacity of the internal queues.
func (c *Client) SetBacklog(len int) int {
	// We can only set the backlog before we've initialized
	if c.q == nil {
		c.qmaxlen = len
	}
	return c.qmaxlen
}

// SetNonBlocking controls the behavior or Publish.  If this is set
// to true, Publish will return immediately when the message would
// exceed the maximum specified backlog.  If it is set to false
// (default), Publish will block.
func (c *Client) SetNonBlocking(nonblock bool) {
	c.non_blocking = nonblock
}

// Connect establishes a connection to and fq server (as specified by
// by a prior call to Creds).
func (c *Client) Connect() error {
	if c.user == "" {
		err := fmt.Errorf("Creds must be called before Connect")
		c.error(err)
		return err
	}
	if c.connected {
		err := fmt.Errorf("Already connected")
		c.error(err)
		return err
	}
	c.done_data = make(chan bool, 1)
	c.done_cmd = make(chan bool, 1)
	c.connected = true

	go c.worker()
	go c.data_worker()
	return nil
}

// Shutdown disconnects from fq and waits for any queued message
// to be published.  Note that if you cannot connect to complete
// publication, this can hang.
func (c *Client) Shutdown() {
	close(c.q)
	<-c.done_data
	<-c.done_cmd
}

// DataBacklog returns the current number of messages queued
// waiting to be sent.
func (c *Client) DataBacklog() int {
	return len(c.q)
}

// Publish schedules a message for publication returning
// true if successful or false if the queue is full and the
// client is set to non blocking mode.
func (c *Client) Publish(msg *Message) bool {
	if c.non_blocking {
		c.enqueue_mu.Lock()
		defer c.enqueue_mu.Unlock()
		if len(c.q) >= c.qmaxlen {
			return false
		}
		c.q <- msg
	} else {
		c.q <- msg
	}
	return true
}

func (c *Client) handle_hook(e *fq_cmd_instr) {
	if c.hooks == nil {
		return
	}
	switch e.cmd {
	case fq_PROTO_BINDREQ:
		c.hooks.BindHook(c, e.data.bind)
	case fq_PROTO_UNBINDREQ:
		c.hooks.UnbindHook(c, e.data.unbind)
	case fq_PROTO_STATUSREQ:
		c.hooks.StatusHook(c, e.data.status.vals)
	}
}

func (c *Client) processBackMessage(bm *backMessage) *Message {
	if bm.hreq != nil {
		e := bm.hreq.entry
		switch bm.hreq.htype {
		case fq_AUTH_HOOK_TYPE:
			if c.sync_hooks && c.hooks != nil {
				c.hooks.AuthHook(c, e.data.auth.err)
			}
		case fq_CMD_HOOK_TYPE:
			c.handle_hook(e)
		default:
			if c.hooks != nil {
				c.hooks.ErrorLogHook(c, fmt.Sprintf("sync cmd feedback unknown: %v", e.cmd))
			}
		}
	}
	return bm.msg
}

// Receive will attempt to receive a message from fq.  If the client
// has been set to synchronous mode, Receive will transparently invoke
// any hooks as a part of fetching messages.  If block is true, the
// call will wait for an available message.  If block is false, nil
// will be returned if no message is immediately available.
func (c *Client) Receive(block bool) *Message {
	if block {
		for {
			select {
			case bm := <-c.backq:
				if msg := c.processBackMessage(bm); msg != nil {
					return msg
				}
			}
		}
	}

	select {
	case bm := <-c.backq:
		if msg := c.processBackMessage(bm); msg != nil {
			return msg
		}
	default:
	}
	return nil
}

func (c *Client) data_connect_internal() (net.Conn, error) {
	cmd := uint32(fq_PROTO_DATA_MODE)
	if c.peermode {
		cmd = uint32(fq_PROTO_PEER_MODE)
	}
	if c.cmd_conn == nil {
		return nil, fmt.Errorf("no cmd connection")
	}
	connstr := fmt.Sprintf("%s:%d", c.host, c.port)
	timeout := time.Duration(2) * time.Second
	conn, err := net.DialTimeout("tcp", connstr, timeout)
	if err != nil {
		return conn, err
	}
	conn.(*net.TCPConn).SetNoDelay(false)
	err = fq_write_uint32(conn, cmd)
	if err != nil {
		return conn, err
	}
	if err := fq_write_short_cmd(conn, uint16(c.key.Len), c.key.Name[:]); err != nil {
		return conn, err
	}
	return conn, nil
}
func (c *Client) do_auth() error {
	if err := fq_write_uint16(c.cmd_conn, uint16(fq_PROTO_AUTH_CMD)); err != nil {
		return fmt.Errorf("auth:cmd:" + err.Error())
	}
	if err := fq_write_uint16(c.cmd_conn, uint16(fq_PROTO_AUTH_PLAIN)); err != nil {
		return fmt.Errorf("auth:plain:" + err.Error())
	}
	user_bytes := []byte(c.user)
	if err := fq_write_short_cmd(c.cmd_conn, uint16(len(user_bytes)), user_bytes); err != nil {
		return fmt.Errorf("auth:user:" + err.Error())
	}
	queue_composed := make([]byte, 0, 256)
	queue_composed = append(queue_composed, []byte(c.queue)...)
	queue_composed = append(queue_composed, byte(0))
	queue_composed = append(queue_composed, []byte(c.queue_type)...)
	if err := fq_write_short_cmd(c.cmd_conn, uint16(len(queue_composed)), queue_composed); err != nil {
		return fmt.Errorf("auth:queue:" + err.Error())
	}
	pass_bytes := []byte(c.pass)
	if err := fq_write_short_cmd(c.cmd_conn, uint16(len(pass_bytes)), pass_bytes); err != nil {
		return fmt.Errorf("auth:pass:" + err.Error())
	}
	if cmd, err := fq_read_uint16(c.cmd_conn); err != nil {
		return fmt.Errorf("auth:response:" + err.Error())
	} else {
		switch cmd {
		case uint16(fq_PROTO_ERROR):
			return fmt.Errorf("auth:proto_error")
		case uint16(fq_PROTO_AUTH_RESP):
			if klen, err := fq_read_uint16(c.cmd_conn); err != nil || klen > uint16(cap(c.key.Name)) {
				return fmt.Errorf("auth:key:" + err.Error())
			} else {
				err = fq_read_complete(c.cmd_conn, c.key.Name[:], int(klen))
				if err != nil {
					return fmt.Errorf("auth:key:" + err.Error())
				}
				c.key.Len = uint8(klen)
			}
			c.data_ready = true
		default:
			if c.hooks != nil {
				c.hooks.ErrorLogHook(c, fmt.Sprintf("server auth response 0x%04x unknown", cmd))
			}
			return fmt.Errorf("auth:proto")
		}
	}
	return nil
}
func (c *Client) connect_internal() (net.Conn, error) {
	connstr := fmt.Sprintf("%s:%d", c.host, c.port)
	timeout := time.Duration(2) * time.Second
	conn, err := net.DialTimeout("tcp", connstr, timeout)
	if err != nil {
		return conn, err
	}
	c.cmd_conn = conn
	if err = fq_write_uint32(conn, uint32(fq_PROTO_CMD_MODE)); err != nil {
		return conn, err
	}
	err = c.do_auth()
	if c.hooks != nil {
		if c.sync_hooks {
			bm := &backMessage{hreq: &hookReq{}}
			bm.hreq.htype = fq_AUTH_HOOK_TYPE
			bm.hreq.entry.data.auth.err = err
			c.backq <- bm
		} else {
			c.hooks.AuthHook(c, err)
		}
	}
	c.HeartBeat()
	return conn, err
}

func (c *Client) command_receiver(cmds chan *fq_cmd_instr, cx_queue chan *fq_cmd_instr) {
	var req *fq_cmd_instr = nil
	defer close(cmds)
	for {
		cmd, err := fq_read_uint16(c.cmd_conn)
		if err != nil {
			c.error(err)
			return
		}
		if req == nil {
			select {
			case possible_req, ok := <-cx_queue:
				if !ok {
					return
				}
				req = possible_req
			default:
			}
		}
		switch cmd {
		case uint16(fq_PROTO_HB):
			c.cmd_hb_last = time.Now()
			c.cmd_hb_needed = true
		case uint16(fq_PROTO_STATUS):
			if req == nil || req.cmd != fq_PROTO_STATUSREQ {
				c.error(fmt.Errorf("protocol violation (exp stats)"))
				return
			}
			vals := make(map[string]uint32)
			for {
				klen, err := fq_read_uint16(c.cmd_conn)
				if err != nil {
					c.error(err)
					return
				}
				if klen == 0 {
					break
				}
				key := make([]byte, int(klen))
				err = fq_read_complete(c.cmd_conn, key, int(klen))
				if err != nil {
					c.error(err)
					return
				}
				val, err2 := fq_read_uint32(c.cmd_conn)
				if err2 != nil {
					c.error(err2)
					return
				}
				vals[string(key)] = val
			}
			req.data.status.vals = vals
			cmds <- req
			req = nil
		case uint16(fq_PROTO_BIND):
			if req == nil || req.cmd != fq_PROTO_BINDREQ {
				c.error(fmt.Errorf("protocol violation (exp bind, %v)", req))
				return
			}
			routeid, err := fq_read_uint32(c.cmd_conn)
			if err != nil {
				c.error(err)
				return
			}
			req.data.bind.OutRouteId = routeid
			cmds <- req
			req = nil
		case uint16(fq_PROTO_UNBIND):
			if req == nil || req.cmd != fq_PROTO_UNBINDREQ {
				c.error(fmt.Errorf("protocol violation (exp unbind)"))
				return
			}
			success, err := fq_read_uint32(c.cmd_conn)
			if err != nil {
				c.error(err)
				return
			}
			req.data.unbind.OutSuccess = success
			cmds <- req
			req = nil
		default:
			c.error(fmt.Errorf("protocol violation: %x", cmd))
			return
		}
	}
}
func (c *Client) command_send(req *fq_cmd_instr, cx_queue chan *fq_cmd_instr) error {
	switch req.cmd {
	case fq_PROTO_STATUSREQ:
		cx_queue <- req
		return fq_write_uint16(c.cmd_conn, uint16(req.cmd))
	case fq_PROTO_HBREQ:
		hb_ms := req.data.heartbeat.interval.Nanoseconds() /
			time.Millisecond.Nanoseconds()
		if err := fq_write_uint16(c.cmd_conn, uint16(req.cmd)); err != nil {
			return err
		}
		if err := fq_write_uint16(c.cmd_conn, uint16(hb_ms)); err != nil {
			return err
		}
		c.cmd_hb_interval = req.data.heartbeat.interval
		c.cmd_hb_last = time.Now()
	case fq_PROTO_BINDREQ:
		cx_queue <- req
		if err := fq_write_uint16(c.cmd_conn, uint16(req.cmd)); err != nil {
			return err
		}
		if err := fq_write_uint16(c.cmd_conn, req.data.bind.Flags); err != nil {
			return err
		}
		if err := fq_write_short_cmd(c.cmd_conn,
			uint16(req.data.bind.Exchange.Len),
			req.data.bind.Exchange.Name[:]); err != nil {
			return err
		}
		pbytes := []byte(req.data.bind.Program)
		pbytes_len := uint16(len(pbytes))
		if len(pbytes) != int(pbytes_len) {
			return fmt.Errorf("program too long")
		}
		if err := fq_write_short_cmd(c.cmd_conn, pbytes_len, pbytes); err != nil {
			return err
		}
	case fq_PROTO_UNBINDREQ:
		cx_queue <- req
		if err := fq_write_uint16(c.cmd_conn, uint16(req.cmd)); err != nil {
			return err
		}
		if err := fq_write_uint32(c.cmd_conn, req.data.unbind.RouteId); err != nil {
			return err
		}
		if err := fq_write_short_cmd(c.cmd_conn,
			uint16(req.data.unbind.Exchange.Len),
			req.data.unbind.Exchange.Name[:]); err != nil {
			return err
		}
	default:
		return fmt.Errorf("can't send unknown cmd: %x", req.cmd)
	}
	return nil
}
func (c *Client) worker_loop() {
	conn, err := c.connect_internal()
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		c.error(err)
		c.signal <- true
		return
	}
	// Let the data channel know it can move forward

	// A go routine is started to read from the wire and put
	// commands into the cmds channel
	cmds := make(chan *fq_cmd_instr, 10)

	// Commands that are send are read from the client cmdq channel
	// and placed into the cx_queue channel, command processing
	// reads from the cmds channel and matches against the cx_queue
	// channel.
	cx_queue := make(chan *fq_cmd_instr, 10)
	hb_chan := make(chan bool, 1)
	hb_quit_chan := make(chan bool, 1)

	// this is like a Ticker, but adaptive to the interval changes
	go (func(c *Client, hb chan bool, q chan bool) {
		for keep_going := true; keep_going; {
			select {
			case <-q:
				keep_going = false
			default:
			}
			time.Sleep(c.cmd_hb_interval)
			hb <- true
		}
		close(hb)
	})(c, hb_chan, hb_quit_chan)

	// command_receiver writes to cmds, so it will close the channel
	// we write to cx_queue via command_send, so we must clost this one
	defer (func() {
		close(cx_queue)
		close(hb_quit_chan)
		conn.Close()
		c.data_ready = false
	})()
	c.signal <- true
	go c.command_receiver(cmds, cx_queue)
	for c.stop == false {
		select {
		case cmd, ok := <-cmds:
			if !ok {
				c.error(fmt.Errorf("reading on command channel terminated"))
				return
			}
			if !c.sync_hooks {
				c.handle_hook(cmd)
			} else {
				bm := &backMessage{hreq: &hookReq{}}
				bm.hreq.htype = fq_CMD_HOOK_TYPE
				bm.hreq.entry = cmd
				c.backq <- bm
			}
		case req, ok := <-c.cmdq:
			if !ok {
				c.error(fmt.Errorf("client command queue closed"))
				return
			}
			if err := c.command_send(req, cx_queue); err != nil {
				c.error(err)
				return
			}
		case <-hb_chan:
			if c.cmd_hb_needed {
				if err := fq_write_uint16(c.cmd_conn, uint16(fq_PROTO_HB)); err != nil {
					c.error(err)
					return
				}
				needed_by := time.Now().Add(-c.cmd_hb_max_age)
				if c.cmd_hb_last.Before(needed_by) {
					c.error(fmt.Errorf("dead: missing heartbeat"))
					return
				}
			}
		}
	}
}
func (c *Client) worker() {
	for c.stop == false {
		c.worker_loop()
		if c.hooks != nil {
			c.hooks.DisconnectHook(c)
		}
	}
	close(c.done_cmd)
}
func (c *Client) data_sender() {
	for c.data_ready && c.stop == false {
		msg, ok := <-c.q
		if !ok {
			c.stop = true
			// We close here to cause the read in data_receiver
			// to error, otherwise it will hang forever.
			c.data_conn.Close()
			return
		}
		err := fq_write_msg(c.data_conn, msg, c.peermode)
		if err != nil {
			return
		}
	}
}
func (c *Client) data_receiver() {
	for c.data_ready {
		if msg, err := fq_read_msg(c.data_conn); err != nil {
			c.error(err)
			return
		} else {
			if msg != nil {
				if c.hooks == nil || c.hooks.MessageHook(c, msg) == false {
					c.backq <- &backMessage{msg: msg}
				}
			}
		}
	}
}
func (c *Client) data_worker_loop() bool {
	c.data_conn = nil
	conn, err := c.data_connect_internal()
	if err != nil {
		c.error(err)
		return false
	}
	c.data_conn = conn
	defer conn.Close()

	go c.data_sender()
	c.data_receiver()

	return true
}
func (c *Client) data_worker() {
	backoff := time.Duration(0)
	for c.stop == false {
		<-c.signal
		if c.data_ready {
			if c.data_worker_loop() {
				backoff = 0
			}
		}
		if backoff > 0 {
			four_ms_jitter := 4096 - (int(rng.Int31()) % 8192)
			jitter := time.Duration(four_ms_jitter) * time.Millisecond
			time.Sleep(backoff + jitter)
		} else {
			backoff = 16 * time.Millisecond
		}
		if backoff < time.Second {
			backoff += (backoff >> 4)
		}
	}
	close(c.done_data)
}

// A sample (and useful) Hook binding that allows for simple subscription.

type transientSubHooks struct {
	MsgsC    chan *Message
	ErrorsC  chan error
	bindings []BindReq
}

// NewTSHooks returns a simple hooks implementation that exposes
// a MsgC channel of Messages and ErrorsC channel of errors.
func NewTSHooks() transientSubHooks {
	return transientSubHooks{
		MsgsC:   make(chan *Message, 10000),
		ErrorsC: make(chan error, 1000),
	}
}
func (h *transientSubHooks) AuthHook(c *Client, err error) {
	if err != nil {
		h.ErrorsC <- err
		return
	}
	for _, breq := range h.bindings {
		c.Bind(&breq)
	}
}
func (h *transientSubHooks) AddBinding(exchange, program string) {
	breq := BindReq{
		Exchange: Rk(exchange),
		Flags:    FQ_BIND_TRANS,
		Program:  program,
	}
	h.bindings = append(h.bindings, breq)
}
func (h *transientSubHooks) BindHook(c *Client, breq *BindReq) {
	if breq.OutRouteId == 0xffffffff {
		h.ErrorsC <- fmt.Errorf("binding failure: %s, %s", breq.Exchange, breq.Program)
	}
}
func (h *transientSubHooks) UnbindHook(c *Client, breq *UnbindReq) {
}
func (h *transientSubHooks) DisconnectHook(c *Client) {
}
func (h *transientSubHooks) ErrorLogHook(c *Client, err string) {
	h.ErrorsC <- fmt.Errorf("%s", err)
}
func (h *transientSubHooks) StatusHook(c *Client, stats map[string]uint32) {
}
func (h *transientSubHooks) MessageHook(c *Client, msg *Message) bool {
	h.MsgsC <- msg
	return true
}
