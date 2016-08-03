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
	"fmt"
	"net"
)

func fq_read_complete(conn net.Conn, data []byte, want int) error {
	sofar := 0
	if want > cap(data) {
		panic("requested buffer overrun")
	}
	for {
		n, err := conn.Read(data[sofar:(want - sofar)])
		if err != nil {
			return err
		}
		sofar += n
		if sofar > want {
			panic("over read")
		}
		if sofar == want {
			return nil
		}
	}
}
func fq_read_uint8(conn net.Conn) (uint8, error) {
	buf := make([]byte, 1)
	if err := fq_read_complete(conn, buf, 1); err != nil {
		return 0, err
	}
	return uint8(buf[0]), nil
}
func fq_read_uint16(conn net.Conn) (uint16, error) {
	buf := make([]byte, 2)
	if err := fq_read_complete(conn, buf, 2); err != nil {
		return 0, err
	}
	return be.Uint16(buf), nil
}
func fq_read_uint32(conn net.Conn) (uint32, error) {
	buf := make([]byte, 4)
	if err := fq_read_complete(conn, buf, 4); err != nil {
		return 0, err
	}
	return be.Uint32(buf), nil
}
func fq_write_uint8(conn net.Conn, v uint8) error {
	cmd := [1]byte{v}
	n, err := conn.Write(cmd[:])
	if err != nil {
		return err
	}
	if n != len(cmd) {
		return fmt.Errorf("bad write (size)")
	}
	return nil
}
func fq_write_uint16(conn net.Conn, v uint16) error {
	cmd := make([]byte, 2)
	be.PutUint16(cmd, v)
	n, err := conn.Write(cmd[:])
	if err != nil {
		return err
	}
	if n != len(cmd) {
		return fmt.Errorf("bad write (size)")
	}
	return nil
}
func fq_write_uint32(conn net.Conn, v uint32) error {
	cmd := make([]byte, 4)
	be.PutUint32(cmd, v)
	n, err := conn.Write(cmd[:])
	if err != nil {
		return err
	}
	if n != len(cmd) {
		return fmt.Errorf("bad write (size)")
	}
	return nil
}
func fq_write_byte_cmd(conn net.Conn, dlen uint8, data []byte) error {
	if err := fq_write_uint8(conn, dlen); err != nil {
		return err
	}
	n, err := conn.Write(data[:int(dlen)])
	if err != nil {
		return err
	}
	if n != int(dlen) {
		return fmt.Errorf("bad write (data)")
	}
	return nil
}
func fq_write_short_cmd(conn net.Conn, dlen uint16, data []byte) error {
	if err := fq_write_uint16(conn, dlen); err != nil {
		return err
	}
	n, err := conn.Write(data[:int(dlen)])
	if err != nil {
		return err
	}
	if n != int(dlen) {
		return fmt.Errorf("bad write (data)")
	}
	return nil
}
func fq_write_long_cmd(conn net.Conn, dlen uint32, data []byte) error {
	if err := fq_write_uint32(conn, dlen); err != nil {
		return err
	}
	n, err := conn.Write(data[:int(dlen)])
	if err != nil {
		return err
	}
	if n != int(dlen) {
		return fmt.Errorf("bad write (data)")
	}
	return nil
}
func fq_read_rk(conn net.Conn, rk *fq_rk) error {
	var err error
	if rk.len, err = fq_read_uint8(conn); err != nil {
		return err
	}
	if err = fq_read_complete(conn, rk.name[:], int(rk.len)); err != nil {
		return err
	}
	return nil
}
func fq_read_msg(conn net.Conn) (*Message, error) {
	var err error
	msg := &Message{}
	if err = fq_read_rk(conn, &msg.Exchange); err != nil {
		return nil, err
	}
	if err = fq_read_rk(conn, &msg.Route); err != nil {
		return nil, err
	}
	if err = fq_read_complete(conn, msg.Sender_msgid.d[:], 16); err != nil {
		return nil, err
	}
	// We're always in peermode as a receiving client
	if err = fq_read_rk(conn, &msg.Sender); err != nil {
		return nil, err
	}
	var nhops uint8
	if nhops, err = fq_read_uint8(conn); err != nil {
		return nil, err
	}
	if nhops > 0 {
		hopbuf := make([]byte, 4*int(nhops))
		if err = fq_read_complete(conn, hopbuf, 4*int(nhops)); err != nil {
			return nil, err
		}
		for i := 0; i < int(nhops); i++ {
			msg.Hops[i] = ne.Uint32(hopbuf[i*4:])
		}
	}
	if msg.Payload_len, err = fq_read_uint32(conn); err != nil {
		return nil, err
	}
	msg.Payload = make([]byte, int(msg.Payload_len))
	if err = fq_read_complete(conn, msg.Payload, int(msg.Payload_len)); err != nil {
		return nil, err
	}
	return msg, nil
}
func fq_write_msg(conn net.Conn, msg *Message, peermode bool) error {
	if err := fq_write_byte_cmd(conn, msg.Exchange.len, msg.Exchange.name[:]); err != nil {
		return err
	}
	if err := fq_write_byte_cmd(conn, msg.Route.len, msg.Route.name[:]); err != nil {
		return err
	}
	if n, err := conn.Write(msg.Sender_msgid.d[:]); err != nil || n != 16 {
		if err != nil {
			return err
		}
		return fmt.Errorf("bad write msgid")
	}
	if peermode {
		if err := fq_write_byte_cmd(conn, msg.Sender.len, msg.Sender.name[:]); err != nil {
			return err
		}
		nhops := uint8(0)
		for i := 0; i < FQ_MAX_HOPS; i++ {
			if msg.Hops[i] == 0 {
				break
			}
			nhops++
		}
		if err := fq_write_uint8(conn, nhops); err != nil {
			return err
		}
		hopbuf := make([]byte, 4*nhops)
		for i := 0; i < int(nhops); i++ {
			ne.PutUint32(hopbuf[(i*4):], msg.Hops[i])
		}
		if n, err := conn.Write(hopbuf); err != nil || n != len(hopbuf) {
			if err != nil {
				return err
			}
			return fmt.Errorf("bad write msgid")
		}
	}
	if err := fq_write_long_cmd(conn, msg.Payload_len, msg.Payload); err != nil {
		return err
	}
	return nil
}
