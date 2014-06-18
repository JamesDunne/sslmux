package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

import "github.com/JamesDunne/go-util/base"

const buffer_size = 4096
const debug = false

type conn struct {
	c      net.Conn
	logger *log.Logger
	buffer []byte

	packet0 []byte
}

func newConn(c net.Conn) *conn {
	return &conn{c: c, buffer: make([]byte, buffer_size), logger: log.New(os.Stderr, fmt.Sprintf("%s: ", c.RemoteAddr()), 0)}
}

// 200ms timeout for SSH detection:
const timeoutDuration = time.Millisecond * time.Duration(500)

// Handles a single connection and sniffs the protocol:
func (c *conn) serve() {
	defer c.logger.Println("closed")
	defer c.c.Close()

	c.logger.Println("accepted")

	var target_addr *base.Dialable
	sniffed := false
	for !sniffed {
		// Set a timeout on sniffing because some SSH clients (PuTTY) will wait eternally for incoming data before sending
		// their first packets:
		c.c.SetReadDeadline(time.Now().Add(timeoutDuration))

		// Read some data:
		n, err := c.c.Read(c.buffer)
		if _, ok := err.(net.Error); ok {
			// Timed out; assume SSH:
			log.Println("timed out; assuming SSH")
			sniffed = true
			target_addr = ssh_addr
			break
		}
		if err != nil {
			return
		}

		p := c.buffer[0:n]
		if debug {
			base.HexDumpToLogger(p, c.logger)
		}

		// Check if TLS protocol:
		if n < 3 {
			continue
		}
		// TLS packet starts with a record "Hello" (0x16), followed by version (0x03 0x00-0x03) (RFC6101 A.1)
		// Reject SSLv2 and lower versions (RFC6176):
		if p[0] == 0x16 && p[1] == 0x03 && (p[2] >= 0x00 && p[2] <= 0x03) {
			sniffed = true
			target_addr = https_addr
			c.logger.Println("detected HTTPS")
			break
		}

		// Check if SSH protocol:
		if n < 4 {
			continue
		}
		if p[0] == 'S' && p[1] == 'S' && p[2] == 'H' && p[3] == '-' {
			sniffed = true
			target_addr = ssh_addr
			c.logger.Println("detected SSH")
			break
		}
	}

	// Clear the deadline:
	c.c.SetReadDeadline(time.Time{})

	// Now just copy data from in to out:
	w, err := net.Dial(target_addr.Network, target_addr.Address)
	if err != nil {
		c.logger.Printf("%s\n", err)
		return
	}

	io.Copy(w, c.c)
}

func serveMux(l net.Listener) {
	defer l.Close()
	var tempDelay time.Duration // how long to sleep on accept failure
	for {
		rw, e := l.Accept()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				log.Printf("http: Accept error: %v; retrying in %v\n", e, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			panic(e)
		}
		tempDelay = 0

		c := newConn(rw)
		// Launch a goroutine to handle traffic:
		go c.serve()
	}
}
