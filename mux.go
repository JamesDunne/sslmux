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

	packet0 [][]byte
}

func newConn(c net.Conn) *conn {
	return &conn{
		c:       c,
		buffer:  make([]byte, buffer_size),
		logger:  log.New(os.Stderr, fmt.Sprintf("%s: ", c.RemoteAddr()), 0),
		packet0: make([][]byte, 0, 5),
	}
}

// timeout for SSH detection:
const timeoutDuration = time.Millisecond * 500

func (c *conn) handleError(err error, logger *log.Logger) (doContinue bool) {
	// EOF = connection closed?
	if err == io.EOF {
		if verbose {
			logger.Printf("io.EOF: %s\n", err.Error())
		}
		return
	}
	// Specific network error:
	if netError, ok := err.(net.Error); ok {
		// I/O Timeout:
		if netError.Timeout() {
			return true
		}

		// Do we continue?
		if netError.Temporary() {
			if verbose {
				logger.Printf("temporary net.Error: %s\n", err.Error())
			}
			return true
		} else {
			if verbose {
				logger.Printf("permanent net.Error: %s\n", err.Error())
			}
			return false
		}
	} else {
		// Don't know what kind of error:
		if verbose {
			logger.Printf("permanent error: %s\n", err.Error())
		}
	}
	return false
}

// Goroutine to handle transmitting packets from one socket to another:
func (c *conn) xmit(r io.Reader, w io.Writer, stop chan bool, logger *log.Logger) {
	buffer := make([]byte, buffer_size)
	for {
		// 5 second read deadline so that we don't get lots of CLOSE_WAIT sockets:
		r.(*net.TCPConn).SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(5000)))
		rn, err := r.Read(buffer)
		if err != nil {
			if c.handleError(err, logger) {
				continue
			} else {
				break
			}
		}

		_, err = w.Write(buffer[:rn])
		if err != nil {
			if c.handleError(err, logger) {
				continue
			} else {
				break
			}
		}
	}

	stop <- true
	if verbose {
		logger.Println("stopped")
	}
}

// Handles a single connection and sniffs the protocol:
func (c *conn) serve() {
	client := c.c

	if verbose {
		defer c.logger.Println("closed")
	}
	defer client.Close()

	if verbose {
		c.logger.Println("accepted")
	}

	var target_addr *base.Dialable
	sniffed := false
	for !sniffed {
		// Set a timeout on sniffing because some SSH clients (PuTTY) will wait eternally for incoming data before sending
		// their first packets:
		client.SetReadDeadline(time.Now().Add(timeoutDuration))

		// Read some data:
		n, err := client.Read(c.buffer)
		if err == io.EOF {
			return
		}
		if _, ok := err.(net.Error); ok {
			// Timed out; assume SSH:
			if verbose {
				c.logger.Println("timed out; assuming SSH")
			}
			sniffed = true
			target_addr = ssh_addr
			break
		}
		if err != nil {
			return
		}

		p := c.buffer[0:n]
		if debug && verbose {
			base.HexDumpToLogger(p, c.logger)
		}

		// Keep a rolling buffer of the packets we're sniffing so we can send them later:
		c.packet0 = append(c.packet0, p)

		// Check if TLS protocol:
		if n < 3 {
			continue
		}
		// TLS packet starts with a record "Hello" (0x16), followed by version (0x03 0x00-0x03) (RFC6101 A.1)
		// Reject SSLv2 and lower versions (RFC6176):
		if p[0] == 0x16 && p[1] == 0x03 && (p[2] >= 0x00 && p[2] <= 0x03) {
			sniffed = true
			target_addr = https_addr
			if verbose {
				c.logger.Println("detected HTTPS")
			}
			break
		}

		// Check if SSH protocol:
		if n < 4 {
			continue
		}
		if p[0] == 'S' && p[1] == 'S' && p[2] == 'H' && p[3] == '-' {
			sniffed = true
			target_addr = ssh_addr
			if verbose {
				c.logger.Println("detected SSH")
			}
			break
		}

		// if we got 4 or more bytes and didn't detected any protocol
		// redirecting it to others
		if n >= 4 && others_addr != nil {
			sniffed = true
			target_addr = others_addr
			if verbose {
				c.logger.Println("unknown protocol")
			}
			break
		}
	}

	// Clear the deadline:
	client.SetReadDeadline(time.Time{})

	// Now just copy data from in to out:
	server, err := net.Dial(target_addr.Network, target_addr.Address)
	if err != nil {
		if verbose {
			c.logger.Printf("%s\n", err)
		}
		return
	}
	defer server.Close()

	// Transmit first packet(s) that we sniffed:
	for _, p := range c.packet0 {
		_, err = server.Write(p)
		if err == io.EOF {
			return
		}
	}

	// Start proxying traffic both ways:
	complete := make(chan bool, 1)

	// From client to server:
	go c.xmit(client, server, complete, log.New(os.Stderr, fmt.Sprintf("%s; client->server: ", c.c.RemoteAddr()), 0))
	go c.xmit(server, client, complete, log.New(os.Stderr, fmt.Sprintf("%s; server->client: ", c.c.RemoteAddr()), 0))

	// Wait until either end closes:
	<-complete

	if verbose {
		c.logger.Println("complete")
	}
}

func serveMux(l net.Listener) (err error) {
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
				log.Printf("Accept error: %v; retrying in %v\n", e, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return e
		}
		tempDelay = 0

		c := newConn(rw)
		// Launch a goroutine to handle traffic:
		go c.serve()
	}

	return nil
}
