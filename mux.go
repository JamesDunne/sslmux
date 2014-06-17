package main

import (
	"log"
	"net"
	"time"
)

func hex_dump(b []byte) {
	const digits = "0123456789abcdef"
	line := make([]byte, 3*16+16)

	lines := len(b) >> 4
	remainder := len(b) & 15

	log.Printf("\nLength: %d\n", len(b))
	t := 0
	for i := 0; i < lines; i++ {
		for j := 0; j < 16; j++ {
			d := b[t]
			t++
			line[j*3+0] = digits[(d>>4)&15]
			line[j*3+1] = digits[d&15]
			line[j*3+2] = ' '

			if d >= 32 && d <= 127 {
				line[16*3+j] = d
			} else {
				line[16*3+j] = '.'
			}
		}

		log.Println(string(line))
	}

	if remainder > 0 {
		for j := 0; j < remainder; j++ {
			d := b[t]
			t++
			line[j*3+0] = digits[(d>>4)&15]
			line[j*3+1] = digits[d&15]
			line[j*3+2] = ' '

			if d >= 32 && d <= 127 {
				line[16*3+j] = d
			} else {
				line[16*3+j] = '.'
			}
		}

		for j := remainder; j < 16; j++ {
			line[j*3+0] = ' '
			line[j*3+1] = ' '
			line[j*3+2] = ' '
			line[16*3+j] = ' '
		}

		log.Println(string(line))
	}
}

const buffer_size = 4096

type conn struct {
	c      net.Conn
	buffer []byte

	packet0 []byte
}

func newConn(c net.Conn) *conn {
	return &conn{c: c, buffer: make([]byte, buffer_size)}
}

// Handles a single connection and sniffs the protocol:
func (c *conn) serve() {
	defer c.c.Close()

	sniffed := false
	for !sniffed {
		// Read some data:
		n, err := c.c.Read(c.buffer)
		if err != nil {
			return
		}

		p := c.buffer[0:n]
		hex_dump(p)

		if n < 3 {
			continue
		}

		if p[0] == 0x16 && p[1] == 0x03 && (p[2] >= 0 && p[2] <= 0x03) {
		}
		sniffed = true
	}

	// Now just copy data from in to out:

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
