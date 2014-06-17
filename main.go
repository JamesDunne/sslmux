package main

import (
	"flag"
	"fmt"
	"net/url"
)

import "github.com/JamesDunne/go-util/base"

var (
	listen_uri *url.URL
	ssh_uri    *url.URL
	https_uri  *url.URL
)

func main() {
	var err error

	// Define our commandline flags:
	fl_listen_uri := flag.String("l", "tcp://0.0.0.0:444", "listen URI (schemes available are tcp, unix)")
	fl_ssh_uri := flag.String("ssh", "tcp://localhost:22", "forward ssh traffic to an sshd listening at this URI")
	fl_https_uri := flag.String("https", "tcp://localhost:443", "forward https traffic to an https service listening at this URI")
	flag.Parse()

	// Parse all the URIs:
	listen_uri, err = url.Parse(*fl_listen_uri)
	base.PanicIf(err)
	ssh_uri, err = url.Parse(*fl_ssh_uri)
	base.PanicIf(err)
	https_uri, err = url.Parse(*fl_https_uri)
	base.PanicIf(err)

	var ltype, laddr string
	ltype = listen_uri.Scheme
	if ltype == "unix" {
		if listen_uri.Host != "" {
			panic(fmt.Errorf("unix URI must have blank host, e.g. unix:///path/to/socket"))
		}
		laddr = listen_uri.Path
	} else {
		laddr = listen_uri.Host
	}

	// Start the server:
	err = base.ServeMain(ltype, laddr, serveMux)
	base.PanicIf(err)
}
