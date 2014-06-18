package main

import (
	"flag"
	"log"
	"os"
)

import "github.com/JamesDunne/go-util/base"

var (
	listen_addr *base.Listenable
	ssh_addr    *base.Dialable
	https_addr  *base.Dialable
	verbose     bool
)

func main() {
	var err error

	// Define our commandline flags:
	fl_listen_uri := flag.String("l", "tcp://0.0.0.0:4444", "listen URI (schemes available are tcp, unix)")
	fl_ssh_uri := flag.String("ssh", "tcp://localhost:22", "forward ssh traffic to an sshd listening at this URI")
	fl_https_uri := flag.String("https", "tcp://localhost:443", "forward https traffic to an https service listening at this URI")
	flag.BoolVar(&verbose, "v", false, "verbose logging")
	flag.Parse()

	// Parse all the URIs:
	listen_addr, err = base.ParseListenable(*fl_listen_uri)
	base.PanicIf(err)
	ssh_addr, err = base.ParseDialable(*fl_ssh_uri)
	base.PanicIf(err)
	https_addr, err = base.ParseDialable(*fl_https_uri)
	base.PanicIf(err)

	// Start the server:
	var sig os.Signal
	sig, err = base.ServeMain(listen_addr, serveMux)
	if err != nil {
		log.Fatal(err)
	}
	if sig != nil {
		log.Printf("\ncaught signal %s\n", sig)
	}
}
