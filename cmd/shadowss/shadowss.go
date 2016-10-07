package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"shadowsocks-go/cmd/shadowss/app"
	"shadowsocks-go/cmd/shadowss/app/options"
	"shadowsocks-go/pkg/util/flag"

	"github.com/spf13/pflag"
)

func waitSignal() {
	var sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	for sig := range sigChan {
		if sig == syscall.SIGHUP {
			//updatePasswd()
		} else {
			// is this going to happen?
			log.Printf("caught signal %v, exit", sig)
			os.Exit(0)
		}
	}
}

func main() {
	serverRunOptions := options.NewServerOption()
	serverRunOptions.AddFlags(pflag.CommandLine)

	flag.InitFlags()

	if err := app.Run(serverRunOptions); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	waitSignal()

	defer func() {
		if err := recover(); err != nil {
			debug.PrintStack()
		}
	}()
}
