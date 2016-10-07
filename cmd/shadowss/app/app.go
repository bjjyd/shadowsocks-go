package app

import (
	"runtime"

	"shadowsocks-go/cmd/shadowss/app/options"
	"shadowsocks-go/pkg/proxyserver"

	"github.com/golang/glog"
)

//Run start a api server
func Run(options *options.ServerOption) error {

	if options.CpuCoreNum > 0 {
		runtime.GOMAXPROCS(options.CpuCoreNum)
	}

	pxy := proxyserver.NewServers(options.EnableUDPRelay)
	err := options.LoadConfigFile()
	if err != nil {
		glog.Fatalf("load user configure error: %v\r\n", err)
	} else {
		pxy.Start()
	}

	return nil
}
