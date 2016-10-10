package proxyserver

import (
	"shadowsocks-go/pkg/config"
)

//ProxyServer implement a proxy server interface
type ProxyServer interface {
	Run()
	Stop()
	Compare(*config.ConnectionInfo) bool
	Traffic() (int64, int64)
	GetListenPort() int
	GetConfig() config.ConnectionInfo
}
