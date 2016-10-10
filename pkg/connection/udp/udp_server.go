package udp

import (
	"reflect"
	"time"

	"shadowsocks-go/pkg/config"
	"shadowsocks-go/pkg/crypto"

	"github.com/golang/glog"
)

//UDPServer maintain a listener
type UDPServer struct {
	Config   *config.ConnectionInfo
	udpProxy *Proxy
}

//NewUDPServer create a TCPServer
func NewUDPServer(cfg *config.ConnectionInfo) *UDPServer {
	return &UDPServer{
		Config: cfg,
	}
}

//Stop implement quit go routine
func (udpSrv *UDPServer) Stop() {
	glog.V(5).Infof("udp server close %v\r\n", udpSrv.Config)
	udpSrv.udpProxy.Stop()
}

//Traffic get user traffic
func (udpSrv *UDPServer) Traffic() (int64, int64) {
	return udpSrv.udpProxy.Traffic()
}

//Run implement a new udp listener
func (udpSrv *UDPServer) Run() {

	password := udpSrv.Config.Password
	method := udpSrv.Config.EncryptMethod
	port := udpSrv.Config.Port
	auth := udpSrv.Config.EnableOTA
	timeout := time.Duration(udpSrv.Config.Timeout) * time.Second

	crypto, err := crypto.NewCrypto(method, password)
	if err != nil {
		glog.Fatalf("Error generating cipher for udp port: %d %v\n", port, err)
		return
	}

	proxy := NewProxy(port, crypto, auth, timeout)
	if proxy == nil {
		glog.Fatalf("listening upd port: %v error:%v\r\n", port, err)
		return
	}
	udpSrv.udpProxy = proxy

	udpSrv.Config.Port = udpSrv.udpProxy.GetPort()

	go proxy.RunProxy()
}

func (udpSrv *UDPServer) Compare(client *config.ConnectionInfo) bool {
	return reflect.DeepEqual(udpSrv.Config, client)
}

func (udpSrv *UDPServer) GetListenPort() int {
	return udpSrv.Config.Port
}

func (udpSrv *UDPServer) GetConfig() config.ConnectionInfo {
	return *udpSrv.Config
}
