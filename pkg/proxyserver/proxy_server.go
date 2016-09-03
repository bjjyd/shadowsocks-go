package proxyserver

import (
	"shadowsocks-go/pkg/config"
	"shadowsocks-go/pkg/connection/tcp"
	"shadowsocks-go/pkg/connection/udp"

	"github.com/golang/glog"
)

//Servers hold on a list of proxyserver
type Servers struct {
	tcpSrvMap map[int64]ProxyServer //id to srv interface map
	udpSrvMap map[int64]ProxyServer //id to srv interface map
	enableUDP bool
}

//NewServers create a servers
func NewServers(udp bool) *Servers {
	return &Servers{
		tcpSrvMap: make(map[int64]ProxyServer),
		udpSrvMap: make(map[int64]ProxyServer),
		enableUDP: udp,
	}
}

func (srv *Servers) storeSrv(tcp ProxyServer, udp ProxyServer, cfg *config.ConnectionInfo) {
	srv.tcpSrvMap[cfg.ID] = tcp

	glog.Infof("store id %d  tcp :%p\r\n", cfg.ID, tcp)

	if srv.enableUDP {
		srv.udpSrvMap[cfg.ID] = udp
	}
}

//CheckServer create new server for users
func (srv *Servers) CheckServer(client *config.ConnectionInfo) (bool, bool) {

	var equal bool
	tcpSrv, exist := srv.tcpSrvMap[client.ID]
	if exist {
		equal = tcpSrv.Compare(client)
	}

	return exist, equal
}

//GetTraffic collection traffic for user,return upload traffic and download traffic
func (srv *Servers) GetTraffic(client *config.ConnectionInfo) (int64, int64, error) {
	var tcpUpload, tcpDownload, udpUpload, udpDownload int64
	tcpSrv, exist := srv.tcpSrvMap[client.ID]
	if exist {
		tcpUpload, tcpDownload = tcpSrv.Traffic()
		glog.V(5).Infof("Got %d Tcp traffic upload %d download:%d\r\n", client.Port, tcpUpload, tcpDownload)
	}

	if srv.enableUDP {
		udpSrv, exist := srv.udpSrvMap[client.ID]
		if exist {
			udpUpload, udpDownload = udpSrv.Traffic()
			glog.V(5).Infof("Got %d udp traffic upload %d download:%d\r\n", client.Port, udpUpload, udpDownload)
		} else {
			glog.Errorf("use udp relay but not found\r\n")
		}
	}

	return tcpUpload + udpUpload, tcpDownload + udpDownload, nil
}

//StopServer stop server only
func (srv *Servers) StopServer(client *config.ConnectionInfo) {
	tcpSrv, ok := srv.tcpSrvMap[client.ID]
	if !ok {
		glog.Warningf("not found tcp server %s\r\n", client.Port)
	} else {
		tcpSrv.Stop()

	}

	if srv.enableUDP {
		udpSrv, ok := srv.udpSrvMap[client.ID]
		if !ok {
			glog.Warningf("not found tcp server %s\r\n", client.Port)
		} else {
			udpSrv.Stop()

		}
	}
}

//CleanUpServer delete server from proxy manage. not use
func (srv *Servers) CleanUpServer(client *config.ConnectionInfo) {

	_, ok := srv.tcpSrvMap[client.ID]
	if !ok {
		glog.Warningf("not found tcp server %s\r\n", client.Port)
	} else {
		delete(srv.tcpSrvMap, client.ID)
	}

	if srv.enableUDP {
		_, ok := srv.udpSrvMap[client.ID]
		if !ok {
			glog.Warningf("not found tcp server %s\r\n", client.Port)
		} else {
			delete(srv.udpSrvMap, client.ID)
		}
	}

}

//StartWithConfig create new server for users
func (srv *Servers) StartWithConfig(v *config.ConnectionInfo) {

	glog.V(5).Infof("Start with %v at %p\r\n", v, v)

	tcpSrv := tcp.NewTCPServer(v)
	go tcpSrv.Run()

	var udpSrv ProxyServer
	if srv.enableUDP {
		udpSrv = udp.NewUDPServer(v)
		go udpSrv.Run()
	}

	srv.storeSrv(tcpSrv, udpSrv, v)
}

//Start create new server for user
func (srv *Servers) Start() {
	for idx := range config.ServerCfg.Clients {
		config := &config.ServerCfg.Clients[idx]
		srv.StartWithConfig(config)
	}
}
