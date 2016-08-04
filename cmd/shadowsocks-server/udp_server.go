package main

import (
	"log"
	"net"

	"github.com/golang/glog"
)

var udp bool

const dnsGoroutineNum = 64

type UDPListener struct {
	password string
	listener *net.UDPConn
}

func runUDP(password, method string, port int) {
	var cipher *ss.Cipher
	listenPort := port

	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv6zero,
		Port: listenPort,
	})
	defer conn.Close()
	if err != nil {
		glog.Fatalf("listening upd port: %v error:%v\r\n", port, err)
	}

	passwdManager.addUDP(port, password, conn)
	if err != nil {
		glog.Fatalf("error listening udp port %v: %v\n", port, err)
		return
	}
	cipher, err = ss.NewCipher(method, password)
	if err != nil {
		log.Printf("Error generating cipher for udp port: %s %v\n", port, err)
		conn.Close()
	}

	UDPConn := ss.NewUDPConn(conn, cipher.Copy())
	for {
		UDPConn.ReadAndHandleUDPReq()
	}
}
