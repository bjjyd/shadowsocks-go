package tcp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"sync"
	"syscall"
	"time"

	"shadowsocks-go/pkg/config"
	connection "shadowsocks-go/pkg/connection/tcp/unmaintained"
	encrypt "shadowsocks-go/pkg/connection/tcp/unmaintained"
	"shadowsocks-go/pkg/util"

	"github.com/golang/glog"
)

const (
	idType  = 0 // address type index
	idIP0   = 1 // ip addres start index
	idDmLen = 1 // domain address length index
	idDm0   = 2 // domain address start index

	typeIPv4 = 1 // type is ipv4 address
	typeDm   = 3 // type is domain address
	typeIPv6 = 4 // type is ipv6 address

	lenIPv4     = net.IPv4len + 2 // ipv4 + 2port
	lenIPv6     = net.IPv6len + 2 // ipv6 + 2port
	lenDmBase   = 2               // 1addrLen + 2port, plus addrLen
	lenHmacSha1 = 10
)

//TCPServer maintain a listener
type TCPServer struct {
	Config          *config.ConnectionInfo
	quit            chan struct{}
	UploadTraffic   int64 //request upload traffic
	DownloadTraffic int64 //request download traffic
	//ClientDict Mapping from client addresses (as host:port) to connection
	clientDict map[string]*connector

	//mutex Mutex used to serialize access to the dictionary
	mutex *sync.Mutex
}

type accepted struct {
	conn net.Conn
	err  error
}

type connector struct {
	clientConn *connection.Conn
	serverConn map[string]net.Conn //proxy to remote connnection
}

//NewTCPServer create a TCPServer
func NewTCPServer(cfg *config.ConnectionInfo) *TCPServer {
	return &TCPServer{
		Config:     cfg,
		quit:       make(chan struct{}),
		clientDict: make(map[string]*connector),
		mutex:      new(sync.Mutex),
	}
}

//Stop implement quit go routine
func (tcpSrv *TCPServer) Stop() {
	glog.V(5).Infof("tcp server close %v\r\n", tcpSrv.Config)
	close(tcpSrv.quit)
}

//Traffic ollection traffic for client,return upload traffic and download traffic
func (tcpSrv *TCPServer) Traffic() (int64, int64) {
	return tcpSrv.UploadTraffic, tcpSrv.DownloadTraffic
}

func getRequest(conn *connection.Conn, auth bool, timeout time.Duration) (host string, ota bool, err error) {

	SetReadTimeout(conn, timeout)

	// buf size should at least have the same size with the largest possible
	// request size (when addrType is 3, domain name has at most 256 bytes)
	// 1(addrType) + 1(lenByte) + 256(max length address) + 2(port) + 10(hmac-sha1)
	buf := make([]byte, 270)
	// read till we get possible domain length field
	if _, err = io.ReadFull(conn, buf[:idType+1]); err != nil {
		glog.Errorln("read buffer from remote connection error:", err)
		return
	}

	var reqStart, reqEnd int
	addrType := buf[idType]
	switch addrType & connection.AddrMask {
	case typeIPv4:
		reqStart, reqEnd = idIP0, idIP0+lenIPv4
	case typeIPv6:
		reqStart, reqEnd = idIP0, idIP0+lenIPv6
	case typeDm:
		glog.V(5).Infoln("Got a Domain Addr Type, read start(%v) end(%v)\r\n", idType+1, idDmLen+1)
		if _, err = io.ReadFull(conn, buf[idType+1:idDmLen+1]); err != nil {
			glog.Errorf("Read from remote err:%v\r\n", err)
			return
		}
		reqStart, reqEnd = idDm0, int(idDm0+buf[idDmLen]+lenDmBase)
	default:
		err = fmt.Errorf("addr type %d not supported", addrType&connection.AddrMask)
		return
	}

	if _, err = io.ReadFull(conn, buf[reqStart:reqEnd]); err != nil {
		return
	}

	glog.V(5).Infof("Got string from remote %v \r\n", buf[reqStart:reqEnd])
	// Return string for typeIP is not most efficient, but browsers (Chrome,
	// Safari, Firefox) all seems using typeDm exclusively. So this is not a
	// big problem.
	switch addrType & connection.AddrMask {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+buf[idDmLen]])
	}
	glog.V(5).Infof("Got host from remote: %v\r\n", host)
	// parse port
	port := binary.BigEndian.Uint16(buf[reqEnd-2 : reqEnd])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	// if specified one time auth enabled, we should verify this
	if auth || addrType&connection.OneTimeAuthMask > 0 {
		ota = true
		if _, err = io.ReadFull(conn, buf[reqEnd:reqEnd+lenHmacSha1]); err != nil {
			return
		}
		iv := conn.GetIv()
		key := conn.GetKey()
		actualHmacSha1Buf := util.HmacSha1(append(iv, key...), buf[:reqEnd])
		if !bytes.Equal(buf[reqEnd:reqEnd+lenHmacSha1], actualHmacSha1Buf) {
			err = fmt.Errorf("verify one time auth failed, iv=%v key=%v data=%v", iv, key, buf[:reqEnd])
			return
		}
	}
	return
}

type isClosed struct {
	isClosed bool
}

func (tcpSrv *TCPServer) handleConnection(clientKey string) {
	connector := tcpSrv.clientDict[clientKey]
	conn := connector.clientConn
	timeout := time.Duration(tcpSrv.Config.Timeout) * time.Second

	closed := false
	defer func() {
		if !closed {
			conn.Close()
			tcpSrv.lock()
			delete(tcpSrv.clientDict, clientKey)
			tcpSrv.unlock()
		}
	}()

	var host string
	host, ota, err := getRequest(conn, tcpSrv.Config.EnableOTA, timeout)
	if err != nil {
		glog.Errorf("error getting request %v<->%v err:%v", conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}
	glog.V(5).Infof("connection host:%v ota:%v \r\n", host, ota)

	remote, err := net.Dial("tcp", host)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			glog.Errorf("dial error:%v\r\n", err)
		} else {
			glog.Errorf(" connecting to:%v occur err:%v", host, err)
		}
		return
	}
	connector.serverConn[host] = remote

	defer func() {
		if !closed {
			remote.Close()
			delete(connector.serverConn, host)
		}
	}()

	glog.V(5).Infof("piping %s<->%s ota=%v connOta=%v", conn.RemoteAddr(), host, ota, conn.IsOta())

	if ota {
		go tcpSrv.handleRequest(conn, remote, timeout)
	} else {
		go tcpSrv.PipeThenClose(conn, remote, timeout, true)
	}
	tcpSrv.PipeThenClose(remote, conn, timeout, false)
	closed = true
	return
}

func (tcpSrv *TCPServer) lock() {
	tcpSrv.mutex.Lock()
}

func (tcpSrv *TCPServer) unlock() {
	tcpSrv.mutex.Unlock()
}

func (tcpSrv *TCPServer) process(accept accepted, cipher *encrypt.Cipher) {
	if accept.err != nil {
		glog.V(5).Infof("accept error: %v\n", accept.err)
		return
	}

	reqAddr := accept.conn.RemoteAddr().String()

	tcpSrv.lock()
	connnector, found := tcpSrv.clientDict[reqAddr]
	if !found {
		conn := connection.NewConn(accept.conn, cipher.Copy())
		connnector = &connector{
			clientConn: conn,
			serverConn: make(map[string]net.Conn),
		}

		tcpSrv.clientDict[reqAddr] = connnector
		tcpSrv.unlock()

		glog.V(5).Infof("Created new connection for client %s\n", reqAddr)
	} else {
		glog.V(5).Infof("Found connection for client %s\n", reqAddr)
		tcpSrv.unlock()
	}
	go tcpSrv.handleConnection(reqAddr)
}

//Run start a tcp listen for user
func (tcpSrv *TCPServer) Run() {
	password := tcpSrv.Config.Password
	method := tcpSrv.Config.EncryptMethod
	port := tcpSrv.Config.Port

	portStr := strconv.Itoa(port)
	ln, err := net.Listen("tcp", ":"+portStr)
	if err != nil {
		glog.Errorf("tcp server(%v) error: %v\n", port, err)
	}
	defer ln.Close()

	cipher, err := encrypt.NewCipher(method, password)
	if err != nil {
		glog.Errorf("Error generating cipher for port: %s %v\n", port, err)
		return
	}
	glog.V(5).Infof("tcp server listening on %v port %v  ...\n", ln.Addr().String(), port)

	for {
		c := make(chan accepted, 1)
		go func() {
			glog.V(5).Infoln("wait for accept")
			var conn net.Conn
			conn, err = ln.Accept()
			c <- accepted{conn: conn, err: err}
		}()

		select {
		case <-tcpSrv.quit:
			glog.Infof("Receive Quit singal for %s\r\n", port)
			return
		case accept := <-c:
			tcpSrv.process(accept, cipher.Copy())
		}
	}
}

func (tcpSrv *TCPServer) Compare(client *config.ConnectionInfo) bool {
	return reflect.DeepEqual(*tcpSrv.Config, *client)
}
