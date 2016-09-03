package udp

import (
	"fmt"
	"net"
	"sync"
	"time"

	"shadowsocks-go/pkg/crypto"
	"shadowsocks-go/pkg/protocol"
	"shadowsocks-go/pkg/util"

	"github.com/golang/glog"
)

//Proxy Information maintained for each client/server connection
type Proxy struct {
	port        int            //this proxy listen port
	cryp        *crypto.Crypto //decode data read from client
	timeout     time.Duration  //write or read timeoutt
	proxyConn   *net.UDPConn   //listener connection
	oneTimeAuth bool           //account configure one time auth

	//ClientDict Mapping from client addresses (as host:port) to connection
	ClientDict map[string]*Connection

	//dmutex Mutex used to serialize access to the dictionary
	dmutex *sync.Mutex
	//quit loop
	quit chan struct{}

	wg sync.WaitGroup

	uploadTraffic int64 //request upload traffic
}

type receive struct {
	readLen int
	cliAddr *net.UDPAddr
	err     error
	buffer  []byte
}

//NewProxy implement new a proxy. it listen on given port
func NewProxy(port int, cryp *crypto.Crypto, auth bool, timeout time.Duration) *Proxy {
	proxy := new(Proxy)
	// Set up Proxy
	saddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil
	}
	pudp, err := net.ListenUDP("udp", saddr)
	if err != nil {
		glog.Errorf("listen on %d failure : %v\r\n", port, err)
		return nil
	}

	glog.V(5).Infof("Proxy serving on port %d\n", port)
	proxy.proxyConn = pudp
	proxy.cryp = cryp
	proxy.timeout = timeout
	proxy.oneTimeAuth = auth

	proxy.ClientDict = make(map[string]*Connection)
	proxy.dmutex = new(sync.Mutex)
	proxy.quit = make(chan struct{})
	proxy.port = port

	return proxy
}

func (pxy *Proxy) dlock() {
	pxy.dmutex.Lock()
}

func (pxy *Proxy) dunlock() {
	pxy.dmutex.Unlock()
}

//Stop quit loop
func (pxy *Proxy) Stop() {
	close(pxy.quit)
	pxy.wg.Wait()
}

//Traffic quit loop
func (pxy *Proxy) Traffic() (int64, int64) {
	var upload, download int64
	for _, val := range pxy.ClientDict {
		val.Dmutex.Lock()

		download += val.DownloadTraffic
		val.DownloadTraffic = 0

		val.Dmutex.Unlock()
	}

	pxy.dlock()
	upload = pxy.uploadTraffic
	pxy.uploadTraffic = 0
	pxy.dunlock()

	return upload, download
}

func (pxy *Proxy) cleanup() {
	glog.Infof("Stop Proxy with %v\r\n", pxy.port)
	err := pxy.proxyConn.Close()
	if err != nil {
		glog.Errorf("connection close error %v\r\n", err)
	}

	for _, val := range pxy.ClientDict {
		close(val.Quit)
	}

	pxy.wg.Done()
}

//decrypt decrypt data to plain text
func (pxy *Proxy) decrypt(encBuffer []byte) ([]byte, error) {

	byteLen := len(encBuffer)
	ivLen := pxy.cryp.GetIVLen()
	if byteLen < ivLen {
		return nil, fmt.Errorf("request body too short\r\n")
	}

	decBuffer := make([]byte, byteLen)
	copy(decBuffer[0:ivLen], encBuffer[0:ivLen])

	_, err := pxy.cryp.UpdataCipherStream(decBuffer[0:ivLen], false)
	if err != nil {
		return nil, err
	}
	err = pxy.cryp.Decrypt(decBuffer[ivLen:], encBuffer[ivLen:byteLen])
	if err != nil {
		return nil, err
	}

	glog.V(5).Infof("Got  decrypt cipher ivlen(%d) iv: \r\n%s", ivLen, util.DumpHex(decBuffer[0:ivLen]))
	glog.V(5).Infof("Got  decrypt datalen(%d) data:\r\n%s", byteLen, util.DumpHex(encBuffer[ivLen:byteLen]))
	glog.V(5).Infof("Got  plainText data:\r\n%s", util.DumpHex(decBuffer[ivLen:]))

	return decBuffer, nil
}

func AssembleResp(resp []byte, byteLen int, crypto *crypto.Crypto) ([]byte, error) {
	dataStart := 0

	dataSize := byteLen + crypto.GetIVLen() // for addr type
	cipherData := make([]byte, dataSize)

	dataStart = crypto.GetIVLen()

	plainText := make([]byte, byteLen)
	copy(plainText[:], resp[:])

	iv, err := crypto.UpdataCipherStream(nil, true)
	if err != nil {
		return nil, err
	}

	err = crypto.Encrypt(cipherData[dataStart:], plainText)
	if err != nil {
		return nil, err
	}

	copy(cipherData[0:dataStart], iv)

	glog.V(5).Infof("encrypt cipher ivlen(%d) iv: \r\n%s \r\n", len(iv), util.DumpHex(iv))
	glog.V(5).Infof("encrypt plainText data : \r\n%s \r\n", util.DumpHex(plainText[:]))
	glog.V(5).Infof("encrypt data: \r\n%s \r\n", util.DumpHex(cipherData[dataStart:]))

	return cipherData, err
}

func (pxy *Proxy) handleRequest(recv receive) {

	saddr := recv.cliAddr.String()
	cliaddr := recv.cliAddr
	n := recv.readLen

	if nil != recv.err && recv.err.(net.Error).Timeout() {
		return
	}

	decBuffer, err := pxy.decrypt(recv.buffer[0:recv.readLen])
	if err != nil {
		glog.Warningf("decrypt request failure(%v) ignore \r\n", err)
		return
	}

	ssProtocol, err := protocol.ParseUDPReq(decBuffer, n, pxy.cryp.GetIVLen())
	if err != nil {
		glog.Warningf("parse request failure(%v) ignore \r\n", err)
		return
	}

	//check ota
	if pxy.oneTimeAuth {
		reqHeader := make([]byte, len(ssProtocol.RespHeader))
		copy(reqHeader, ssProtocol.RespHeader)
		reqHeader[0] = ssProtocol.AddrType | (protocol.AddrOneTimeAuthFlag)

		authData := append(reqHeader, ssProtocol.Data...)
		glog.V(5).Infof("read req header(%s) data:%s\r\n",
			util.DumpHex(reqHeader[:]), util.DumpHex(ssProtocol.Data[:]))

		result := ssProtocol.CheckHMAC(pxy.cryp.Key[:], authData)
		if !result {
			glog.Errorln("invalid not auth request")
			return
		}
	} else {
		glog.V(5).Infof("this client(%d) not enable auth\r\n", pxy.port)
	}

	serverAddr := &net.UDPAddr{
		IP:   ssProtocol.DstAddr.IP,
		Port: ssProtocol.DstAddr.Port,
	}

	glog.V(5).Infof("from client %s to severr %s , read Read len(%d) buffer \r\n%s",
		saddr, serverAddr.String(),
		n, util.DumpHex(ssProtocol.Data[:]))

	//check our local map for connection
	pxy.dlock()
	conn, found := pxy.ClientDict[saddr]
	if !found {
		conn = NewConnection(serverAddr, cliaddr)
		if conn == nil {
			glog.Errorf("Created new connection remote network  is unreachable\n")
			pxy.dunlock()
			return
		}
		pxy.ClientDict[saddr] = conn
		pxy.dunlock()

		glog.V(5).Infof("Created new connection for client %s\n", saddr)
		// Fire up routine to manage new connection
		go conn.RunConnection(pxy.proxyConn, pxy.cryp, ssProtocol.RespHeader, pxy.wg)
	} else {
		glog.V(5).Infof("Found connection for client %s\n", saddr)
		pxy.dunlock()
	}

	// Relay to server
	_, err = conn.ServerConn.Write(ssProtocol.Data[:])
	if err != nil {
		glog.Warningln("write buffer into remote server failure:", err)
		return
	}
	pxy.dlock()
	pxy.uploadTraffic += int64(len(ssProtocol.Data[:]))
	pxy.dunlock()
}

//RunProxy Routine to handle inputs to Proxy port
func (pxy *Proxy) RunProxy() {

	pxy.wg.Add(1)

	for {
		recvChan := make(chan receive, 1)
		go func() {
			var buffer [4096]byte
			n, cliaddr, err := pxy.proxyConn.ReadFromUDP(buffer[:])
			recvChan <- receive{n, cliaddr, err, buffer[0:n]}
		}()

		select {
		case <-pxy.quit:
			pxy.cleanup()
			return
		case recv := <-recvChan:
			pxy.handleRequest(recv)
		}
	}
}
