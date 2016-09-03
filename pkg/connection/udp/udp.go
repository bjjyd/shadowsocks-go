package udp

import (
	"net"
	"sync"

	"shadowsocks-go/pkg/crypto"

	"github.com/golang/glog"
)

//Connection implement for every conection
type Connection struct {
	ClientAddr      *net.UDPAddr // Address of the client
	ServerConn      *net.UDPConn // UDP connection to server
	Quit            chan struct{}
	DownloadTraffic int64 //download traffic
	Dmutex          *sync.Mutex
}

//NewConnection Generate a new connection by opening a UDP connection to the server
func NewConnection(srvAddr, cliAddr *net.UDPAddr) *Connection {
	conn := new(Connection)
	conn.ClientAddr = cliAddr
	srvudp, err := net.DialUDP("udp", nil, srvAddr)
	if err != nil {
		glog.Errorf("Dial to remote server %s err:%v\r\n", srvAddr.String(), err)
		return nil
	}

	conn.ServerConn = srvudp
	conn.Quit = make(chan struct{})
	conn.Dmutex = new(sync.Mutex)
	return conn
}

//RunConnection Go routine which manages connection from server to single client
func (conn *Connection) RunConnection(write *net.UDPConn, crypto *crypto.Crypto, respHeader []byte, wg sync.WaitGroup) {
	wg.Add(1)
	for {
		// Read from server
		type receive struct {
			readLen int
			err     error
			buffer  []byte
		}

		recvChan := make(chan receive, 1)
		go func() {
			buffer := make([]byte, 2048)
			n, err := conn.ServerConn.Read(buffer[0:])
			recvChan <- receive{n, err, buffer[0:n]}
		}()

		select {
		case <-conn.Quit:
			glog.Infof("quit remote Connection %v->%v \r\n", conn.ClientAddr.String(), conn.ServerConn.RemoteAddr().String())
			conn.ServerConn.Close()
			wg.Done()
			return
		case recv := <-recvChan:
			if recv.err != nil {
				glog.Errorf("read %s->%s failure %v \r\n", conn.ClientAddr.String(), conn.ServerConn.RemoteAddr().String(), recv.err)
				continue
			}

			buffer := recv.buffer
			n := recv.readLen

			// Relay it to client
			respHeaderLen := len(respHeader)
			resp := make([]byte, n+respHeaderLen)
			copy(resp[:], respHeader)
			copy(resp[respHeaderLen:], buffer[0:n])
			encBuff, err := AssembleResp(resp[:], n+respHeaderLen, crypto)
			_, err = write.WriteToUDP(encBuff[:], conn.ClientAddr)
			if err != nil {
				glog.Errorf("write local->%s failure %v \r\n", conn.ClientAddr.String(), err)
			}
			conn.Dmutex.Lock()
			conn.DownloadTraffic += int64(len(encBuff[:]))
			conn.Dmutex.Unlock()
		}
	}
}
