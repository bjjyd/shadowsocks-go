package ssclient

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"shadowsocks-go/pkg/crypto"
	"shadowsocks-go/pkg/protocol"
	"shadowsocks-go/pkg/util"
	bytesPool "shadowsocks-go/pkg/util/pool/bytes"

	"github.com/golang/glog"
)

type Client struct {
	net.Conn
	cryp          *crypto.Crypto //every to remote request have diff iv
	chunkId       uint32
	IV            []byte
	RequestBuffer *bytesPool.BytePool
	enableOTA     bool
}

func NewClient(c net.Conn, cipher *crypto.Crypto) *Client {
	client := &Client{
		Conn:          c,
		cryp:          cipher,
		chunkId:       0,
		RequestBuffer: bytesPool.NewBytePool(1024*5, 1024*5),
		enableOTA:     false,
	}
	return client
}

func (c *Client) Close() error {
	return c.Conn.Close()
}

func (c *Client) getAndIncrChunkId() (chunkId uint32) {
	chunkId = c.chunkId
	c.chunkId += 1
	return
}

func (c *Client) Read(b []byte) (n int, err error) {
	if c.cryp.CheckCryptoStream(false) == false {
		iv := make([]byte, c.cryp.GetIVLen())
		if _, err = io.ReadFull(c.Conn, iv); err != nil {
			return
		}
		if _, err = c.cryp.UpdataCipherStream(iv, false); err != nil {
			return
		}
		if len(c.IV) == 0 {
			c.IV = iv
		}
	}

	cipherData := make([]byte, len(b))

	n, err = c.Conn.Read(cipherData)
	if n > 0 {
		c.cryp.Decrypt(b[0:n], cipherData[0:n])
	}
	return
}

func (c *Client) Write(b []byte) (n int, err error) {
	var iv []byte
	if c.cryp.CheckCryptoStream(true) == false {
		iv, err = c.cryp.UpdataCipherStream(nil, true)
		if err != nil {
			return
		}
	}

	dataSize := len(b) + len(iv)
	cipherData := make([]byte, dataSize)

	if iv != nil {
		copy(cipherData, iv)
	}

	c.cryp.Encrypt(cipherData[len(iv):], b)
	n, err = c.Conn.Write(cipherData)
	return
}

func (c *Client) parseTCPBuffer(ssProtocol *protocol.SSProtocol, stage, expectedLen int) error {

	readLen := expectedLen
	readBuf := make([]byte, readLen)

	if _, err := io.ReadFull(c, readBuf[0:readLen]); err != nil {
		glog.Errorln("read err : ", err)
		return err
	}

	glog.V(5).Infof("read data\r\n%s\r\n",
		util.DumpHex(readBuf[0:readLen]))

	var err error
	switch stage {
	case protocol.ParseStageAddrType:
		_, err = ssProtocol.ParseReqAddrType(readBuf[0:readLen])
	case protocol.ParseStageDomainLen:
		ssProtocol.ParseReqDomainLen(readBuf[0:readLen])
	case protocol.ParseStageAddrAnddPort:
		_, err = ssProtocol.ParseReqAddrAndPort(readBuf[0:readLen])
	case protocol.ParseStageHMAC:
		ssProtocol.ParseReqHMAC(readBuf[0:readLen])
	}

	return err
}

func (c *Client) ParseTcpReq() (*protocol.SSProtocol, error) {

	ivLen := c.cryp.GetIVLen()
	ssProtocol := protocol.NewSSProcol(ivLen)

	err := c.parseTCPBuffer(ssProtocol, protocol.ParseStageAddrType, protocol.ProtocolAddrTypeLen)
	if err != nil {
		glog.Errorf("parse request addr type error %v\r\n", err)
		return nil, err
	}
	glog.V(5).Infof("read addr type %v\r\n",
		ssProtocol.AddrType)

	if ssProtocol.AddrType == protocol.AddrTypeDomain {
		err = c.parseTCPBuffer(ssProtocol, protocol.ParseStageDomainLen, protocol.ProtocolHostLen)
		if err != nil {
			glog.Errorf("parse request domain len  error %v\r\n", err)
			return nil, err
		}
		glog.V(5).Infof("read domain len\r\n%v\r\n",
			ssProtocol.HostLen)
	}

	err = c.parseTCPBuffer(ssProtocol, protocol.ParseStageAddrAnddPort, ssProtocol.HostLen+protocol.ProtocolDstAddrPortLen)
	if err != nil {
		glog.Errorf("parse request addr and port error %v\r\n", err)
		return nil, err
	}
	glog.V(5).Infof("read domain and port %v:%v\r\n",
		ssProtocol.DstAddr.IP.String(), ssProtocol.DstAddr.Port)

	if ssProtocol.OneTimeAuth {
		c.enableOTA = true
		err = c.parseTCPBuffer(ssProtocol, protocol.ParseStageHMAC, protocol.ProtocolHMACLen)
		if err != nil {
			glog.Errorf("parse request hmac error %v\r\n", err)
			return nil, err
		}
		glog.V(5).Infof("read hmac %v\r\n", util.DumpHex(ssProtocol.HMAC[:]))
	}

	return ssProtocol, nil
}

func (c *Client) ParseReqData(buf []byte) ([]byte, error) {
	const (
		dataLenLen  = 2
		hmacSha1Len = 10
	)

	bufLen := len(buf)
	headerLen := 0
	dataEndIdx := 0

	if c.enableOTA {
		idxData0 := dataLenLen + hmacSha1Len
		headerLen = dataLenLen + hmacSha1Len

		if bufLen < headerLen {
			buf = make([]byte, headerLen)
		}

		if _, err := io.ReadFull(c, buf[:headerLen]); err != nil {
			return nil, err
		}
		dataLen := binary.BigEndian.Uint16(buf[:dataLenLen])
		expectedHmacSha1 := buf[dataLenLen:idxData0]

		dataEndIdx = int(dataLen) + headerLen
		if bufLen < dataEndIdx {
			buf = make([]byte, int(dataLen)+headerLen)
		}


		if _, err := io.ReadFull(c, buf[headerLen:dataEndIdx]); err != nil {
			return nil, err
		}
		chunkIdBytes := make([]byte, 4)
		chunkId := c.getAndIncrChunkId()
		binary.BigEndian.PutUint32(chunkIdBytes, chunkId)
		actualHmacSha1 := util.HmacSha1(append(c.IV, chunkIdBytes...), buf[headerLen:dataEndIdx])
		if !bytes.Equal(expectedHmacSha1, actualHmacSha1) {
			return nil, fmt.Errorf("Not auth data")
		}
	} else {
		n, err := c.Read(buf[:])
		if err != nil {
			return nil, err
		}
		headerLen = 0
		dataEndIdx = n
	}

	return buf[headerLen:dataEndIdx], nil
}
