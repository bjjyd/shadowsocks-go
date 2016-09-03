package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	"shadowsocks-go/pkg/util"

	"github.com/golang/glog"
)

const (
	ProtocolAddrTypeLen    = 1
	ProtocolDstAddrIPv4Len = net.IPv4len
	ProtocolDstAddrIPv6Len = net.IPv6len
	ProtocolDstAddrPortLen = 2
	ProtocolHostLen        = 1
	ProtocolHMACLen        = 10
)

const (
	addrTypeIPv4   = 1
	AddrTypeDomain = 3
	addrTypeIPv6   = 4
)

const (
	AddrOneTimeAuthFlag = 0x10
	addrTypeFlag        = 0x0F
)

const (
	ParseStageIV = iota
	ParseStageAddrType
	ParseStageAddrAnddPort
	ParseStageUDPData
	ParseStageHMAC
	ParseStageDomainLen
)

//DstAddr description dest ip addr
type DstAddr struct {
	IP   net.IP
	Port int
}

//SSProtocol implement ss package
type SSProtocol struct {
	RespHeader  []byte
	IV          []byte
	AddrType    byte
	OneTimeAuth bool
	HostLen     int
	DstAddr     DstAddr
	Data        []byte
	HMAC        [10]byte
	ParseStage  int
}

func NewSSProcol(ivLen int) *SSProtocol {
	return &SSProtocol{
		RespHeader: make([]byte, 0, 32),
		IV:         make([]byte, ivLen),
		ParseStage: ParseStageIV,
	}
}

func (ssProtocol *SSProtocol) ParseReqIV(decBuffer []byte) int {
	copy(ssProtocol.IV, decBuffer[0:len(ssProtocol.IV)])

	return len(ssProtocol.IV)
}

func (ssProtocol *SSProtocol) ParseReqAddrType(decBuffer []byte) (int, error) {

	addr := decBuffer[0]
	ssProtocol.AddrType = addr & addrTypeFlag
	ssProtocol.OneTimeAuth = 0x10 == (addr & AddrOneTimeAuthFlag)

	ssProtocol.RespHeader = append(ssProtocol.RespHeader, addr)
	ssProtocol.RespHeader[0] = ssProtocol.AddrType

	var err error

	switch ssProtocol.AddrType {
	case addrTypeIPv4:
		ssProtocol.HostLen = ProtocolDstAddrIPv4Len
	case addrTypeIPv6:
		ssProtocol.HostLen = ProtocolDstAddrIPv6Len
	case AddrTypeDomain:
		ssProtocol.HostLen = 0
	default:
		err = fmt.Errorf("addr type %v not supported\r\n", ssProtocol.AddrType)
	}

	return ProtocolAddrTypeLen, err
}

func (ssProtocol *SSProtocol) ParseReqDomainLen(decBuffer []byte) int {

	hostlen := decBuffer[0]
	glog.V(5).Infof("host len %v \r\n", hostlen)
	ssProtocol.HostLen = int(hostlen)
	glog.V(5).Infof("host len %v\r\n", ssProtocol.HostLen)

	ssProtocol.RespHeader = append(ssProtocol.RespHeader, decBuffer[0])

	return ProtocolHostLen
}

func (ssProtocol *SSProtocol) ParseReqAddrAndPort(decBuffer []byte) (int, error) {
	ssProtocol.RespHeader = append(ssProtocol.RespHeader, decBuffer...)

	switch ssProtocol.AddrType {
	case addrTypeIPv4, addrTypeIPv6:
		ssProtocol.DstAddr.IP = net.IP(decBuffer[:ssProtocol.HostLen])
	case AddrTypeDomain:
		domainEndIdx := ssProtocol.HostLen
		domain := string(decBuffer[:domainEndIdx])

		dIP, err := net.ResolveIPAddr("ip", domain)
		if err != nil {
			return 0, fmt.Errorf("[udp]failed to resolve domain name: %s\n", domain)
		}
		ssProtocol.DstAddr.IP = dIP.IP

	default:
		return 0, fmt.Errorf("[udp]addr type %v not supported\r\n", ssProtocol.AddrType)
	}

	parseLen := ssProtocol.HostLen
	ssProtocol.DstAddr.Port = int(binary.BigEndian.Uint16(decBuffer[parseLen : parseLen+ProtocolDstAddrPortLen]))
	parseLen += ProtocolDstAddrPortLen

	return parseLen, nil
}

func (ssProtocol *SSProtocol) ParseReqHMAC(decBuffer []byte) int {
	copy(ssProtocol.HMAC[:], decBuffer[:ProtocolHMACLen])

	return ProtocolHMACLen
}

func (ssProtocol *SSProtocol) ParseUDPReqData(decBuffer []byte) int {
	buffLen := len(decBuffer)

	ssProtocol.Data = make([]byte, buffLen)
	copy(ssProtocol.Data, decBuffer[:buffLen])

	return buffLen
}

// //Parse ss packet into SSProtocol
// func Parse(decBuffer []byte, byteLen, ivLen int) (*SSProtocol, error) {
//
// 	ssProtocol := new(SSProtocol)
//
// 	ssProtocol.ParseReqIV(decBuffer, ivLen)
// 	for index := byteLen; index > 0; index++ {
//
// 	}
//
// 	parseLen := 0 + ivLen
// 	ssProtocol.ParseReqIV(decBuffer, byteLen, ivLen)
//
// 	parseLen++
//
// 	glog.V(5).Infof("Got decrypt plain text data buffer \r\n%s \r\n", util.DumpHex(decBuffer[ivLen:]))
//
// 	glog.V(5).Infof("Got AddrType:%d  one time auth:%t\r\n", ssProtocol.AddrType, ssProtocol.OneTimeAuth)
//
// 	switch ssProtocol.AddrType {
// 	case addrTypeIPv4:
// 		ssProtocol.DstAddr.IP = net.IP(decBuffer[parseLen : parseLen+protocaldstAddrIPv4Len])
// 		parseLen += dstAddrIPv4Len
// 	case addrTypeIPv6:
// 		ssProtocol.DstAddr.IP = net.IP(decBuffer[parseLen : parseLen+protocaldstAddrIPv6Len])
// 		parseLen += dstAddrIPv6Len
// 	case addrTypeDomain:
// 		hostlen := decBuffer[parseLen]
// 		parseLen += protolcolHostLen
//
// 		ssProtocol.HostLen, _ = strconv.Atoi(string(hostlen))
//
// 		domainEndIdx := ssProtocol.HostLen + parseLen
// 		domain := string(decBuffer[parseLen:domainEndIdx])
// 		parseLen += ssProtocol.HostLen
//
// 		dIP, err := net.ResolveIPAddr("ip", domain)
// 		if err != nil {
// 			return nil, fmt.Errorf("[udp]failed to resolve domain name: %s\n", domain)
// 		}
// 		ssProtocol.DstAddr.IP = dIP.IP
// 	default:
// 		return nil, fmt.Errorf("[udp]addr type %v not supported\r\n", ssProtocol.AddrType)
// 	}
//
// 	ssProtocol.DstAddr.Port = int(binary.BigEndian.Uint16(decBuffer[parseLen : parseLen+protocaldstAddrPortLen]))
// 	parseLen += dstAddrPortLen
//
// 	ssProtocol.RespHeader = make([]byte, parseLen-ivLen)
// 	copy(ssProtocol.RespHeader, decBuffer[ivLen:parseLen])
// 	//need to fix resp header
// 	ssProtocol.RespHeader[0] = ssProtocol.AddrType
//
// 	dataBufferLen := 0
// 	if ssProtocol.OneTimeAuth {
// 		dataBufferLen = byteLen - parseLen - protocalHMACLen
//
// 		copy(ssProtocol.HMAC[:], decBuffer[parseLen+dataBufferLen:])
//
// 		glog.V(5).Infof("Got decrypt HMAC buffer \r\n%s \r\n", util.DumpHex(ssProtocol.HMAC[:]))
// 	} else {
// 		dataBufferLen = byteLen - parseLen
// 	}
// 	dataBufferEndIdex := dataBufferLen + parseLen
// 	ssProtocol.Data = make([]byte, dataBufferLen)
// 	copy(ssProtocol.Data, decBuffer[parseLen:dataBufferEndIdex])
//
// 	glog.V(5).Infof("Got decrypt data buffer \r\n%s \r\n", util.DumpHex(ssProtocol.Data[:]))
// 	return ssProtocol, nil
// }

func (ssProtocol *SSProtocol) CheckHMAC(key []byte, authData []byte) bool {
	if ssProtocol.OneTimeAuth {
		authKey := append(ssProtocol.IV, key...)

		glog.V(5).Infof("request auth data: \r\n %s \r\n  authKey:\r\n %s \r\n", util.DumpHex(authData), util.DumpHex(authKey))

		hmac := util.HmacSha1(authKey, authData)
		if !bytes.Equal(ssProtocol.HMAC[:], hmac) {
			glog.Errorf("Unauthorized request\r\n")
			return false
		}
	} else {
		glog.Warningf("invalid request with auth \r\n")
		return false
	}

	return true
}
