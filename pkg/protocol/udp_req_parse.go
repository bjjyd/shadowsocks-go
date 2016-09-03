package protocol

import (
	"shadowsocks-go/pkg/util"

	"github.com/golang/glog"
)

func ParseUDPReq(decBuffer []byte, byteLen int, ivLen int) (*SSProtocol, error) {
	ssProtocol := NewSSProcol(ivLen)

	var err error
	var tmpLen int
	var endIndex int

	parseLen := ssProtocol.ParseReqIV(decBuffer[0:ivLen])

	tmpLen, err = ssProtocol.ParseReqAddrType(decBuffer[parseLen : parseLen+ProtocolAddrTypeLen])
	if err != nil {
		return nil, err
	}

	glog.V(5).Infof("read req header(%s)\r\n",
		util.DumpHex(ssProtocol.RespHeader[:]))

	parseLen += tmpLen

	if ssProtocol.AddrType == AddrTypeDomain {
		tmpLen = ssProtocol.ParseReqDomainLen(decBuffer[parseLen : parseLen+ProtocolHostLen])
		parseLen += tmpLen
	}

	glog.V(5).Infof("read req header(%s)\r\n",
		util.DumpHex(ssProtocol.RespHeader[:]))

	endIndex = parseLen + ssProtocol.HostLen + ProtocolDstAddrPortLen
	tmpLen, err = ssProtocol.ParseReqAddrAndPort(decBuffer[parseLen:endIndex])
	if err != nil {
		return nil, err
	}
	parseLen += tmpLen

	if ssProtocol.OneTimeAuth {
		endIndex = byteLen - ProtocolHMACLen
		tmpLen = ssProtocol.ParseUDPReqData(decBuffer[parseLen:endIndex])
		parseLen += tmpLen

		ssProtocol.ParseReqHMAC(decBuffer[parseLen:])
	} else {
		endIndex = byteLen
		tmpLen = ssProtocol.ParseUDPReqData(decBuffer[parseLen:endIndex])
	}

	return ssProtocol, nil
}
