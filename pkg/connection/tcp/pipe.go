package tcp

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"time"

	connection "shadowsocks-go/pkg/connection/tcp/unmaintained"
	"shadowsocks-go/pkg/util"

	"github.com/golang/glog"
)

func SetReadTimeout(c net.Conn, timeout time.Duration) {
	if timeout != 0 {
		c.SetReadDeadline(time.Now().Add(timeout))
	}
}

// PipeThenClose copies data from src to dst, closes dst when done.
func (tcpSrv *TCPServer) PipeThenClose(src, dst net.Conn, timeout time.Duration, inDirect bool) {
	defer dst.Close()
	buf := make([]byte, 4108)

	for {
		SetReadTimeout(src, timeout)
		n, err := src.Read(buf)
		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			// Note: avoid overwrite err returned by Read.
			if _, err := dst.Write(buf[0:n]); err != nil {
				glog.Errorf("write err:%v", err)
				break
			}
			if inDirect {
				tcpSrv.UploadTraffic += int64(n)
			} else {
				tcpSrv.DownloadTraffic += int64(n)
			}
		}
		if err != nil {
			break
		}
	}
}

// PipeThenClose copies data from src to dst, closes dst when done, with ota verification.
func (tcpSrv *TCPServer) handleRequest(src *connection.Conn, dst net.Conn, timeout time.Duration) {
	const (
		dataLenLen  = 2
		hmacSha1Len = 10
		idxData0    = dataLenLen + hmacSha1Len
	)

	defer func() {
		dst.Close()
	}()
	// sometimes it have to fill large block
	buf := make([]byte, 4108)
	i := 0
	for {
		i += 1
		SetReadTimeout(src, timeout)
		if n, err := io.ReadFull(src, buf[:dataLenLen+hmacSha1Len]); err != nil {
			if err == io.EOF {
				break
			}
			glog.Errorf("conn=%p #%v read header error n=%v: %v", src, i, n, err)
			break
		}
		dataLen := binary.BigEndian.Uint16(buf[:dataLenLen])
		expectedHmacSha1 := buf[dataLenLen:idxData0]

		var dataBuf []byte
		if len(buf) < int(idxData0+dataLen) {
			dataBuf = make([]byte, dataLen)
		} else {
			dataBuf = buf[idxData0 : idxData0+dataLen]
		}
		if n, err := io.ReadFull(src, dataBuf); err != nil {
			if err == io.EOF {
				break
			}
			glog.V(5).Infof("conn=%p #%v read data error n=%v: %v", src, i, n, err)
			break
		}
		chunkIdBytes := make([]byte, 4)
		chunkId := src.GetAndIncrChunkId()
		binary.BigEndian.PutUint32(chunkIdBytes, chunkId)
		actualHmacSha1 := util.HmacSha1(append(src.GetIv(), chunkIdBytes...), dataBuf)
		if !bytes.Equal(expectedHmacSha1, actualHmacSha1) {
			glog.V(5).Infof("conn=%p #%v read data hmac-sha1 mismatch, iv=%v chunkId=%v src=%v dst=%v len=%v expeced=%v actual=%v", src, i, src.GetIv(), chunkId, src.RemoteAddr(), dst.RemoteAddr(), dataLen, expectedHmacSha1, actualHmacSha1)
			break
		}
		var writeLen int
		var err error
		if writeLen, err = dst.Write(dataBuf); err != nil {
			glog.V(5).Infof("conn=%p #%v write data error n=%v: %v", dst, i, writeLen, err)
			break
		}
		tcpSrv.UploadTraffic += int64(writeLen)
	}
}
