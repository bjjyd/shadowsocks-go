package util

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

const version = "2.1.3-alpha"

func PrintVersion() string {

	fmt.Println("shadowss version", version)
	return version
}

func IsFileExists(path string) (bool, error) {
	stat, err := os.Stat(path)
	if err == nil {
		if stat.Mode()&os.ModeType == 0 {
			return true, nil
		}
		return false, errors.New(path + " exists but is not regular file")
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func HmacSha1(key []byte, data []byte) []byte {
	hmacSha1 := hmac.New(sha1.New, key)
	hmacSha1.Write(data)
	return hmacSha1.Sum(nil)[:10]
}

func OtaConnectAuth(iv, key, data []byte) []byte {
	return append(data, HmacSha1(append(iv, key...), data)...)
}

func OtaReqChunkAuth(iv []byte, chunkId uint32, data []byte) []byte {
	nb := make([]byte, 2)
	binary.BigEndian.PutUint16(nb, uint16(len(data)))
	chunkIdBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(chunkIdBytes, chunkId)
	header := append(nb, HmacSha1(append(iv, chunkIdBytes...), data)...)
	return append(header, data...)
}

type ClosedFlag struct {
	flag bool
}

func (flag *ClosedFlag) SetClosed() {
	flag.flag = true
}

func (flag *ClosedFlag) IsClosed() bool {
	return flag.flag
}
