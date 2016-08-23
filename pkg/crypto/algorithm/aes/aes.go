package aes

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/golang/glog"
)

type aesInfo struct {
	keyLen int
	ivLen  int
}

var info = map[string]aesInfo{
	"aes-128-cfb": aesInfo{keyLen: 16, ivLen: 16},
	"aes-192-cfb": aesInfo{keyLen: 24, ivLen: 16},
	"aes-256-cfb": aesInfo{keyLen: 32, ivLen: 16},
}

//AES implementation aes encrypt and decrypt
type AES struct {
	Name string
}

//NewAES is return a AES handler
func NewAES(aesType string) (*AES, error) {
	alg := &AES{
		Name: aesType,
	}
	return alg, nil
}

//NewStream create a new stream by key and iv
func (a *AES) NewStream(key, iv []byte, encrypt bool) (cipher.Stream, error) {
	glog.V(5).Infoln("New Aes Stream")
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if encrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	}
	return cipher.NewCFBDecrypter(block, iv), nil
}

//GetIVLen return the iv len of this method
func (a *AES) GetIVLen() int {
	v, ok := info[a.Name]
	if !ok {
		return 0
	}

	return v.ivLen
}

func (a *AES) GetKeyLen() int {
	v, ok := info[a.Name]
	if !ok {
		return 0
	}

	return v.keyLen
}
