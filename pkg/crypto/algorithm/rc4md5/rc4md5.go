package rc4md5

import (
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"

	"github.com/golang/glog"
)

const (
	rc4MD5KeyLen = 16
	rc4MD5IVLen  = 16
)

//AES implementation aes encrypt and decrypt
type RC4MD5 struct {
	Name string
}

//NewAES is return a AES handler
func NewRC4MD5(typ string) (*RC4MD5, error) {
	alg := &RC4MD5{
		Name: typ,
	}
	return alg, nil
}

//NewStream create a new stream by key and iv
func (a *RC4MD5) NewStream(key, iv []byte, _ bool) (cipher.Stream, error) {
	glog.V(5).Infoln("New Aes Stream")
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	rc4key := h.Sum(nil)

	return rc4.NewCipher(rc4key)
}

//GetIVLen return the iv len of this method
func (a *RC4MD5) GetIVLen() int {
	return rc4MD5IVLen
}

func (a *RC4MD5) GetKeyLen() int {
	return rc4MD5KeyLen
}
