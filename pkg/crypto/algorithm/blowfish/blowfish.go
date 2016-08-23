package blowfish

import (
	"crypto/cipher"

	"golang.org/x/crypto/blowfish"
)

const (
	bfKeyLen = 16
	bfIVLen  = 8
)

//AES implementation aes encrypt and decrypt
type BFCFB struct {
	Name string
}

//NewAES is return a AES handler
func NewBFCFB(typ string) (*BFCFB, error) {
	alg := &BFCFB{
		Name: typ,
	}
	return alg, nil
}

//NewStream create a new stream by key and iv
func (a *BFCFB) NewStream(key, iv []byte, encrypt bool) (cipher.Stream, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if encrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	}
	return cipher.NewCFBDecrypter(block, iv), nil
}

//GetIVLen return the iv len of this method
func (a *BFCFB) GetIVLen() int {
	return bfIVLen
}

func (a *BFCFB) GetKeyLen() int {
	return bfKeyLen
}
