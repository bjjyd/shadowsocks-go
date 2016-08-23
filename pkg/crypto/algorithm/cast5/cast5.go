package cast5

import (
	"crypto/cipher"

	"golang.org/x/crypto/cast5"
)

const (
	cast5cfbKeyLen = 16
	cast5cfbIVLen  = 8
)

//AES implementation aes encrypt and decrypt
type Cast5cfb struct {
	Name string
}

//NewAES is return a AES handler
func NewCast5cfb(typ string) (*Cast5cfb, error) {
	alg := &Cast5cfb{
		Name: typ,
	}
	return alg, nil
}

//NewStream create a new stream by key and iv
func (a *Cast5cfb) NewStream(key, iv []byte, encrypt bool) (cipher.Stream, error) {
	block, err := cast5.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if encrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	}
	return cipher.NewCFBDecrypter(block, iv), nil
}

//GetIVLen return the iv len of this method
func (a *Cast5cfb) GetIVLen() int {
	return cast5cfbIVLen
}

func (a *Cast5cfb) GetKeyLen() int {
	return cast5cfbKeyLen
}
