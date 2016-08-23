package des

import (
	"crypto/cipher"
	"crypto/des"
)

const (
	desKeyLen = 8
	desIVLen  = 8
)

//AES implementation aes encrypt and decrypt
type Des struct {
	Name string
}

//NewAES is return a AES handler
func NewDes(typ string) (*Des, error) {
	alg := &Des{
		Name: typ,
	}
	return alg, nil
}

//NewStream create a new stream by key and iv
func (a *Des) NewStream(key, iv []byte, encrypt bool) (cipher.Stream, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if encrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	}
	return cipher.NewCFBDecrypter(block, iv), nil
}

//GetIVLen return the iv len of this method
func (a *Des) GetIVLen() int {
	return desIVLen
}

func (a *Des) GetKeyLen() int {
	return desKeyLen
}
