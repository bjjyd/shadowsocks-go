package chacha20

import (
	"crypto/cipher"

	"github.com/codahale/chacha20"
)

const (
	chacha20KeyLen = 32
	chacha20IVLen  = 8
)

//AES implementation aes encrypt and decrypt
type ChaCha20 struct {
	Name string
}

//NewAES is return a AES handler
func NewChaCha20(typ string) (*ChaCha20, error) {
	alg := &ChaCha20{
		Name: typ,
	}
	return alg, nil
}

//NewStream create a new stream by key and iv
func (a *ChaCha20) NewStream(key, iv []byte, encrypt bool) (cipher.Stream, error) {
	return chacha20.New(key, iv)
}

//GetIVLen return the iv len of this method
func (a *ChaCha20) GetIVLen() int {
	return chacha20KeyLen
}

func (a *ChaCha20) GetKeyLen() int {
	return chacha20IVLen
}
