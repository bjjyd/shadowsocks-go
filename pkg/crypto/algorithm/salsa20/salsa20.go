package salsa20

import (
	"crypto/cipher"
	"encoding/binary"

	"golang.org/x/crypto/salsa20/salsa"
)

const (
	salsa20KeyLen = 32
	salsa20IVLen  = 8
)

//AES implementation aes encrypt and decrypt
type Salsa20 struct {
	Name    string
	nonce   [8]byte
	key     [32]byte
	counter int
}

//NewAES is return a AES handler
func NewSalsa20(typ string) (*Salsa20, error) {
	alg := &Salsa20{
		Name: typ,
	}
	return alg, nil
}

//NewStream create a new stream by key and iv
func (c *Salsa20) NewStream(key, iv []byte, encrypt bool) (cipher.Stream, error) {
	copy(c.nonce[:], iv[:8])
	copy(c.key[:], key[:32])
	return c, nil
}

func (c *Salsa20) XORKeyStream(dst, src []byte) {
	var buf []byte
	padLen := c.counter % 64
	dataSize := len(src) + padLen
	if cap(dst) >= dataSize {
		buf = dst[:dataSize]
	} else {
		buf = make([]byte, dataSize)
	}

	var subNonce [16]byte
	copy(subNonce[:], c.nonce[:])
	binary.LittleEndian.PutUint64(subNonce[len(c.nonce):], uint64(c.counter/64))

	// It's difficult to avoid data copy here. src or dst maybe slice from
	// Conn.Read/Write, which can't have padding.
	copy(buf[padLen:], src[:])
	salsa.XORKeyStream(buf, buf, &subNonce, &c.key)
	copy(dst, buf[padLen:])

	c.counter += len(src)
}

//GetIVLen return the iv len of this method
func (a *Salsa20) GetIVLen() int {
	return salsa20KeyLen
}

func (a *Salsa20) GetKeyLen() int {
	return salsa20IVLen
}
