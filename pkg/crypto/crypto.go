package crypto

import (
	"crypto/rand"
	"io"

	"shadowsocks-go/pkg/crypto/algorithm"
	"shadowsocks-go/pkg/util"
)

//Crypto use for crypto wrap
type Crypto struct {
	Key []byte
	alg algorithm.Algorithm
}

//NewCrypto create a new crypto
func NewCrypto(method, password string) (*Crypto, error) {
	cryp := &Crypto{}

	var err error
	cryp.alg, err = algorithm.CreateAlgorithm(method)
	if err != nil {
		return nil, err
	}

	cryp.Key = util.EvpBytesToKey(password, cryp.alg.GetKeyLen())

	return cryp, nil
}

//Encrypt input byte to dest
func (c *Crypto) Encrypt(dst, src []byte) ([]byte, error) {
	iv := make([]byte, c.alg.GetIVLen())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream, err := c.alg.NewStream(c.Key, iv, true)
	if err != nil {
		return nil, err
	}

	stream.XORKeyStream(dst, src)
	return iv, nil
}

//Decrypt input byte to dest
func (c *Crypto) Decrypt(iv, dst, src []byte) error {
	stream, err := c.alg.NewStream(c.Key, iv, false)
	if err != nil {
		return err
	}

	stream.XORKeyStream(dst, src)

	return nil
}

//GetIVLen Get iv len
func (c *Crypto) GetIVLen() int {
	return c.alg.GetIVLen()
}
