package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"shadowsocks-go/pkg/crypto/algorithm"
	cryptoutil "shadowsocks-go/pkg/util/crypto"
)

//Crypto use for crypto wrap
type Crypto struct {
	Key       []byte
	alg       algorithm.Algorithm
	decStream cipher.Stream
	encStream cipher.Stream
}

//NewCrypto create a new crypto
func NewCrypto(method, password string) (*Crypto, error) {
	cryp := &Crypto{}

	var err error
	cryp.alg, err = algorithm.CreateAlgorithm(method)
	if err != nil {
		return nil, err
	}

	cryp.Key = cryptoutil.EvpBytesToKey(password, cryp.alg.GetKeyLen())

	return cryp, nil
}

//Encrypt input byte to dest
func (c *Crypto) Encrypt(dst, src []byte) error {

	if c.encStream == nil {
		return fmt.Errorf("cant allocate stream by nil iv")
	}

	c.encStream.XORKeyStream(dst, src)
	return nil
}

//Decrypt input byte to dest
//if iv not nil will force update stream
func (c *Crypto) Decrypt(dst, src []byte) error {
	if c.decStream == nil {
		return fmt.Errorf("cant allocate stream by nil iv")
	}

	c.decStream.XORKeyStream(dst, src)

	return nil
}

func (c *Crypto) UpdataCipherStream(iv []byte, encrypt bool) ([]byte, error) {

	if encrypt {
		if iv == nil {
			iv = make([]byte, c.alg.GetIVLen())
			if _, err := io.ReadFull(rand.Reader, iv); err != nil {
				return nil, err
			}
		}

		stream, err := c.alg.NewStream(c.Key, iv, true)
		if err != nil {
			return nil, err
		}
		c.encStream = stream
	} else {
		if iv == nil {
			return nil, fmt.Errorf("cant allocate stream by nil iv")
		} else {
			stream, err := c.alg.NewStream(c.Key, iv, false)
			if err != nil {
				return nil, err
			}
			c.decStream = stream
		}
	}

	return iv, nil
}

//GetIVLen Get iv len
func (c *Crypto) CheckCryptoStream(encrypt bool) bool {
	if encrypt {
		if c.encStream == nil {
			return false
		}
	} else {
		if c.decStream == nil {
			return false
		}
	}
	return true
}

//GetIVLen Get iv len
func (c *Crypto) GetIVLen() int {
	return c.alg.GetIVLen()
}
