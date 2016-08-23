package algorithm

import "crypto/cipher"

//Algorithm for encrypt interface
type Algorithm interface {
	GetIVLen() int
	GetKeyLen() int
	NewStream(key, iv []byte, encrypt bool) (cipher.Stream, error)
}
