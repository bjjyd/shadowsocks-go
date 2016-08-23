package algorithm

import (
	"fmt"

	"shadowsocks-go/pkg/crypto/algorithm/aes"
	"shadowsocks-go/pkg/crypto/algorithm/blowfish"
	"shadowsocks-go/pkg/crypto/algorithm/cast5"
	"shadowsocks-go/pkg/crypto/algorithm/chacha20"
	"shadowsocks-go/pkg/crypto/algorithm/des"
	"shadowsocks-go/pkg/crypto/algorithm/rc4md5"
	"shadowsocks-go/pkg/crypto/algorithm/salsa20"
)

const (
	//AlgorithmTypeUnset not used any algorithm
	AlgorithmTypeUnset = ""
	//AlgorithmTypeAES128CFB for "aes-128-cfg"
	AlgorithmTypeAES128CFB = "aes-128-cfb"
	//AlgorithmTypeAES192CFB for "aes-192-cfb"
	AlgorithmTypeAES192CFB = "aes-192-cfb"
	//AlgorithmTypeAES256CFB for "aes-256-cfb"
	AlgorithmTypeAES256CFB = "aes-256-cfb"
	//AlgorithmTypeDESCFB for "des-cfb"
	AlgorithmTypeDESCFB = "des-cfb"
	//AlgorithmTypeBFCFB for "bf-cfb"
	AlgorithmTypeBFCFB = "bf-cfb"
	//AlgorithmTypeCAST5CFB for "cast5-cfb"
	AlgorithmTypeCAST5CFB = "cast5-cfb"
	//AlgorithmTypeRC4MD5 for "rc4-md5"
	AlgorithmTypeRC4MD5 = "rc4-md5"
	//AlgorithmTypeCHACHA20 for "chacha20"
	AlgorithmTypeCHACHA20 = "chacha20"
	//AlgorithmTypeSALSA20 for "salsa20"
	AlgorithmTypeSALSA20 = "salsa20"
)

//CreateAlgorithm new a algorithm inteface
func CreateAlgorithm(algType string) (Algorithm, error) {
	switch algType {
	case AlgorithmTypeUnset, AlgorithmTypeAES256CFB:
		return aes.NewAES(AlgorithmTypeAES256CFB)
	case AlgorithmTypeAES128CFB, AlgorithmTypeAES192CFB:
		return aes.NewAES(algType)
	case AlgorithmTypeDESCFB:
		return des.NewDes(algType)
	case AlgorithmTypeBFCFB:
		return blowfish.NewBFCFB(algType)
	case AlgorithmTypeCAST5CFB:
		return cast5.NewCast5cfb(algType)
	case AlgorithmTypeRC4MD5:
		return rc4md5.NewRC4MD5(algType)
	case AlgorithmTypeCHACHA20:
		return chacha20.NewChaCha20(algType)
	case AlgorithmTypeSALSA20:
		return salsa20.NewSalsa20(algType)
	default:
		return nil, fmt.Errorf("not support type %s\r\n", algType)
	}
}
