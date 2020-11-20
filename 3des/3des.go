package _des

import (
	"CryptoHashCode/utils"
	"crypto/cipher"
	"crypto/des"
)

/**
 *	使用3des进行加密
 */
func TripleDesEncrypt(data, key []byte) ([]byte, error) {

	//Key
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	//Data
	originText := utils.PKCS5EndPadding(data, block.BlockSize())
	//Mode
	mode := cipher.NewCBCEncrypter(block, key[:block.BlockSize()])
	//加密
	cipherText := make([]byte, len(originText))
	mode.CryptBlocks(cipherText, originText)

	return cipherText, nil

}

/**
 *	使用3des进行解密
 */
func TripleDesDecrypt(data, key []byte) ([]byte, error) {

	//Key
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	//Mode
	mode := cipher.NewCBCDecrypter(block, key[:block.BlockSize()])
	//解密
	originText := make([]byte, len(data))
	mode.CryptBlocks(originText, data)
	//Data(去除填充)
	originText = utils.ClearPKCS5Padding(originText)

	return originText,nil
}