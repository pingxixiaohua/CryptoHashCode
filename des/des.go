package des

import (
	"CryptoHashCode/utils"
	"crypto/cipher"
	"crypto/des"
)

/**
 *	使用des进行加密
 */
func DESEnCrypt(data []byte, key []byte) ([]byte, error) {

	//Key
	block, err := des.NewCipher(key)
	if err != nil {
		return nil,err
	}
	//Data
	originText := utils.PKCS5EndPadding(data, block.BlockSize())
	//Mode
	mode := cipher.NewCBCEncrypter(block, key)
	//加密
	cipherText := make([]byte, len(originText))
	mode.CryptBlocks(cipherText, originText)

	return cipherText, nil
}

/**
 *	使用des进行解密
 */
func DESDeCrypt(data []byte, key []byte) ([]byte, error) {

	//Key
	block, err := des.NewCipher(key)
	if err != nil {
		return nil,err
	}
	//Mode
	mode := cipher.NewCBCDecrypter(block,key)
	//解密
	originText := make([]byte, len(data))
	mode.CryptBlocks(originText, data)
	//Data(去除填充)
	originText = utils.ClearPKCS5Padding(originText)

	return originText, nil
}