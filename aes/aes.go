package aes

import (
	"CryptoHashCode/utils"
	"crypto/aes"
	"crypto/cipher"
)

/*
 * 使用aes算法对数据加密
 */
func AESEncrypt(data, key []byte) ([]byte,error) {
	//Key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil,err
	}
	//Data（填充）
	originData := utils.PKCS5EndPadding(data, block.BlockSize())
	//Mode
	mode := cipher.NewCBCEncrypter(block,key[:block.BlockSize()])
	//加密
	cipherText := make([]byte, len(originData))
	mode.CryptBlocks(cipherText, originData)

	return cipherText,err
}

/**
 *使用aes算法对数据解密
 */
func AESDecrypt(data, key []byte) ([]byte,error) {

	//Key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil,err
	}
	//Mode
	mode := cipher.NewCBCDecrypter(block, key[:block.BlockSize()])
	//解密
	originText := make([]byte, len(data))
	mode.CryptBlocks(originText,data)
	//Data（去除填充）
	originText = utils.ClearPKCS5Padding(originText)

	return originText,err
}
