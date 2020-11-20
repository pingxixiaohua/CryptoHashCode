package utils

import "bytes"


//=============================PKCS5填充===========================。

/*
 *尾部填充
 */
func PKCS5EndPadding(data []byte, blockSize int) []byte {

	//1、计算要填充的个数
	size := blockSize - len(data)%blockSize
	//2、准备要填充的内容
	paddingText := bytes.Repeat([]byte{byte(size)}, size)
	//3、填充到data上
	return append(data,paddingText...)

}

/*
 *去除尾部填充
 */
func ClearPKCS5Padding(data []byte) []byte {

	clearSize := int(data[len(data)-1])
	return data[:len(data)-clearSize]

}


//=============================Zeros填充==========================

/*
 *尾部填充
 */

func ZeroEndPadding(data []byte, blockSize int) []byte {

	//1、计算要填充的个数
	size := blockSize - len(data)%blockSize
	//2、准备要填充的内容
	paddingText := bytes.Repeat([]byte{byte(0)}, size)
	//3、填充到data上
	return append(data, paddingText...)

}

/*
 *去除尾部填充
 */

func ClearZerosPadding(data []byte, blockSize int) []byte {

	clearSize := blockSize - len(data)%blockSize
	return data[:len(data)-clearSize]

}