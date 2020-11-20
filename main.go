package main

import (
	_des "CryptoHashCode/3des"
	"CryptoHashCode/aes"
	"CryptoHashCode/des"
	"CryptoHashCode/ecc"
	"CryptoHashCode/rsa"
	"fmt"
)

func main() {

fmt.Println("============================DEA算法===========================")

	key1 := []byte("12345678")
	data1 := "天若有情天亦老，人间正道是沧桑."
	fmt.Println("明文:",data1)
	//加密
	cipherText1, err := des.DESEnCrypt([]byte(data1), key1)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("DES算法加密后的内容:", string(cipherText1))
	//解密
	originText1, err := des.DESDeCrypt(cipherText1, key1)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("DES算法解密后的内容:",string(originText1))


fmt.Println("============================3DES算法==========================")
	key2 := []byte("123456781234567812345678")
	data2 := "生当作人杰，死亦为鬼雄."
	fmt.Println("明文",data2)
	//加密
	cipherText2, err := _des.TripleDesEncrypt([]byte(data2),key2)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("3DES算法加密后的内容:", string(cipherText2))
	//解密
	originText2, err := _des.TripleDesDecrypt(cipherText2, key2)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("3DES算法解密后的内容:",string(originText2))


fmt.Println("============================AES算法===========================")

	key3 := []byte("1234567812345678")
	data3 := "世间安得双全法，不负如来不负卿."
	fmt.Println("明文:",data3)
	//加密
	cipherText3, err := aes.AESEncrypt([]byte(data3), key3)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("AES算法加密后的内容:", string(cipherText3))
	//解密
	originText3, err := aes.AESDecrypt(cipherText3, key3)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("AES算法解密后的内容:",string(originText3))


fmt.Printf("\n\n")
fmt.Println("===========================RSA算法============================")

	data4 := "天长地久有时尽，此恨绵绵无绝期."
	fmt.Println("明文:",data4)

	//pri, err := rsa.CreateRSAkey()
	//if err != nil {
	//	fmt.Println("密钥生成失败:", err.Error())
	//	return
	//}

	//将私钥保存到证书文件
	//err = rsa.GeneratePriPem(pri)
	//if err != nil {
	//	fmt.Println("私钥证书生成失败")
	//	return
	//}
	//
	//err = rsa.GeneratePubPem(pri.PublicKey)
	//if err != nil {
	//	fmt.Println("公钥证书生成失败")
	//	return
	//}
	pri, err := rsa.GenerateKeysPem("lx")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("===============公钥加密，私钥解密==============")
	//公钥加密
	cipherText4, err := rsa.RSAEncrypt(pri.PublicKey,[]byte(data4))
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("rsa算法公钥加密内容:",string(cipherText4))
	//私钥解密
	originText4, err := rsa.RSADecrypt(pri, cipherText4)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("rsa算法私钥解密内容:",string(originText4))


	fmt.Println("================私钥签名，公钥验签=============")
	//私钥签名
	signText4, err := rsa.RSASign(pri, []byte(data4))
	if err != nil {
		fmt.Println("rsa算法签名失败：", err.Error())
		return
	}
	//公钥验签
	verifyResult, err := rsa.RSAVerify(pri.PublicKey, []byte(data4), signText4)
	if err != nil {
		fmt.Println("rsa签名验证失败:", err.Error())
	}
	if verifyResult {
		fmt.Println("rsa签名验证成功!")
	} else {
		fmt.Println("rsa签名验证失败!")
	}

fmt.Println("==============================ECC算法===============================")

	data5 := "我自横刀向天笑，去留肝胆两昆仑."

	priKey, err := ecc.GenerateKey()
	if err != nil {
		fmt.Println("ecdsa生成秘钥错误:",err.Error())
		return
	}

	r, s, err := ecc.ECDSASign(priKey, []byte(data5))
	if err != nil {
		fmt.Println("签名错误:",err.Error())
		return
	}

	verifyResult2 := ecc.ECDSAVerify(priKey.PublicKey, []byte(data5), r, s)
	if verifyResult2 {
		fmt.Println("验证成功")
	}else {
		fmt.Println("验证错误")
	}

}
