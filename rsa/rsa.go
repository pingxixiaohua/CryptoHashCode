package rsa

import (
	"CryptoHashCode/utils"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"os"
)

const RSA_PRIVATE_KEY  = "RSA PRIVATE KEY"
const RSA_PUBLIC_KEY  = "RSA PUBLIC KEY"
/*
 *	生成一对RSA密钥对，并返回密钥数据
 */
func CreateRSAkey() (*rsa.PrivateKey, error)  {
	//
	var bits int
	flag.IntVar(&bits,"b",2048,"rsa密钥长度")

	//私钥
	privatekey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	//公钥
	//publickey := privatekey.PublicKey

	return privatekey,nil
}

/*
 * 生成一对密钥，并以pem文件格式进行保存，即生成两个证书
 */
func GenerateKeysPem(file_name string) (*rsa.PrivateKey,error) {
	//1、生成私钥
	pri, err := CreateRSAkey()
	if err != nil {
		return nil,err
	}

	//2、生成私钥证书
	err = generatePriPem(pri, file_name)
	if err != nil {
		return nil,err
	}
	//3、生成公钥证书
	err = generatePubPem(pri.PublicKey, file_name)
	if err != nil {
		return nil,err
	}
	return pri,nil
}

//=====================从证书文件中读取私钥数据和公钥数据，到内存中==================
/*
 * 从证书文件中读取私钥数据到内存当中
 */
func ReadPriPem(file string) (*rsa.PrivateKey, error) {
	blockBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(blockBytes)
	//block.Bytes私钥
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

/*
 * 从证书文件中读取公钥数据到内存中
 */
func ReadPubPem(file string) (*rsa.PublicKey, error) {
	blockBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(blockBytes)

	return x509.ParsePKCS1PublicKey(block.Bytes)
}

//====================保存私钥和公钥数据到文件中,进行持久化存储==================

/*
 *	根据私钥生成一个私钥证书文件
 */
func generatePriPem(pri *rsa.PrivateKey, file_name string) (error) {
	//1.对私钥进行序列化
	priBytes := x509.MarshalPKCS1PrivateKey(pri)
	//2.新建文件
	file, err := os.Create("rsa_pri_"+file_name+".pem")
	if err != nil {
		return err
	}
	//3.block     PEM编码格式
	block := pem.Block{
		Type:    RSA_PRIVATE_KEY,
		Bytes:   priBytes,
	}
	//4.写入
	return pem.Encode(file,&block)
}

/*
 *生成一个公钥证书文件
 */
func generatePubPem(pub rsa.PublicKey, file_name string) (error) {
	pubBytes := x509.MarshalPKCS1PublicKey(&pub)
	file, err := os.Create("rsa_pub_"+file_name+".pem")
	if err != nil {
		return err
	}
	block := pem.Block{
		Type:    RSA_PUBLIC_KEY,
		Bytes:   pubBytes,
	}
	return  pem.Encode(file,&block)
}



//==========================公钥加密，私钥解密===========================

	//数据加密
func RSAEncrypt(pub rsa.PublicKey, data []byte) ([]byte, error) {
	/*
	 *	对数据data进行加密，并返回加密后的密文
	 *	运用EncryptPKCS1v15包
	 *	EncryptPKCS1v15(rand io.Reader, pub *PublicKey, msg []byte) ([]byte, error)
	 */
	return rsa.EncryptPKCS1v15(rand.Reader, &pub, data)
}

	//数据解密
func RSADecrypt(pri *rsa.PrivateKey, cipher []byte) ([]byte, error) {

	return rsa.DecryptPKCS1v15(rand.Reader, pri, cipher)

}

//==========================私钥签名，公钥验签===========================

	//数字签名
func RSASign(pri *rsa.PrivateKey, data []byte) ([]byte, error) {
	//将数据进行MD5 hash加密
	hashed := utils.MD5Hash(data)

	return rsa.SignPKCS1v15(rand.Reader, pri, crypto.MD5, hashed)

}

	//验证签名
func RSAVerify(pub rsa.PublicKey, data []byte, sign []byte) (bool, error) {
	//将原数据进行SHA256 hash加密
	hashed := utils.MD5Hash(data)

	verifyResult := rsa.VerifyPKCS1v15(&pub, crypto.MD5, hashed, sign)

	return verifyResult == nil, verifyResult
}
