package ecc

import (
	"CryptoHashCode/utils"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

/*
 *	调用go语言的api生成一个ecdsa算法的私钥
 */
func GenerateKey() (*ecdsa.PrivateKey, error) {
	//p256规则生成的一条曲线，p256 Curve是一个结构体
	curve := elliptic.P256()

	return ecdsa.GenerateKey(curve, rand.Reader)

}

/*
 * 私钥对数据进行签名
 */
func ECDSASign(pri *ecdsa.PrivateKey, data []byte) (*big.Int, *big.Int, error) {

	hash := utils.SHA256Hash(data)

	return ecdsa.Sign(rand.Reader, pri, hash)
}

/*
 * 公钥对签名进行验签
 */
func ECDSAVerify(pub ecdsa.PublicKey, data []byte, r *big.Int, s *big.Int) bool {

	hash := utils.SHA256Hash(data)
	return ecdsa.Verify(&pub, hash, r, s)
}
