/**
 * @Time    :2022/5/14 8:40
 * @Author  :MELF晓宇
 * @Email   :xyzh.melf@petalmail.com
 * @FileName:main.go
 * @Project :gmsm
 * @Blog    :https://blog.csdn.net/qq_29537269
 * @Guide   :https://guide.melf.space
 * @Information:
 *
 */

package main

import (
	"crypto"
	"fmt"
	"github.com/melf-xyzh/gmsm/sm2"
	"github.com/melf-xyzh/gmsm/sm3"
	"github.com/melf-xyzh/gmsm/sm4"
	"log"
)

func main() {
	// 随机生成sm2公私钥
	privateKey, publicKey, err := sm2.CreateSM2Key()
	if err != nil {
		log.Fatal(err)
	}

	// 生成私钥文件（pem格式）
	err = sm2.CreatePrivatePem(privateKey, nil, "cert/privateKey.pem")
	if err != nil {
		log.Fatal(err)
	}
	// 生成公钥文件（pem格式）
	err = sm2.CreatePublicPem(publicKey, "cert/publicKey.pem")
	if err != nil {
		log.Fatal(err)
	}
	// 读取私钥文件（pem格式）
	privateKey, err = sm2.ReadPrivatePem("cert/privateKey.pem", nil)
	if err != nil {
		log.Fatal(err)
	}
	// 读取公钥文件（pem格式）
	publicKey, err = sm2.ReadPublicPem("cert/publicKey.pem")
	if err != nil {
		log.Fatal(err)
	}

	// 生成私钥文件（cer格式）
	err = sm2.CreatePrivateCer(privateKey, "cert/privateKey.cer")
	if err != nil {
		log.Fatal(err)
	}
	// 生成公钥文件（cer格式）
	err = sm2.CreatePublicCer(publicKey, "cert/publicKey.cer")
	if err != nil {
		log.Fatal(err)
	}
	// 读取私钥文件（cer格式）
	privateKey, err = sm2.ReadPrivateCer("cert/privateKey.cer")
	if err != nil {
		log.Fatal(err)
	}
	// 读取公钥文件（cer格式）
	publicKey, err = sm2.ReadPublicCer("cert/publicKey.cer")
	if err != nil {
		log.Fatal(err)
	}

	data := "Hello,World!"
	// sm2加密
	cipherStr := sm2.Encrypt(publicKey, data)
	fmt.Println("加密结果：" + cipherStr)
	// sm2解密
	data, err = sm2.Decode(privateKey, cipherStr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("解密结果：" + data)

	// sm2加密(适配java)
	cipherStr, err = sm2.EncryptForJava(publicKey, data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("加密结果：" + cipherStr)
	// sm2解密(java)
	data, err = sm2.DecryptForJava(privateKey, cipherStr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("解密结果：" + data)

	// sm2签名
	sign, err := sm2.Sign(privateKey, data, crypto.BLAKE2b_256)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("签名结果：" + sign)
	// sm2验签
	ok := sm2.Verify(publicKey, data, sign)
	if ok {
		fmt.Println("验签成功")
	} else {
		fmt.Println("验签失败")
	}

	// sm3
	hashData := sm3.Hash(data)
	fmt.Println("sm3签名：" + hashData)

	// sm4银联Mac摘要算法
	abstract, err := sm4.SecretText("663578966666", []byte("1234567890abcdef"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("银联摘要：" + abstract)
}
