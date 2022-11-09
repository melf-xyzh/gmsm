package sm2

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"unsafe"
)

// CreateSM2Key
/**
 *  @Description: 随机生成公私钥
 *  @return privateKey 私钥
 *  @return publicKey 公钥
 *  @return err
 */
func CreateSM2Key() (privateKey *sm2.PrivateKey, publicKey *sm2.PublicKey, err error) {
	// 生成sm2秘钥对
	privateKey, err = sm2.GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	// 进行sm2公钥断言
	publicKey = privateKey.Public().(*sm2.PublicKey)
	return
}

// CreatePrivatePem
/**
 *  @Description: 创建Pem私钥文件
 *  @param privateKey 私钥
 *  @param pwd 密码
 *  @param path Pem私钥文件保存路径
 *  @return err
 */
func CreatePrivatePem(privateKey *sm2.PrivateKey, pwd []byte, path string) (err error) {
	// 将私钥反序列化并进行pem编码
	var privateKeyToPem []byte
	privateKeyToPem, err = x509.WritePrivateKeyToPem(privateKey, pwd)
	if err != nil {
		return err
	}
	// 将私钥写入磁盘
	if path == "" {
		path = "cert/sm2Private.Pem"
	}
	// 获取文件中的路径
	paths, _ := filepath.Split(path)
	err = os.MkdirAll(paths, os.ModePerm)
	if err != nil {
		return err
	}
	var file *os.File
	file, err = os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(privateKeyToPem)
	if err != nil {
		return err
	}
	return
}

// CreatePrivateCer
/**
 *  @Description: 创建Cer私钥文件
 *  @param privateKey 私钥
 *  @param path Cer私钥文件保存路径
 *  @return err
 */
func CreatePrivateCer(privateKey *sm2.PrivateKey, path string) (err error) {
	privateKeyStr := x509.WritePrivateKeyToHex(privateKey)
	// 将私钥写入磁盘
	if path == "" {
		path = "cert/sm2Private.cer"
	}
	// 获取文件中的路径
	paths, _ := filepath.Split(path)
	err = os.MkdirAll(paths, os.ModePerm)
	if err != nil {
		return err
	}
	var file *os.File
	file, err = os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(privateKeyStr)
	if err != nil {
		return err
	}
	return
}

// CreatePublicPem
/**
 *  @Description: 创建Pem公钥文件
 *  @param publicKey 公钥
 *  @param path Pem公钥文件保存路径
 *  @return err
 */
func CreatePublicPem(publicKey *sm2.PublicKey, path string) (err error) {
	// 将私钥反序列化并进行pem编码
	var publicKeyToPem []byte
	publicKeyToPem, err = x509.WritePublicKeyToPem(publicKey)
	if err != nil {
		return err
	}
	// 将私钥写入磁盘
	if path == "" {
		path = "cert/sm2Public.Pem"
	}
	// 获取文件中的路径
	paths, _ := filepath.Split(path)
	err = os.MkdirAll(paths, os.ModePerm)
	if err != nil {
		return err
	}
	var file *os.File
	file, err = os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(publicKeyToPem)
	if err != nil {
		return err
	}
	return
}

// CreatePublicCer
/**
 *  @Description: 创建Cer公钥文件
 *  @param publicKey 公钥
 *  @param path Cer公钥文件保存路径
 *  @return err
 */
func CreatePublicCer(publicKey *sm2.PublicKey, path string) (err error) {
	publicKeyStr := x509.WritePublicKeyToHex(publicKey)
	// 将私钥写入磁盘
	if path == "" {
		path = "cert/sm2Public.cer"
	}
	// 获取文件中的路径
	paths, _ := filepath.Split(path)
	err = os.MkdirAll(paths, os.ModePerm)
	if err != nil {
		return err
	}
	var file *os.File
	file, err = os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(publicKeyStr)
	if err != nil {
		return err
	}
	return
}

// ReadPrivatePem
/**
 *  @Description: 读取Pem私钥文件
 *  @param path Pem私钥文件路径
 *  @param pwd 密码
 *  @return privateKey 私钥
 *  @return err
 */
func ReadPrivatePem(path string, pwd []byte) (privateKey *sm2.PrivateKey, err error) {
	// 打开文件读取私钥
	var file *os.File
	file, err = os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var fileInfo os.FileInfo
	fileInfo, err = file.Stat()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, fileInfo.Size(), fileInfo.Size())
	_, err = file.Read(buf)
	if err != nil {
		return nil, err
	}
	// 将pem格式私钥文件进行反序列化
	privateKey, err = x509.ReadPrivateKeyFromPem(buf, pwd)
	if err != nil {
		return nil, err
	}
	return
}

// ReadPublicPem
/**
 *  @Description: 读取Pem公钥文件
 *  @param path Pem公钥文件路径
 *  @return publicKey 公钥
 *  @return err
 */
func ReadPublicPem(path string) (publicKey *sm2.PublicKey, err error) {
	// 打开文件读取私钥
	var file *os.File
	file, err = os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var fileInfo os.FileInfo
	fileInfo, err = file.Stat()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, fileInfo.Size(), fileInfo.Size())
	_, err = file.Read(buf)
	if err != nil {
		return nil, err
	}
	// 将pem格式私钥文件进行反序列化
	publicKey, err = x509.ReadPublicKeyFromPem(buf)
	if err != nil {
		return nil, err
	}
	return
}

// ReadPrivateCer
/**
 *  @Description: 读取Cer私钥文件
 *  @param path Cer私钥文件路径
 *  @return privateKey 私钥
 *  @return err
 */
func ReadPrivateCer(path string) (privateKey *sm2.PrivateKey, err error) {
	var file *os.File
	file, err = os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return
	}
	defer file.Close()
	content := make([]byte, 0)
	content, err = ioutil.ReadAll(file)
	privateKey, err = x509.ReadPrivateKeyFromHex(string(content))
	return
}

// ReadPrivateCerStr
/**
 *  @Description: 利用私钥字符串生成私钥
 *  @param privateStr 私钥字符串
 *  @return privateKey 私钥
 *  @return err
 */
func ReadPrivateCerStr(privateStr string) (privateKey *sm2.PrivateKey, err error) {
	privateKey, err = x509.ReadPrivateKeyFromHex(string(privateStr))
	return
}

// ReadPublicCer
/**
 *  @Description: 读取Cer公钥文件
 *  @param path Cer公钥文件路径
 *  @return publicKey 公钥
 *  @return err
 */
func ReadPublicCer(path string) (publicKey *sm2.PublicKey, err error) {
	var file *os.File
	file, err = os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return
	}
	defer file.Close()
	content := make([]byte, 0)
	content, err = ioutil.ReadAll(file)
	publicKey, err = x509.ReadPublicKeyFromHex(string(content))
	return
}

// ReadPublicCerStr
/**
 *  @Description: 利用公钥字符串生成私钥
 *  @param publicStr 公钥字符串
 *  @return publicKey 公钥
 *  @return err
 */
func ReadPublicCerStr(publicStr string) (publicKey *sm2.PublicKey, err error) {
	publicKey, err = x509.ReadPublicKeyFromHex(publicStr)
	return
}

// Encrypt
/**
 *  @Description: SM2加密(公钥加密)
 *  @param publicKey 公钥
 *  @param data 需要加密的数据
 *  @return cipherStr 加密后的字符串
 */
func Encrypt(publicKey *sm2.PublicKey, data string) (cipherStr string) {
	// 将字符串转为[]byte
	dataByte := []byte(data)
	// sm2加密
	cipherTxt, err := publicKey.EncryptAsn1(dataByte, rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	// 转为16进制字符串输出
	//cipherStr = fmt.Sprintf("%x", cipherTxt)
	cipherStr = hex.EncodeToString(cipherTxt)
	return
}

// EncryptForJava
/**
 *  @Description: SM2加密(公钥加密)(适配Java版)
 *  @param publicKey 公钥
 *  @param data 需要加密的数据
 *  @return cipherTxt 加密后的字符串
 *  @return err
 */
func EncryptForJava(publicKey *sm2.PublicKey, data string) (cipherTxt string, err error) {
	// 将数据转为[]byte
	dataByte := []byte(data)
	// sm2加密
	cipher := make([]byte, 0)
	cipher, err = sm2.Encrypt(publicKey, dataByte, nil, sm2.C1C3C2)
	if err != nil {
		return "", err
	}
	// 切去前两个字节（为了与京西的java程序兼容）
	cipher = cipher[1:]
	// 将密文转为16进制字符串
	cipherTxt = fmt.Sprintf("%x", cipher)
	return
}

// Decode
/**
 *  @Description: 解密(私钥解密)
 *  @param privateKey 私钥
 *  @param cipherStr 加密后的字符串
 *  @return data 解密后的数据
 *  @return err
 */
func Decode(privateKey *sm2.PrivateKey, cipherStr string) (data string, err error) {
	// 16进制字符串转[]byte
	bytes, _ := hex.DecodeString(cipherStr)
	// sm2解密
	var dataByte []byte
	dataByte, err = privateKey.DecryptAsn1(bytes)
	if err != nil {
		return data, err
	}
	// byte数组直接转成string，优化内存
	str := (*string)(unsafe.Pointer(&dataByte))
	return *str, err
}

// DecryptForJava
/**
 *  @Description: 解密(私钥解密)(适配Java版)
 *  @param privateKey 私钥
 *  @param cipherStr 加密后的字符串
 *  @return data 解密后的数据
 *  @return err
 */
func DecryptForJava(privateKey *sm2.PrivateKey, cipherStr string) (data string, err error) {
	// 此做法为了与java兼容
	// https://www.cnblogs.com/lylhqy/p/15693757.html
	cipherStr = "04" + cipherStr
	// 将16进制字符串转为[]byte
	txtByte := make([]byte, 0)
	txtByte, err = hex.DecodeString(cipherStr)
	if err != nil {
		return
	}
	// sm2解密
	dataByte := make([]byte, 0)
	dataByte, err = sm2.Decrypt(privateKey, txtByte, sm2.C1C3C2)
	if err != nil {
		return
	}
	// 将[]byte转为string
	data = string(dataByte)
	return
}

// Sign
/**
 *  @Description: 签名
 *  @param privateKey 私钥
 *  @param msg 需要签名的内容
 *  @param signer
 *  @return sign 签名字符串
 *  @return err
 */
func Sign(privateKey *sm2.PrivateKey, msg string, signer crypto.SignerOpts) (sign string, err error) {
	if signer == nil {
		signer = crypto.SHA256
	}
	dataByte := []byte(msg)
	var signByte []byte
	// sm2签名
	signByte, err = privateKey.Sign(rand.Reader, dataByte, signer)
	if err != nil {
		return "", err
	}
	// 转为16进制字符串输出
	sign = hex.EncodeToString(signByte)
	return sign, nil
}

// Verify
/**
 *  @Description: 验签
 *  @param publicKey 公钥
 *  @param msg 需要验签的内容
 *  @param sign 签名字符串
 *  @return verify
 */
func Verify(publicKey *sm2.PublicKey, msg, sign string) (verify bool) {
	// 16进制字符串转[]byte
	msgBytes := []byte(msg)
	signBytes, _ := hex.DecodeString(sign)
	// sm2验签
	verify = publicKey.Verify(msgBytes, signBytes)
	return
}
