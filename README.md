# gmsm
对Go语言常用国密SM2/SM3/SM4算法方法的封装

### 说明

本库为https://github.com/tjfoc/gmsm 库的二次封装，在此处向前辈致敬！

### 安装

```bash
go get github.com/melf-xyzh/gmsm
```

### 使用方法

#### 随机生成sm2公私钥

```go
privateKey, publicKey, err := sm2.CreateSM2Key()
if err != nil {
	log.Fatal(err)
}
```

#### 生成读取公私钥文件（pem格式）

```go
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
```

#### 生成读取公私钥文件（cer格式）

```go
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

// 读取私钥字符串（cer格式）
privateKey, err = sm2.ReadPrivateCerStr(privateKeyStr)
if err != nil {
	log.Fatal(err)
}
// 读取公钥字符串（cer格式）
publicKey, err = sm2.ReadPublicCerStr(publicKeyStr)
if err != nil {
	log.Fatal(err)
}
```

##### sm2加密解密

```go
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
```

##### sm2签名验签

```go
// sm2签名（软加密签名）
sign, err := sm2.Sign(privateKey, data, crypto.BLAKE2b_256)
if err != nil {
    log.Fatal(err)
}
fmt.Println("签名结果：" + sign)
// sm2验签（软加密验签）
ok := sm2.Verify(publicKey, data, sign)
if ok {
    fmt.Println("验签成功")
} else {
    fmt.Println("验签失败")
}

// sm2签名（加密机签名）
sign, err = sm2.EncryptorSign(privateKey, data)
if err != nil {
    log.Fatal(err)
}
fmt.Println("签名结果：" + sign)

// sm2验签（加密机验签）
ok = sm2.EncryptorVerify(publicKey, data, sign)
if ok {
    fmt.Println("验签成功")
} else {
    fmt.Println("验签失败")
}

// sm2签名（硬件加密）
signR, signS, err := sm2.HardwareSign(privateKey, data)
if err != nil {
    log.Fatal(err)
}
fmt.Println("签名R：" + signR)
fmt.Println("签名S：" + signS)

// sm2验签（硬件验签）
ok = sm2.HardwareVerify(publicKey, data, signR, signS)
if ok {
    fmt.Println("验签成功")
} else {
    fmt.Println("验签失败")
}
```

##### sm3算法

```go
// sm3
hashData := sm3.Hash(data)
fmt.Println("sm3签名：" + hashData)
```

##### sm4加密解密

```go
data := []byte("Hello World")
key := []byte("123456789abcdefg")
mode := smconstant.CBC
//mode := smconstant.ECB
//mode := smconstant.OFB
// mode := smconstant.CFB
encrypt, err := sm4.Encrypt(data, key, mode)
if err != nil {
    return
}
fmt.Println(hex.EncodeToString(encrypt))
bytes, err := sm4.Decrypt(encrypt, key, mode)
if err != nil {
    return
}
fmt.Println(string(bytes))
```

##### sm4银联Mac摘要算法

```go
abstract, err := sm4.SecretText("663578966666", []byte("1234567890abcdef"))
if err != nil {
	log.Fatal(err)
}
fmt.Println("银联摘要：" + abstract)
```

