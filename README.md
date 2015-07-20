AES/CBC/PKCS7Padding加密的实现
======
一些情况下，客户端要与服务端通信会加密。常会要到加密算法AES(Advanced Encryption Standard)，下面是Python和PHP的实现。

**Python需要安Crypto库**
**PHP需要安装mcrypt扩展**

### 说明 ###
加密模式采用AES/CBC/PKCS7Padding

**注意：加密后的字节码使用Base64转换成字符串**
* 加密模式: CBC
* 填充模式: PKCS7Padding
* 加密密钥: 用户密钥 SHA256 的32 bytes
* AES IV : 加密密钥的前 16 bytes
* Base 64: Base64.DEFAULT

加密过程:

加密：padding->CBC加密->base64编码

解密：base64解码->CBC解密->unpadding
