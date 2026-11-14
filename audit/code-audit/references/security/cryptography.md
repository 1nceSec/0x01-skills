# Cryptography Security Audit

> 密码学安全审计模块
> 覆盖: 加密算法、密钥管理、TLS/SSL、哈希函数

---

## 弱加密算法

### 1. 已淘汰的算法

```python
# 危险: DES (56-bit 密钥)
from Crypto.Cipher import DES
cipher = DES.new(key, DES.MODE_ECB)

# 危险: 3DES (被 NIST 废弃)
from Crypto.Cipher import DES3

# 危险: RC4 (多个漏洞)
from Crypto.Cipher import ARC4

# 危险: Blowfish (过时)
from Crypto.Cipher import Blowfish
```

```java
// 危险: DES
Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

// 危险: RC4
Cipher cipher = Cipher.getInstance("RC4");
```

### 2. 检测命令

```bash
# Python
grep -rn "DES\|DES3\|ARC4\|RC4\|Blowfish\|RC2" --include="*.py"

# Java
grep -rn "DES/\|RC4\|RC2\|Blowfish" --include="*.java"

# 通用
grep -rn "MD5\|SHA1\|SHA-1" --include="*.py" --include="*.java" --include="*.js"
```

---

## 不安全的加密模式

### 1. ECB 模式

```python
# 危险: ECB 模式 (相同明文产生相同密文，可分析模式)
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)
# 攻击: 相同的块产生相同的密文 (经典: ECB 企鹅图像)
```

### 2. IV 重用

```python
# 危险: 固定 IV
IV = b'0' * 16  # 硬编码 IV
cipher = AES.new(key, AES.MODE_CBC, IV)

# 危险: 可预测 IV
iv = str(int(time.time())).encode().ljust(16, b'\x00')
```

### 3. Padding Oracle

```python
# 危险: 暴露填充错误
def decrypt(ciphertext):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext
    except ValueError as e:
        # 暴露了是填充错误还是其他错误!
        if "Padding" in str(e):
            raise PaddingError()  # 可被利用进行 Padding Oracle 攻击
        raise
```
### 4. 检测命令

```bash
# ECB 模式
grep -rn "MODE_ECB\|ECB/\|/ECB/" --include="*.py" --include="*.java"

# 固定 IV
grep -rn "iv\s*=.*b['\"]0\|IV\s*=.*\\\\x00" --include="*.py"
grep -rn "new IvParameterSpec.*new byte\[16\]" --include="*.java"
```

---

## 弱哈希函数

### 1. 密码存储

```python
# 危险: MD5/SHA1 存储密码
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()
password_hash = hashlib.sha1(password.encode()).hexdigest()

# 危险: 无盐哈希
password_hash = hashlib.sha256(password.encode()).hexdigest()
```

### 2. 数据完整性

```python
# 危险: MD5 完整性检查 (碰撞攻击)
file_hash = hashlib.md5(file_content).hexdigest()
```

### 3. 检测命令

```bash
# 弱哈希用于密码
grep -rn "md5\|sha1\|MD5\|SHA1" --include="*.py" --include="*.java" | grep -i "password"

# 无盐哈希
grep -rn "hashlib\.(md5|sha)\|MessageDigest\.getInstance" --include="*.py" --include="*.java"
```

---

## 密钥管理

### 1. 硬编码密钥

```python
# 危险: 硬编码
SECRET_KEY = "my_secret_key_123"
API_KEY = "sk-xxxx"
DB_PASSWORD = "password123"

# 危险: 源码中的密钥
AES_KEY = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
```

### 2. 弱密钥生成

```python
# 危险: 可预测的随机数
import random
key = ''.join(random.choices('abcdef0123456789', k=32))

# 危险: 时间种子
random.seed(int(time.time()))
key = random.randbytes(32)
```

```java
// 危险: java.util.Random (可预测)
Random random = new Random();
byte[] key = new byte[32];
random.nextBytes(key);
```

### 3. 密钥派生

```python
# 危险: 直接使用密码作为密钥
password = "user_password"
key = password.encode().ljust(32, b'\x00')  # 弱!
```

### 4. 检测命令

```bash
# 硬编码密钥
grep -rn "SECRET_KEY\s*=\s*['\"]" --include="*.py"
grep -rn "api[_-]?key\s*[:=]\s*['\"]" --include="*.py" --include="*.js"
grep -rn "password\s*[:=]\s*['\"]" --include="*.py" --include="*.yaml" --include="*.json"

# 弱随机数
grep -rn "random\.\|Random\(" --include="*.py" --include="*.java" | grep -v "SecureRandom\|secrets\."

# 直接用密码作密钥
grep -rn "password.*ljust\|password.*encode.*key" --include="*.py"
```

---
---

## TLS/SSL 配置

### 1. 证书验证

```python
# 危险: 禁用证书验证
import requests
requests.get(url, verify=False)

import urllib3
urllib3.disable_warnings()

# 危险: 信任所有证书
import ssl
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
```

```java
// 危险: 信任所有证书
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() { return null; }
        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
    }
};
```

### 2. TLS 版本

```python
# 危险: 允许旧版本 TLS
import ssl
context = ssl.SSLContext(ssl.PROTOCOL_TLS)  # 可能允许 TLS 1.0
```

```java
// 危险: 允许 SSLv3, TLS 1.0
SSLContext.getInstance("SSL");
```

### 3. 弱密码套件

```python
# 危险: 弱密码套件
context.set_ciphers('ALL')
context.set_ciphers('DEFAULT')
```

### 4. 检测命令

```bash
# 证书验证禁用
grep -rn "verify\s*=\s*False\|CERT_NONE\|check_hostname.*False" --include="*.py"
grep -rn "trustAllCerts\|TrustAllCertificates\|ALLOW_ALL" --include="*.java"

# 旧版 TLS
grep -rn "SSLv3\|TLSv1_0\|PROTOCOL_SSLv" --include="*.py" --include="*.java"

# 弱密码套件
grep -rn "set_ciphers.*ALL\|set_ciphers.*DEFAULT" --include="*.py"
```

---

## JWT 安全

### 1. 弱签名

```python
# 危险: 弱密钥
SECRET = "secret"

# 危险: 允许 none 算法
jwt.decode(token, options={"verify_signature": False})

# 危险: 不验证算法
def verify(token):
    return jwt.decode(token, SECRET, algorithms=jwt.algorithms.get_default_algorithms())
```

### 2. RS256/HS256 混淆

```python
# 攻击: 将 RS256 改为 HS256，用公钥作为 HMAC 密钥
# 公钥通常是公开的 → 攻击者用公钥签 HS256 token，服务端用同一公钥验证通过
```

---

## 审计清单

```
[ ] 检查是否使用弱加密算法 (DES, RC4, Blowfish)
[ ] 检查是否使用 ECB 模式
[ ] 检查 IV/Nonce 是否正确生成 (随机、不重用)
[ ] 检查是否使用认证加密 (GCM, ChaCha20-Poly1305)
[ ] 检查密码存储 (bcrypt, Argon2, scrypt)
[ ] 检查是否使用弱哈希 (MD5, SHA1) 于敏感场景
[ ] 检查密钥是否硬编码
[ ] 检查随机数生成是否安全
[ ] 检查密钥派生函数
[ ] 检查 TLS 证书验证
[ ] 检查 TLS 版本 (>=1.2)
[ ] 检查密码套件配置
[ ] 检查 JWT 配置 (算法、密钥强度)
```

---

## PoC Examples
```bash
# 检测 AES-ECB
rg -n "AES/ECB" --glob "*.{java,kt}"

# 检测弱哈希
rg -n "MD5|SHA1" --glob "*.{java,py,go,js,ts,cs,php}"

# TLS 过时协议探测
curl -Iv --tlsv1.0 https://api.example.com

# JWT 弱算法/混淆
rg -n "Algorithm\\.none|HS256|RS256" --glob "*.{java,js,ts,py,cs}"
```

---

## References

- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [CWE-327: Use of Broken Crypto](https://cwe.mitre.org/data/definitions/327.html)
