---
name: ctf-crypto
description: 密码学：RSA弱参数、AES-ECB、padding oracle、哈希扩展
category: crypto
---

## 特征识别
- 给了公钥/密文/加密脚本(.py)，题目含encrypt/decrypt/cipher/RSA/AES

## 工具
`openssl` `python3`(pycryptodome/gmpy2/sympy) `RsaCtfTool` `hashpump` `PadBuster`

## 解题步骤

### RSA
1. 提取n,e,c：`openssl rsa -pubin -in pub.pem -text -noout`
2. 小n(<512bit)：`python3 -c "from sympy import factorint; print(factorint(n))"` 或 factordb.com
3. 共模攻击(同n不同e)：扩展欧几里得 → `pow(c1,s1,n)*pow(c2,s2,n)%n`
4. 低指数(e=3)：直接开e次方根 `gmpy2.iroot(c, e)`；c > n时用CRT或Hastad广播攻击
5. Wiener(e很大/d很小)：连分数攻击恢复d
6. Fermat分解(p≈q)：`a=isqrt(n); while not is_square(a*a-n): a+=1; p=a-isqrt(a*a-n)`
7. `RsaCtfTool --publickey pub.pem --uncipherfile cipher.txt`

### RSA进阶
- **多素数RSA**(n=p*q*r)：phi=(p-1)(q-1)(r-1)，分解后照常
- **dp泄露**(dp=d mod p-1)：`p = gcd(pow(2,e*dp,n)-2, n)` 恢复p
- **Coppersmith**(已知明文高位)：SageMath `small_roots()` 求剩余位
- **PKCS#1 v1.5 Bleichenbacher**: padding oracle逐步缩小明文范围

### AES
7. ECB模式(相同明文→相同密文)：字节位移攻击/选择明文逐字节爆破
8. CBC翻转：修改前一块密文的特定字节影响下一块解密结果
   - `C[i] ^= old_byte ^ new_byte` → 下一块对应位置变为new_byte
9. Padding Oracle：逐字节爆破，根据padding错误/正确的响应差异
```python
# Padding Oracle核心逻辑
for i in range(16):  # 逐字节从末尾开始
    for guess in range(256):
        modified_iv[15-i] = guess
        if oracle(modified_iv + cipher_block):  # padding正确
            intermediate[15-i] = guess ^ (i+1)
            plaintext[15-i] = intermediate[15-i] ^ original_iv[15-i]
            break
    for j in range(i+1):  # 更新padding值
        modified_iv[15-j] = intermediate[15-j] ^ (i+2)
```
- 工具: `PadBuster` / `python3 padding_oracle_attack.py`

### 哈希
10. 长度扩展(MD5/SHA1/SHA256)：`hashpump -s <sig> -d <data> -a <append> -k <keylen>`
    - 适用场景：`hash(secret+data)` 已知且可追加数据，key长度可爆破(1-32)
11. 弱哈希碰撞：MD5 `fastcoll` 生成碰撞对；SHA1用 `sha1collider`

### 其他常见密码学
- **异或加密**: 已知部分明文 → `key = ciphertext ^ known_plaintext` → 循环key解密全文
- **自定义加密**: 逆向加密函数，写解密脚本；注意取模/移位/查表操作的逆运算
- **DSA/ECDSA nonce复用**: 两次签名用相同k → `k = (m1-m2) * inverse(s1-s2) mod q` → 恢复私钥
- **DES弱密钥**: 密钥全0/全1/全E/全F → 加密=解密
- **RC4/XOR流密码**: 已知明文片段→恢复密钥流→解密剩余

### 古典密码
- 凯撒/ROT13：CyberChef ROT13暴力 | `tr 'A-Za-z' 'N-ZA-Mn-za-m'`
- 维吉尼亚：Kasiski检验定密钥长度 → 频率分析各段
- 栅栏密码：尝试2~10行数重排
- 仿射密码：`m = a*x + b mod 26`，a与26互素，gcd(a,26)=1

### 实用解密模板
```python
# RSA解密
from Crypto.Util.number import long_to_bytes, inverse
phi = (p-1)*(q-1); d = inverse(e, phi)
print(long_to_bytes(pow(c, d, n)))

# AES-ECB解密
from Crypto.Cipher import AES
print(AES.new(key, AES.MODE_ECB).decrypt(ct))

# AES-CBC解密
from Crypto.Cipher import AES
print(AES.new(key, AES.MODE_CBC, iv).decrypt(ct))
```

## Flag位置
- 解密结果即flag
- 伪造签名后访问特权接口获取flag
- 解密后可能是base64编码，再解一层
