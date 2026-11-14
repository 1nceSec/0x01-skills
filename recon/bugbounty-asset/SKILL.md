---
name: bugbounty-asset
description: 国外SRC（Bug Bounty：HackerOne/Bugcrowd/Intigriti/YesWeHack）资产收集六步管道，与国内线 src-asset 镜像对称：①Scope解读→②主体清单(收购/ASN/reverse whois)→③被动资产(CT日志/被动DNS/数据集)→④主动测绘(枚举/爆破/排列组合/存活/端口)→⑤指纹识别→⑥汇总，衔接 bugbounty-triage 精判。用户给出 bug bounty program 链接/公司名，要求"跑国外SRC/收集国外资产/bug bounty recon/国外信息收集"时使用。
---

# Bug Bounty（国外 SRC）资产收集六步管道

## 触发与输入

用户提供 HackerOne/Bugcrowd/Intigriti/YesWeHack 的 program URL（例：`https://hackerone.com/xxx`）
或目标公司名，要求按流程收集资产。全程只做授权范围内的信息收集，**out_of_scope 资产绝对不碰**（国外 program 法律敏感度高于国内）。

## 启动前（必做）

1. **工具位置（本机 2026-11-13 已装齐，23 个）**：`E:\PenTest\0x02_Tools\S_Src\GoBin\`（22 个 go 工具 exe）+ `E:\Environment\Python312\Scripts\waymore.exe`。字典：`E:\PenTest\0x03_Dicts\DNS\Jhaddix-combined.txt`（217万行）+ `n0kovo_large.txt`（95万行）。nuclei 模板：`E:\PenTest\0x02_RedTeam_Tools\S_Scanner\nuclei-templates\`（28450 yaml，本机原生位置，`C:\Users\21500\nuclei-templates` 是指向它的 junction，nuclei 自动识别无需 -t）。使用前 `export PATH="$PATH:/e/PenTest/0x02_Tools/S_Src/GoBin"`。
   > **安装前查重（用户规则 2026-11-13）**：任何工具/字典/模板安装前，先在 `E:\PenTest` 全盘搜同名或同类（`find /e/PenTest -iname "<tool>*"`，注意 `0x01_SRC_Tools`、`0x02_RedTeam_Tools` 等历史工具区与 junction 重定向），已存在则用现有的，禁止重复安装。教训：nuclei 模板本机早有（junction 兜底才没产生重复文件）。已知双份：httpx（S_Scanning 旧 56MB / GoBin v1.12.0——**链路统一用 GoBin 版**）。
   已装版本：subfinder v2.17.0 / httpx v1.12.0 / nuclei v3.11.1 / amass v3.23.3 / katana v1.8.0 / naabu 2.7.0 / tlsx v1.4.0 / asnmap v1.2.0 / dnsx 1.3.1 / ffuf 2.1.0 / gotator 1.1 / waymore v8.9，另有 assetfinder、hakrevdns、qsreplace、meg、anew、inscope、notify、gospider、hakrawler、gowitness、goaltdns。
   > 注意：**altdns 在本机用 goaltdns 等价替代**（Python 版 altdns 不兼容 py3.12）；④的 `altdns -i ... -r -s ...` 命令换成 `goaltdns` 同参数。gotator 正确仓库是 `Josue87/gotator`（非 blackcat-1b）；hakrevdns 是 `hakluke/hakrevdns`（非 tomnomnom）。
   缺失重装（GitHub 直连慢用 `https://gh-proxy.com/` 镜像前缀，goproxy.cn 加速）：
   ```bash
   export GOPROXY=https://goproxy.cn,direct GOBIN="E:\PenTest\0x02_Tools\S_Src\GoBin"
   go install -v github.com/owasp-amass/amass/v3/...@latest
   go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
   go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
   go install -v github.com/projectdiscovery/katana/cmd/katana@latest
   go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest
   go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
   go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
   go install -v github.com/tomnomnom/assetfinder@latest
   go install -v github.com/ffuf/ffuf/v2@latest
   go install -v github.com/hakluke/hakrevdns@latest
   ```
2. **API key 配置**：amass 无 key 数据源减半（Chaos/VirusTotal/SecurityTrails/Shodan/Censys/WhoisXML 等，
   写入 `~/.config/amass.ini`，`amass enum -config` 指定）。缺 key 时向用户逐项索要，**不回显内容**。
3. **规则确认**：读 program 的 policy——是否允许自动化扫描/爆破/端口扫描（很多 program 禁止高速主动扫描，
   只允许被动；这直接决定④的执行边界）。

## 六步编排（与国内线 src-asset 逐步对照）

| 步骤 | 做什么 | 关键命令/来源 | 产物 | 对照国内 |
|---|---|---|---|---|
| ①Scope解读 | 读 program policy/scope 表，判定类型（**通配符型** `*.example.com` / **资产清单型** / **集团型** "any asset"如 Sony/IBM/AT&T），提取 in_scope/out_of_scope/已列 acquisitions，输出 scope_json；后续所有产物用 tomnomnom `inscope` 过滤：`cat all_subs.txt \| inscope -scope scope.txt` | HackerOne/Bugcrowd 页面 | 步骤①输出/{program}_scope.json + 人工研判清单 | ①范围解读 |
| ②主体清单 | 集团型/通配符型才做：收购历史（Crunchbase/tracxn/owler）→ ASN（bgp.he.net 或 `amass intel -org "<公司名>"`）→ `asnmap -asn <ASN>` 得 CIDR → reverse whois（`amass intel -d <域> -whois`、whoisxmlapi）→ SAN 证书挖掘（`tlsx -san -cn -host <IP/CIDR>`）→ Shodan `org:"<公司>"` | `amass intel -asn <X> -whois -d <target>` 一次串起来 | 步骤②输出/{program}_主体资产.json（根域清单+CIDR清单） | ②公司清单(股权穿透) |
| ③被动资产 | CT 证书日志（crt.sh）、被动 DNS（VirusTotal）、Chaos 免费数据集（projectdiscovery.io/chaas，可整包下载）、Wayback/gau 历史 URL | `subfinder -d <域> -all`、`assetfinder --subs-only <域>` | 步骤③输出/{program}_被动子域清单.txt | ③备案资产(根域名/APP/小程序) |
| ④主动测绘 | 爆破（ffuf + n0kovo/dns-Jhaddix 字典【本机 `E:\PenTest\0x03_Dicts\DNS\`】，`FUZZ.example.com`）、**排列组合扫描**（altdns/gotator 对已知子域做变体再解析——零日志子域只能靠这个挖到）、CIDR 反查域名（`echo <CIDR> \| hakrevdns`）、存活（httpx）、端口（naabu，重点 3000/4848/6379/9200/27017/2375）、**爬取组合**（katana 深爬 `-d 3 -jc` 主力 + gospider/hakrawler 互补 + `waymore` 替代 gau 拿历史 URL 含 POST 参数）；scope 内含 APP 则加 APK 静态提取 | `goaltdns -i live_subs.txt -w words.txt -r -s permuted_live.txt`（本机替代 altdns）、`gotator -sub live_subs.txt -perm perm.txt -depth 2 \| dnsx -silent`、`ffuf -u https://FUZZ.<域> -w <字典>`、`amass enum -d <域> -active -cidr <CIDR> -asn <ASN>`、`cat <子域> \| httpx -title -tech-detect -status-code` | 步骤④输出/{program}_live_hosts.txt、open_ports、urls、permuted_live | ④Web资产(Quake测绘) |
| ⑤指纹识别 | httpx 技术栈+标题、tlsx JARM/JA3 TLS 指纹、nuclei tech-detect、gowitness 全量截图（肉眼筛高价值目标最快） | `nuclei -l live_hosts.txt -tags tech`、`gowitness file -f live_hosts.txt -P shots/ --no-http` | 步骤⑤输出/{program}_指纹结果.csv + shots/ | ⑤指纹识别(TscanPlus) |
| ⑥汇总 | `sort -u` 合并②③④ → `inscope` 过滤回 scope 内 → nuclei 中危以上漏扫 → `amass track` diff 上次运行新增子域；**周期监控**：tomnomnom `meg` 对全部 URL 批量请求并 diff 响应差异（内容级变化监控，比子域 diff 更早发现改版/新端点）→ **交给 bugbounty-triage 做关键脆弱资产精判（P0–P3 打点清单）** | `diff old_subs.txt new_subs.txt \| grep ">"` | 步骤⑥输出/{program}_汇总大表.csv → 精判后打点清单 | ⑥汇总大表→asset-triage |

## 核心公式（贯穿全程）

- **②根域种子 = scope 明示 ∪ 收购清单 ∪ reverse whois ∪ ASN/CIDR 反查 ∪ SAN 挖掘 − out_of_scope 黑名单**
- ①输出的 scope_json（in_scope/通配符/黑名单/allowed_activities）是②-⑥的机器可读输入
- ④主动动作的边界由①的 policy 决定：禁止主动扫描的 program，④只跑被动存活（httpx 对已知子域）

## 与国内线的关键差异（必读，勿混用）

1. **主体归属**：国内走企查查/爱企查**股权穿透**+ICP 备案；国外走**收购公告+ASN+reverse whois+SAN 挖掘**——同构思想（沿公司组织关系扩资产），数据源体系完全不同。
2. **被动源王座**：国内是备案库；国外是**证书透明日志（CT）**——新建 HTTPS 子域必然留痕，crt.sh/Chaos 是第一被动源。
3. **测绘引擎**：国内 Quake/TscanPlus；国外 Censys/Shodan + ProjectDiscovery 工具链。
4. **scope 法律边界**：国内 SRC 越界多发警告/不计分；国外 program out_of_scope 可能直接封号甚至法律追责，①的判定必须保守。
5. **周期性 diff**：amass 自带 `amass track`（本地库比对历次扫描）+ Chaos 数据集按月更新，国外线的增量发现比国内自动化程度高。

## 环境生存法则（实战踩坑）

1. **Medium 资料查阅**：出版物自定义域名（infosecwriteups.com、osintteam.blog）可直接自动化访问；medium.com 主站连续自动化访问会触发 Cloudflare 质询——冷却约 1 小时，或用户人工打开一次页面过质询后再接管。`cf_clearance` 与浏览器指纹绑定，跨浏览器/会话注入无效。
2. 高流量步骤（ffuf/naabu/nuclei）执行前二次确认 program 速率规则；对 wildcard 目标控制并发。
3. amass 每次扫描自动落本地库（`amass db -list`），**重跑同一命令即自动 diff 新增资产**——用 track 而不是每次全量重扫。
4. 长任务（②③④）后台运行 + 每单元落盘；网络抖动常见，请求级重试（同国内线法则 4）。
5. Windows 下 Python 统一 `python -X utf8`；中文产物文件 UTF-8 无 BOM（同国内线法则 2/3）。

## 完成后交付

向用户给出：⑥大表路径+各 sheet 行数、各步关键数字（根域数/收购公司数/CIDR 数/子域数/存活数/指纹覆盖率）、
人工研判清单（scope 存疑项）、策略决策及依据（如：集团型才做②、program 禁主动则④降级）。

## 方法论来源（学习素材）

- The Ultimate Bug Bounty Recon Guide（wolfsec1337，41KB 综合指南）——inscope/altdns/gotator/juicy_params/Axiom分布式/监控告警
- How to Build a Complete Attack Surface Map（Rakeshjoshi）——资产清单/攻击面地图方法论（in/out/unknown 三态 scope）
- My 3-Step Recon Blueprint 2026（kd-200/Very Lazy Tech）——katana/gospider/hakrawler/waymore 爬取组合
- Different Approaches For Reconnaissance（z0id，H1/BC 研究员）——meg 响应 diff/视觉侦察
- The Passive OSINT Toolkit +15 工具（Omar Maged）——被动源工具分阶段清单
- How Hackers Find and Target Vulnerable Websites（mainekhacker）——目标选择两路径（机会型/定向型）
- Hakluke's Guide to Amass（2.7K claps 经典）——amass intel/enum/db/track 五子命令
- My Recon Methodology ep1（realm3ter）——acquisitions→ASN→reverse whois→SAN 全链
- Bug Bounty Recon: CIDR, ASN & Subdomain Enumeration Guide（sinhaamrit）——水平/垂直侦察二分法
- The Cyberboy PayPal Live Hunting、Monika 自动化侦察流水线（本地已译制笔记：`RedTeamNotes/漏洞挖掘笔记/信息搜集系列/`）
