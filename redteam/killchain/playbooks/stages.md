# Kill Chain 阶段定义 + 执行循环（红队评估）

> 本文件由 SKILL.md 路由加载。Bootstrap 完成后进入 Stage 1，每轮循环 Read 一次。
> v2.1: Kill Chain 三路径 — 外网Web红队 + 内网AD红队 + 云原生K8s红队，按目标环境自动路由。

## 分支路由

| 条件 | 分支 | 典型场景 |
|------|------|---------|
| 目标为公网Web应用/无内网入口 | **Web红队** | SRC打点、外网边界突破、Web应用RCE |
| 已获内网立足点/目标含域环境 | **AD红队** | 攻防演练内网推进、域控接管 |
| 外网突破后发现内网 | Web→AD **链式切换** | 完整红队：Web突破→内网横向→域控 |
| 目标暴露K8s管理面/突破后发现容器环境 | **K8s红队** | 面板/API/kubelet/etcd暴露→集群接管→宿主机→内网 |

---

# 分支A：外网Web红队 Kill Chain

> 目标：RCE / 后台权限 / 数据。路径：Web漏洞链。
> XSS/CSRF等不直接产出shell/data的类型为低优先级，仅当可链式升级时才投入。

## Kill Chain 总览（Web）

| Stage | 名称 | 目标 | 推进门 |
|-------|------|------|--------|
| W1 | Web Recon | 技术栈+攻击面测绘 | 技术栈确认+≥1个高价值入口 |
| W2 | Exploit | RCE/权限/数据 | 命令执行 或 后台权限 或 敏感数据 |
| W3 | Deepen | 扩大战果+链式提升 | 更高权限 或 更多数据 |
| W4 | Objective | 证据采集+得分提交 | 目标达成证据齐全 |

### Stage W1: Web侦察

**知识卡**：`exploit/web-rce-vectors.md` + `recon-methodology.md`

1. 技术栈指纹（响应头/Cookie/端口/页面特征）→ 匹配RCE向量优先级表Tier分类
2. JS审计：路由/API端点/硬编码凭证/加密逻辑/webpack chunk分析
3. 目录探测：`/actuator` `/nacos` `/druid` `/swagger` `/manager` `/admin` `/console`
4. 功能点枚举：文件上传/搜索/导出/URL参数/XML解析/模板渲染
5. **云存储引用收集**（JS/接口回包/CNAME里出现 OSS/COS/S3/BOS 域名时）：
   - 按 `appsec/bucket-takeover-test.md` §2-§3 逐引用验活（NoSuchBucket=悬空）
   - 悬空桶 → §9 killchain用法：授权范围内抢注 → 可信域投递（初始访问/供应链向量，supply_chain bonus）
6. **源码获取判断**（识别到框架/CMS/商业系统后立即执行）：
   - 免费渠道（直接执行）：GitHub/Gitee搜索 | .git/.svn/.DS_Store泄露探测 | 备份文件探测(.bak/.zip/.rar/.tar.gz) | heapdump/actuator泄露 | Web Archive历史快照 | 官方试用版/演示版
   - 付费渠道（找到后报用户确认）：淘宝/闲鱼搜商业系统源码 | 源码交易站(互站网等) | Telegram群/论坛泄露版
   - 获取到源码 → 记入 `source_intel[]` → 委托 `Skill("code-audit")` 审计 → 产出进findings作为W2 Tier 0输入

**产出**：技术栈判定 → 按快速决策树确定Tier 1/2/3测试顺序 + 悬空桶清单（如有）+ 源码审计结果（如有）

### Stage W2: 漏洞利用（RCE向量优先级驱动）

**知识卡**：`exploit/web-rce-vectors.md` + `exploit/middleware-java.md` + 按需加载注入/上传/SSRF等

按RCE向量优先级表执行：

**Tier 0 — 源码审计产出**（最高优先级，有审计结果时优先执行）：
- code-audit skill产出的0day/auth bypass/SQLi/RCE → 直接构造PoC验证
- 源码中发现的硬编码凭证/密钥 → 直接尝试登录/解密
- 源码中的危险函数调用链 → 构造触发路径

**Tier 1 — 批量检测**（每个≤3min，并行）：
- Java反序列化（Shiro/Fastjson/Weblogic/JBoss）→ 指纹命中即打
- Log4Shell → 全字段JNDI喷射
- Struts2 OGNL → .action/.do端点探测
- Spring系列 → SpEL/Actuator/Spring4Shell
- 中间件弱口令 → 默认路径+默认凭证

**Tier 2 — 手工构造**（每个≤15min，逐功能点）：
- 文件上传→WebShell | 命令注入 | SSTI | SSRF→内网 | SQLi→写文件 | XXE

**Tier 3 — 链式利用**（有线索时针对性）：
- 认证绕过→后台→RCE | JS泄露凭证→接管 | 日志投毒→LFI→RCE
- SSRF→云元数据→AK/SK | 原型污染→RCE | heapdump→凭证→数据

**止损**：单向量≤5种bypass无突破→标记parked，推进下一个

**pentest委托**（红队专用快速模式）：
- 触发：`redteam-state.mjs path next` 返回 `delegate_pentest` 时，或手工判断需要系统化覆盖测试
- 调用：`Skill("pentest-flow")`，传入目标URL+已有Cookie/Token
- 约束：pentest只负责找入口（RCE/权限/数据），不做完整覆盖测试
- 返回：confirmed findings列表（漏洞类型+PoC+可利用性评估）
- 红队消费结果：取RCE/权限类finding → 进W3深入利用；取数据类finding → 进W4目标达成
- pentest产出的findings自动写入红队blackboard.findings[]

### Stage W3: 深入利用

命中任意RCE/权限/数据后：
1. **RCE确认**：`whoami`/`id`/`ipconfig` → 记录权限级别
2. **扩大数据面**：数据库连接串→证明可达（库名+表名，不拖库）
3. **链式升级**：低权限→提权 | 单点→横向 | Web→内网入口
4. **发现内网**：→ 切换到分支B（AD红队）Stage 3起
5. **发现容器环境**（`/.dockerenv`、cgroup含kubepods、SA token存在）→ 切换到分支C（K8s红队）K2起

### Stage W4: 目标达成

采集证据，按得分矩阵提交（见下方通用得分矩阵）。

---

# 分支B：内网AD红队 Kill Chain

> 目标：域控接管 / 核心数据库 / 核心业务系统控制权。
> 前置：已获内网立足点（来自Web突破或VPN/钓鱼）。

## Kill Chain 总览（AD）

| Stage | 名称 | 目标 | 推进门 |
|-------|------|------|--------|
| A1 | Recon | 内网环境探测+域判断 | 域环境确认+初始凭证 |
| A2 | PrivEsc | 本机提权+凭证导出 | SYSTEM/root+本机凭证 |
| A3 | Lateral | 横向移动+域内推进 | 域管凭证或域控shell |
| A4 | Persist | 关键节点持久化 | ≥2个独立持久化点 |
| A5 | Objective | 达成目标+得分最大化 | 高分项全部提交 |

### Stage A1: 内网侦察

**知识卡**：`recon/windows-workgroup.md` + `recon/ad-domain-enum.md`

1. 本机信息：whoami/ipconfig/域判断/网络段
2. 内网存活探测（OPSEC评估后执行）
3. 域环境枚举：域控/域用户/GPO/SPN/委派配置
4. 服务发现：数据库/文件共享/内部Web应用

### Stage A2: 权限提升

**知识卡**：`privesc/linux.md` 或 `privesc/windows.md`

1. 判断OS → 加载对应提权知识卡
2. 按知识卡优先级逐项检查
3. 提权成功 → 导出本机凭证（mimikatz/hashdump/SAM）

### Stage A3: 横向移动

**知识卡**：`lateral/techniques.md` + `ad-attack/delegation.md` + `ad-attack/ticket.md`

1. 凭证复用：PTH/PTT（优先wmiexec，流量小）
2. 委派攻击：非约束/约束/RBCD
3. Kerberoasting/AS-REP Roasting → 离线破解
4. 每拿下新主机 → A2(提权→导凭证) → 回A3

**得分驱动**：每多控一台主机都是得分项。横向兼顾"向域控推进"和"扩大控制面"。

### Stage A4: 权限维持

**知识卡**：`persist/techniques.md`
- 计划任务 > 服务 > 注册表 > WMI（按OPSEC排序）
- 初始立足点+关键跳板各部署一个
- 持久化操作**需用户确认**

### Stage A5: 达成目标

同Stage W4，按通用得分矩阵采集提交。

---

# 分支C：云原生K8s红队 Kill Chain

> 目标：集群接管（cluster-admin）/ 宿主机 root / 云账号凭据。
> 前置：目标暴露 K8s 管理面（Web突破进入容器环境同样从 K2 起）。
> **知识卡**：全阶段加载 `redteam/cloud/k8s-attack.md`。

## Kill Chain 总览（K8s）

| Stage | 名称 | 目标 | 推进门 |
|-------|------|------|--------|
| K1 | 管理面入口 | 拿到面板/API访问权 | admin token 或 匿名API可读 |
| K2 | Pod立足 | 业务Pod shell + 环境侦察 | Pod内五问完成 + ≥1凭据 |
| K3 | 逃逸+宿主机 | 宿主机文件系统读取 | hostroot可读 + shadow/id_rsa到手 |
| K4 | 横向+目标 | 下一台主机/集群/云账号 | 新主机root 或 集群控制权 |

### Stage K1: 管理面入口

**知识卡**：`redteam/cloud/k8s-attack.md` §1-§2

1. 入口向量按命中率过一遍：Dashboard NodePort → API Server 6443匿名 → kubelet 10250匿名 → etcd 2379 → Secret API可列举
2. 面板登录墙别死磕：直接打 Secret API 偷 admin token（列表定namespace → 取secret → base64解码）
3. 面板已进：看SA名是否 `admin-user`（教程式部署指纹=cluster-admin直达）
4. 无面板无匿名面 → 回Web分支找业务漏洞进Pod（K2起）

### Stage K2: Pod立足

**知识卡**：`redteam/cloud/k8s-attack.md` §3-§4

1. **选业务Pod不选系统Pod**（有凭据/最小破坏/可能特权三理由）
2. exec进Pod → 五问侦察：我是谁(CapEff) / 我在哪(/etc/hosts+route) / 挂了什么(lsblk/mount) / 有什么凭据(env+/proc/1/environ+SA token) / 集群权限多大(SSRR)
3. env硬编码云密钥（OSS/MQ AK-SK）直接入 `credentials[]`
4. 非特权且无挂载 → 检查表4-7项（docker.sock/hostPID/cgroup），仍无 → 回K1换Pod或回Web分支

### Stage K3: 逃逸+宿主机

**知识卡**：`redteam/cloud/k8s-attack.md` §5-§7

1. 逃逸检查表7项按序过，命中即走对应手法
2. 挂宿主盘：`mount -o ro /dev/dm-0 /tmp/hostroot`（**必须只读**，OPSEC红线）→ 读 `/etc/hostname` 确认越狱
3. 宿主机收割清单：shadow / id_rsa / **known_hosts(横向名单)** / cron(备份目标) / Jenkins凭据 / kubelet pki / 云凭据
4. 全部凭据入黑板，known_hosts展开进 `network[]`

### Stage K4: 横向+目标

**知识卡**：`redteam/cloud/k8s-attack.md` §8

1. SSH链：偷到的id_rsa + known_hosts/cron目标逐台试（回uid=0即新主机）
2. 集群链：kubelet pki/admin token → 节点/集群控制（多集群同测）
3. 云链：AK/SK → 云控制台 → 云管/VPN（centralised_system目标）
4. 拿新Linux主机 → 参考A2提权导凭证再横向（Windows主机回AD分支A3）
5. 证据按得分矩阵采集提交

---

# 通用模块（三个分支共用）

## 得分矩阵（目标体系）

> 用户提供规则时以用户规则为准，否则按以下通用权重。
> 靶标由用户指定，是最高优先级目标。其余目标按分支归属。

### 顶级目标

| 目标 | category | 权重 | 证据要求 | 说明 |
|------|----------|------|---------|------|
| 靶标系统权限 | target | critical | 靶标权限截图+whoami/id | 用户指定的靶标，打穿=出局 |
| 靶标数据 | target | critical | 靶标业务数据脱敏截图 | 靶标中的核心数据 |

### Web分支目标

| 目标 | category | 权重 | 证据要求 |
|------|----------|------|---------|
| 外网服务器RCE | server_control | high | whoami+ipconfig+hostname |
| 管理后台权限 | admin_panel | high | 登录截图+管理功能操作截图 |
| 数据库访问 | db_access | high | 库名+表名+脱敏样本(≤3条) |
| 敏感数据获取 | sensitive_data | medium | 数据类型+数量+脱敏截图 |

### 内网分支目标（AD + K8s）

| 目标 | category | 权重 | 证据要求 |
|------|----------|------|---------|
| 域控接管 | centralised_system | critical | DCSync输出/Golden Ticket+域管hash |
| K8s集群接管（cluster-admin/多集群） | centralised_system | critical | admin token操作截图+kubectl get nodes |
| 堡垒机控制 | centralised_system | high | 登录截图+可管理主机列表 |
| 云管/VPN管理 | centralised_system | high | 管理界面截图+可控资源范围 |
| 云账号凭据（AK/SK可用） | centralised_system | high | 凭据调用云API成功回显（脱敏） |
| K8s宿主机root | server_control | high | whoami+hostname+节点名对应 |
| 内网主机(每台) | intranet_host | medium(累加) | whoami+ipconfig+hostname |
| 内网数据库/文件共享/全量secrets | intranet_data | medium | 库名表名/共享路径+数据样本 |

### 加分项

| 目标 | category | 权重 | 证据要求 |
|------|----------|------|---------|
| 完整攻击链 | attack_chain | bonus | 入口→靶标的完整路径图 |
| 0day使用 | zero_day | bonus | 漏洞详情+PoC |
| 供应链/迂回突破 | supply_chain | bonus | 第三方入口→目标的路径 |

### 过程资产（不计分但必须追踪）

凭证（密码/hash/ticket/token/key）→ `credentials[]` 中追踪
网络拓扑（已知网段/路由）→ `network[]` 中追踪

## Reason-Act 循环（每个阶段内部）

### Step 1: 读黑板 + 态势评估

读 `redteam-blackboard.json`，评估：
- `meta.current_stage` + 推进门条件是否满足
- `assets` 已控资产 / `credentials` 已获凭证
- `attack_path` 攻击路径 / 未探索路径
- 阻塞项（需用户授权的操作）

**每轮必答**：
1. 当前Kill Chain哪个阶段（W1-W4 / A1-A5 / K1-K4）？离推进门差什么？
2. objectives[]中哪些已达成、哪些在推进、哪些被阻塞？
3. 手上有哪些凭证/权限可用？已知哪些网段？
4. 下一步ROI最高的操作？OPSEC风险？
5. 当前scoreboard得分？还有哪些critical/high目标没拿？
6. 源码获取状态？审计是否有产出？

### Step 2: 知识卡加载

按当前阶段从 `knowledge-routing.yaml` 加载。Web分支可加载appsec知识卡，AD分支加载redteam知识卡。

### Step 3: 执行（主Agent或Worker）

**主Agent亲自做**：阶段推进决策 | OPSEC敏感操作 | 链式攻击
**Spawn Worker做**：独立目标测试 | 独立RCE向量探测 | 内网服务探测

Worker规则：独立 `worker-{id}.json`，发现一律 `pending`，主Agent Merge后写 `findings`。

**Merge流程**（Worker结果回收时）：
1. Worker结果通过`bb merge`合并到blackboard（facts/intents/hints追加，findings按id更新）
2. `intent validate` — evidence_refs必须引用已有facts
3. `bb observe` — 检测矛盾/盲点/陈旧/孤立fact/重复失败，有问题记入decision_log处理
4. `bb plan` — 根据黑板变更自动建议下一步action，按priority执行
5. 验证门：基础门（所有发现必过）→ High/Critical需Grounding+Negation

**失败归因**：L1工具错→修正 | L2凭证失效→刷新 | L3被WAF拦→bypass | L4路径不通→新路径 | L5阶段阻塞→请求协助（L3×3→升L5）

### Step 4: 阶段推进判断

推进门满足 → 加载下一阶段 → 更新 `meta.current_stage` → 继续
不满足 → 继续当前阶段
连续3轮无进展 → 方向切换或请求协助

---

## OPSEC 评估矩阵

| 风险 | 操作类型 | 处理 |
|------|---------|------|
| 低 | 被动收集/DNS/证书/单次curl/JS审计 | 直接执行 |
| 中 | 目录探测/Tier 1批量检测/端口扫描 | 限速执行，标注风险 |
| 高 | 批量扫描/工具上传/持久化/DCSync | 需用户确认 |

## 方向切换

**触发**：当前路径3轮无进展 / 被WAF阻断 / 发现更优路径
**策略**：
1. Web分支：切换Tier（如Tier 1无果→Tier 2手工测试→Tier 3链式）
2. AD分支：检查未用凭证 / 其他入口 / 加载evasion知识卡
3. K8s分支：换入口向量（面板→API→kubelet→etcd）/ 换Pod / 检查表未过的逃逸项
4. 跨分支：Web发现内网入口→切AD | Web发现容器特征→切K8s | AD/K8s发现新Web应用→切Web
5. 最后请求用户协助

## Compact恢复步骤

1. Read redteam-blackboard.json
2. `meta.current_stage` → 当前阶段（W1-W4 / A1-A5 / K1-K4），`meta.branch` → 当前分支
3. `objectives[]` → 各目标达成状态，找到status=in_progress和blocked的
4. `assets` + `credentials` + `network` → 已控资产、凭证和已知网段
5. `attack_path` → 完整攻击路径
6. `source_intel[]` → 源码获取和审计状态
7. `scoreboard` → 当前得分，对照objectives看还差什么
8. `decision_log` 最后一条 → 态势和策略
9. 查攻击路径：`node shared/state/redteam-state.mjs path show`
10. 继续执行