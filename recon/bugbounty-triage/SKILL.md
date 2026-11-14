---
name: bugbounty-triage
description: 国外SRC(Bug Bounty)关键/薄弱资产识别筛选定位（asset triage）：输入 bugbounty-asset 产出的资产大表（live_hosts/httpx指纹/端口/JS产物/截图），五类信号分级粗筛→主动验证→AI精判，输出 P0–P3 打点清单。用户要求"精判/筛选关键资产/定位薄弱资产/挑高价值目标/triage"时使用；对标国内 asset-triage。
---

# Bug Bounty（国外 SRC）关键脆弱资产定位管道

## 触发与输入

上游 `bugbounty-asset` ⑥步产出：`live_hosts.txt`（httpx 指纹结果）、`open_ports.txt`、
`js/secrets.txt`、`params/juicy_params.txt`、`screenshots/`。也可独立接收任何含 URL+指纹的资产表。
全程在 program scope 边界内操作。

## 精判框架：五类信号 → 加权 → P0–P3

### 信号 1：高价值端口（命中即 P0 候选）

Web 之外的暴露服务直通管理面/数据面：

```
grep -E ":3000|:4848|:6379|:9200|:9300|:27017|:28017|:2375|:5900|:9000" open_ports.txt
```

端口含义速查：3000 Grafana / 4848 GlassFish / 6379 Redis / 9200-9300 Elasticsearch /
27017-28017 MongoDB / 2375 Docker API（无 TLS=可直接建容器）/ 5900 VNC / 9000 SonarQube-Portainer。

### 信号 2：标题与指纹关键词（面板/中间件）

```
cat httpx_results.txt | grep -iE "jenkins|grafana|kibana|elastic|admin|dashboard|manager|console|phpmyadmin|swagger|graphql"
```

命中即人工优先级队列——Grafana 未授权、Jenkins 脚本执行、Swagger 暴露完整 API 面，都是 critical 常客。

### 信号 3：域名语义（环境与遗忘资产）

```
cat live_subs.txt | grep -iE "dev|uat|stag|test|cache|edge|cdn|internal|vpn|sso|old|legacy|backup|demo" > semantic_hits.txt
```

`cache/edge` 前缀的资产常是"遗忘的基础设施"（缓存层配置松、监控弱）；`dev/stag/uat` 常缺认证。
**泄露情报加权**：曾出现在泄露数据/暗网讨论中的资产（历史泄露 API 域名、旧 jwt_secret 所属系统）
优先级上调——泄露过一次的资产大概率仍存在且弱监控。

### 信号 4：技术栈新鲜度（老旧版本 → 已知 CVE）

httpx `-tech-detect` / WhatWeb 指纹出来后对照版本：

- jQuery < 3.0（XSS，`jQuery.fn.jquery` 控制台一查便知）、老 Apache/Tomcat/PHP、过时 CMS 主题
- 老版本中间件直接对照已知 CVE 清单，命中即 P1 起步

### 信号 5：JS 与参数产物密度

- **ghost JS 最高优先**：`comm -23 <(sort passive_js) <(sort live_js) > historical_only.txt`——
  历史存在、当前线上无引用的 JS，每个都是潜在幽灵端点
- `.map` source map 暴露 = 独立 P2（拿全源码树），`curl -s .../main.js.map | jq '.sources[]'`
- `secrets.txt` 有效密钥命中 = P0
- juicy_params 密度（`redirect=|url=|file=|path=|token=|id=|user=`）高的资产加权；
  历史与当前 JS bundle 端点 diff 出"前端已删后端还在"的端点 = P1

### 分级口径（与国内 asset-triage 对齐）

| 级别 | 判定 |
|---|---|
| **P0** | 有效密钥泄露 / 暴露面板疑似默认凭据 / Docker API 2375 直达 / 高危端口服务无认证 |
| **P1** | 高价值中间件指纹（Jenkins/Grafana/Swagger）+ 版本命中 CVE / 内部 API 端点（/api/v1/admin/*）/ 幽灵端点仍 200 |
| **P2** | dev/stag/uat 语义域名 + 非常规端口 / source map 暴露 / juicy 参数密集 |
| **P3** | 常规资产 → 进周期监控（amass track + 定期 diff），不投入即时人力 |

## 主动验证（scope 允许的主动活动范围内）

1. nuclei 面板/暴露类模板对 P0-P1 候选确认：`nuclei -l p01_targets.txt -t exposures/ -t panels/ -severity medium,high,critical`
2. **视觉侦察**（z0id 方法）：`gowitness report generate` 或 EyeWitness（自动出 HTML 报告）全量截图，P0-P1 候选逐张人工看——截图是"500 个子域里最快锁定登录页/默认安装页/老组件 banner"的手段；z0id 的 grep 流：`cat *.txt | sort -u | grep --color "error"` 对全资产元数据表按关键词过筛
3. 幽灵端点带认证实测（老端点常 200）

## AI 精判（对标国内线 AI 精判步骤）

把 P0-P1 候选清单 + 截图描述 + 指纹 + 端口 + 关联 JS 密钥喂给模型，要求输出：每个资产的
可疑攻击路径假设（如"Grafana 3000 + 版本 x → CVE-xxxx 未授权 RCE 链"）、验证顺序建议、
预期报告严重级。模型结论仅作假设，逐条人工验证后才算确认。

## 反偏方（精判之后是什么——重要哲学）

> Recon 是工具不是宗教。精判的终点是**转人工理解业务**，不是更深的扫描。

90% 时间找资产、10% 理解资产 = 本末倒置。高赏金漏洞（账户接管/业务逻辑/支付绕过）大多藏在
主应用的业务流程里，不在 `test-vault-qa-staging4.internal` 这种深挖子域里。P0-P3 清单的意义
是**决定时间投给哪几个资产**，然后像普通用户一样注册、改邮箱、下单、观察——
"如果我把邮箱改成别人的会怎样"这种问题只有好奇心能问出来，工具问不出来。

## 环境生存法则

1. 端口/grep 立标逻辑写进上游 pipeline（配合 notify/Telegram 实时推送 interesting_ports）
2. 资产与历史结果落 SQLite（或至少带日期的文件），新增资产自动进精判队列：
   `diff old_subs.txt new_subs.txt | grep ">"`；amass 用户直接 `amass track`
3. 新增子域 = 测得最少 = 最脆弱，精判队列永远优先吃 diff 产物

## 完成后交付

P0-P3 打点清单（含每资产的信号依据：端口/指纹/语义/版本/JS 产物五维标注）、
AI 精判的攻击路径假设表、建议的人工验证顺序、以及"转人工理解"的首选 3 个业务流。

## 下游衔接（选好目标开测后）

- **通用手法模块**（国内外通用，直接复用国内线知识库）：
  `shared/knowledge/appsec/param-asymmetry-fuzz.md` — 列表接口字段回拼/隐藏参数/ORDER BY 注入/接口联想 fuzz/鉴权绕过变体（HackerOne 报告同样吃这类发现，payload 通用）
  `shared/knowledge/appsec/logic-test.md` §六~§九 — 验证码族/支付/竞态/游戏结果重置手法层通用；**仅跳过**其国内平台定级规则（条数定级/短信轰炸收录/一洞多交），定级按各平台 policy + VRT
- **产品审计模式（国外同样适用）**：`Skill("code-audit")` product 模式（Phase P）——拿商业产品安装包审计的流程国内外通用；国外出口为 ZDI/厂商 PSIRT/CVE 披露（评级按 CVSS/目标 policy），仅不套用 P.3 的国内 SRC 定级口径
- **不适用国外线**：`wx-miniprogram-sessionkey-test.md`（微信生态）、`core/report-generator/references/src-platform-grading.md`（国内 SRC 定级表）——国外报告按 impact 写作（该文件 §三 的三视角写法可参考，规则表不可套用）

## 对照国内

国内 `asset-triage`：TscanPlus 指纹→信号粗筛→主动验证→AI 精判→P0–P3 打点。
本 skill 为其国外镜像：httpx/WhatWeb 指纹→五类信号粗筛→nuclei/截图验证→AI 精判+业务理解→P0–P3。
差异：国外多"JS/参数产物密度"信号（国外 JS 挖掘生态成熟）；国内多"备案主体关联"信号。

## 方法论来源

- The Ultimate Bug Bounty Recon Guide（wolfsec1337，41KB）——端口立标/juicy_params/通知管道
- Practical JavaScript Recon（wolfsec1337）——ghost JS 优先级/200 选 20 分诊逻辑
- How Dark Web Intelligence Helped Me Prioritize High-Value Targets——泄露资产优先级逻辑
- Why Recon Alone Won't Make You a Top Bug Hunter（cyberhrsh）——"转人工理解"反偏方
