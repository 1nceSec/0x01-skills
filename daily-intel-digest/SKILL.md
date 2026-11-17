---
name: daily-intel-digest
description: 每日安全情报消化流水线（20件/天）：H1数据集有正文报告5篇（附件嵌图）+ H1空正文老报告浏览器抢救5篇 + Medium SRC赏金实战/工具/渗透红队文章10篇。产出后执行**思路反哺**——把新笔记的可迁移思路整合进漏洞挖掘/渗透测试类 skills。定时任务（每天10:00 automation-3fa4983a）与用户手动触发"跑今日情报/跑一轮消化"均走本 skill。
---

# 每日安全情报消化流水线

## 凭证与状态（启动前必读）

1. **凭证**：`E:\Agent\credentials.md`——PLAYWRIGHT_MCP_EXTENSION_TOKEN（Chrome 主用/Edge 备用分档表）、Medium 登录态（Chrome Google OAuth，勿 cookie 注入）、HF 镜像用法。失效按文件内"失效特征"排查；确认轮换则更新该文件，不反复索要。
2. **状态文件**：`E:\RedTeamNotes\漏洞挖掘笔记\HackerOne 报告解读\_processed.json`——`processed`（H1 报告 id，**比较前 str() 归一**）、`medium_done`（已入库 Medium URL）、`focus_order`、`last_run`。
3. **环境**：pyarrow 已装（`E:\Environment\Python312\python.exe -X utf8`，勿用 pandas）；`hackerone-dataset/train.parquet` 本地缓存（缺失则按凭证库 hf-mirror 链接重下）。

## 任务 1：HackerOne 数据集报告解读（5 篇，无浏览器，最先做）

**选题**：focus_order 精确匹配弱点名：`Improper Access Control - Generic` → `Privilege Escalation` → `Business Logic Errors` → `Information Disclosure` → `Cross-site Scripting (XSS) - Generic` → `Improper Authentication - Generic`；顺序取每类未处理中 vote_count 最高、has_bounty?=True、**正文 ≥200 字符**的 1 篇，共 5 篇（每类 1 篇取满 5；类内耗尽取下一名，仍不足全库 vote 降序补足）。

**产出**：`E:\RedTeamNotes\漏洞挖掘笔记\HackerOne 报告解读\<笔记名>\`（同名文件夹 + md + 截图）。

**流程**：
1. `curl -s https://hackerone.com/reports/<id>.json`（HTML 页是 CF 壳，.json 无门槛）→ `attachments[]`：`id`↔正文 `{F<id>}` 占位符、`expiring_url` 约 1h 有效当下下载、`type` 以 `image/` 开头才下 → 存 `<报告id>-<附件id>.<ext>`
2. 笔记骨架：`# 中文标题` → ```url 块（报告链接 + writeup 外链若有）→ `**tags:** #HackerOne #<弱点中文>` → `---` → 四段：**漏洞原理 / 利用条件 / 复现步骤 / 可迁移的挖掘思路**。不写"修复方式"节（猎人视角）
3. 复现步骤按原 `{F<id>}` 语义位置插入 `![[<报告id>-<附件id>.<ext>]]`——**严禁只下载不嵌入**
4. 代码/请求包原样保留，安全术语（IDOR/SSRF/subdomain takeover 等）不译，不增不减
5. id 追加进 processed（str 归一）

参考实现：工作区 `restructure-notes.py`；样例：Shopify邮箱确认绕过（14 图嵌位）/ Apple登录劫持（5 图）。

## 任务 2：空正文老报告浏览器抢救（5 篇）

背景：数据集 30.4% 报告无正文（vote 最高的顶级老报告几乎全在此列），API 无正文但网页端可读。

1. pyarrow 筛：正文 <200 字符、未处理、vote 降序 → 前 5 篇
2. attach Chrome（凭证库 Chrome 档）。失败→确认 Chrome 开着→确认 token 失效则更新凭证库+标注，跳过本任务（不算失败）。hackerone.com 一般无质询；遇质询等 15s 重试一次仍败跳过该篇
3. 逐篇 goto 报告页，sleep 8，提取 `.report-with-metadata-sidebar` innerText（双方 SUMMARY/时间线/赏金/severity/writeup 外链）
4. 笔记：骨架同任务 1，赏金与 severity 写开头引言行（`> vote X，厂商悬赏 $Y，Severity Z`）；writeup 外链进 url 块；无图片不强求；Summary 信息不足不成稿的跳过并记录，不硬凑
5. id 追加 processed

## 任务 3：Medium 文章（10 篇）

**内容范围与优先级（优先级排序而非排除）**：
1. **优先**：SRC 平台（HackerOne/Bugcrowd/Intigriti/YesWeHack）漏洞挖掘拿赏金实战，**带赏金数字优先**（"earned $X" 类）
2. **也收（排后）**：泛安全工具盘点与用法、与 SRC 无关的渗透/红队思路——质量达标即收，优先类不足 10 篇时补足
3. **不收**：新闻/资讯/行业动态/漏洞通告盘点，一律跳过

**质量门禁**：claps/出版物/作者/内容密度；新文 claps≥20 即可，老文≥500 强。

**流程**：
1. attach Chrome（与任务 2 共用连接，勿重复 attach）
2. 采集源优先出版物**自定义域名**（infosecwriteups.com、osintteam.blog、meetcyber.net、systemweakness.com 等——无质询首选）；medium.com 主站仅无质询时用。对照 medium_done 去重
3. 每篇走 medium-reader 全流程：提取（Medium 用 `article` 元素模板）→ 清洗（node 解 JSON 转义去噪，去 Listen/Share/计数器行）→ translate skill 规则翻译 → 入库 `E:\RedTeamNotes\漏洞挖掘笔记\`（SRC 实战按厂商/漏洞类型归目录、工具类入 工具相关/、信息搜集入 信息搜集系列/，目录不存在按主题新建；文件名=H1 概括版；双链只链真实 md）
4. medium_done 追加

## 任务 4：思路反哺（产出后必做，这是流水线的闭环）

全部笔记完成后，**通读今日笔记的"可迁移的挖掘思路"段**，回答一个问题：这些思路能否优化进现有攻防 skills？执行：

1. 列出今日笔记思路清单 → 对照本地 skills（web-vuln-hunting / core-pentest-flow / recon-bugbounty-asset / recon-bugbounty-triage / api-recon / recon-asset-triage / red-team / pentest）
2. 有增量价值的思路（新攻击面、新信号、新 checklist 项）→ **更新对应 skill 的相应章节**（不另开新 skill）；每条更新注明来源（"2026-MM-DD 报告 #<id>"）
3. 无增量则不动——反哺是择优整合，不是机械搬运
4. 简报中列出：反哺了哪些 skill 的哪些章节、依据今日哪篇笔记

## 降级策略（逼近上下文/时间限制）

任务 1 全部保住 → 任务 2 按 vote 降序尽量做 → 任务 3 至少 3 篇 → 任务 4 至少对已产出部分执行。剩余次日顺延（选题按"未处理+排序"天然续跑）。如实汇报完成量。

## 环境生存法则（实测踩坑）

1. medium.com 主站质询随浏览器会话记，重启 Chrome = 清零；出版物自定义域名永远免质询
2. 批量页面读取每篇间隔 ≥8s；Chrome 自动翻译改标题（中文/乱码）无害，按内容 H1 判断
3. playwright 会话断（"not open"）→ 重新 attach，勿重开浏览器
4. Excel/产物落盘：完成一个存一个，勿攒批
5. HackerOne 老报告页面 `.report-with-metadata-sidebar` 选择器可能随改版失效——失败时退化为 `article` 或 body innerText

## 完成后交付（简报）

任务 1 五篇（id/标题/弱点/vote/路径/嵌图数）、任务 2 篇数（id/vote/赏金/路径）及跳过原因、任务 3 篇数（标题/类型[赏金实战|工具|渗透红队]/赏金金额[若有]/路径）及跳过原因、**任务 4 反哺清单（skill 名/更新章节/依据笔记）**、processed 与 medium_done 累计数。

### 质询失败清单（简报必含节，用户 2026-11-17 要求）

**只要本日存在质询绕过失败的篇目，简报必须包含独立的"质询失败"节**——不能只报"任务完成"。格式：

```markdown
## ⚠️ 质询失败待人工（N 篇）
以下文章采集失败，请你在 Chrome 里手动打开并通过质询，然后告诉我"补采"，我立即接管提取：
1. <完整 URL> —— 失败原因（质询/懒渲染）
2. ...
```

失败篇目**不写入** processed/medium_done（保持未处理状态，人工过质询后补采即正常闭环）。若本日零失败，简报明确写"本日无质询失败"。
