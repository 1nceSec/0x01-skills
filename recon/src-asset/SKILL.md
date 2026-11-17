---
name: src-asset
version: 1.0
when_to_use: SRC资产收集/信息收集/资产测绘/打点准备
triggers:
  - SRC
  - 资产收集
  - 信息收集
  - 资产测绘
description: SRC(安全应急响应中心)资产收集六步管道【国内SRC口径】。给定一个SRC官网/公告URL，自动完成：①资产范围解读→②公司清单(股权穿透)→③备案资产(根域名/APP/小程序)→④Web资产(Quake测绘)→⑤指纹识别(TscanPlus)→⑥汇总大表。当用户给出SRC链接并要求"跑一遍/收集资产/按流程走"时使用。
---

# SRC 资产收集六步管道

## 触发与输入

用户提供一个 SRC 的官网/公告 URL（例：`https://src.example.com/...`），
要求按流程收集其资产。全程只读信息收集，仅用于授权测试。

## 启动前（必做）

> **工具包根目录**：`E:\PenTest\0x02_Tools\S_Src\A_AssetCollect\SRC资产收集工具包\`（下文 提示词/ 与 脚本/ 均指此目录下子目录；2026-11-13 自 Claude 工作区迁入）

1. **凭证检查**：`python -X utf8 "E:\PenTest\0x02_Tools\S_Src\A_AssetCollect\SRC资产收集工具包\脚本\00_检查凭证.py"`
   - 已知缺口清单（2026-11-13）：国内链 **Quake Key / 爱企查Cookie / 代理池API**；国外链 amass 各数据源 key（可选）
   - 缺失项：向用户逐项索要（解释见《首次配置_凭证说明.md》），拿到后写入对应文件，**不回显内容**
   - 全部就绪才进入①
2. 确认工作目录结构（输出都落在工作区根目录的 步骤N输出/ 下，一个SRC一套文件）

## 六步编排（详细提示词在 提示词/ 目录，逐步展开执行）

| 步骤 | 做什么 | 关键产物 | 提示词 |
|---|---|---|---|
| ①范围解读 | 浏览SRC公告，提取收录/不收录原文，判定类型（集团型/公司型/域名清单型/混合），输出 scope_json 与人工研判清单 | 步骤①实验_{src}解读结果.md | 提示词/步骤①_资产范围解读.md |
| ②公司名称 | equity_recon 股权穿透（口径来自①：≥50%/全资/双阈值） | 步骤②输出/{src}_单位名称清单.xlsx | 提示词/步骤②_公司名称确认.md |
| ③备案资产 | beian_recon 双遍网站+APP/小程序，公示域名直入，step3_merge 出种子 | 步骤③输出/{src}_备案资产清单.xlsx | 提示词/步骤③_备案信息获取.md |
| ④Web资产 | quake_full_sweep（省积分四约束+SaaS长尾采样策略） | 步骤④输出/{src}_Web资产URL.csv | 提示词/步骤④_Web资产获取.md |
| ⑤指纹识别 | TscanPlus v3.5.0 低频全量（切块+可断点bat；**patched exe 内嵌旧绝对路径 `0x01_SRC_Tools`，config 已自愈可用至 2028**）；**agent 后台会话 TscanPlus 起不来（WebView2 桌面依赖），headless 兜底用 httpx -tech-detect**（GoBin）或请用户桌面跑 bat | 步骤⑤输出/{src}_指纹识别结果.xlsx | 提示词/步骤⑤_指纹识别.md |
| ⑥汇总大表 | 写总览配置json → step6_build_master 合并①-⑤ | 步骤⑥输出/{src}_SRC资产汇总大表.xlsx | 提示词/步骤⑥_汇总大表.md |

## 核心公式（贯穿全程）

- ②单位清单 = 股权穿透树 ∪ SRC点名清单 − 黑名单 − 注销
- ③根域名种子 = ICP反查 ∪ SRC公示 − 黑名单（**公示即收录**，与备案主体无关）
- ①输出的 scope_json（core_entities/股权口径/brand_domains/黑名单）是②-⑥的机器可读输入

## 汇报风格（用户明确要求）

**结论先行**：每步先给结果表/数字，解读放后面；简明，不啰嗦。

## 环境生存法则（多次踩坑换来的，违反必出事）

1. Windows bat 里**用 `ping -n N 127.0.0.1 >nul` 做延时**，`timeout /t` 在本环境静默失效
2. **units/种子等中文文本文件必须 UTF-8 无BOM**——cmd 的 `echo >` 写出的是 GBK，会炸；
   一律用 Python/Node 写文件
3. Python 跑中文脚本统一 `python -X utf8`；多行 python -c 不可靠，写临时 .py 文件
4. 长任务（②③④⑤）一律**后台运行 + 断点续跑**；网络抖动（RemoteDisconnected/DNS失败）常见，
   脚本要有请求级重试 + **每完成一个单元就落盘**（不要攒到最后存）
5. equity_recon 名称搜pid走Bing兜底，可能失败 → 用 WebFetch 搜 `site:aiqicha.baidu.com 公司名`
   拿 pid，手工注入 collect.jsonl 的 search 记录后重跑（注意先清掉 hit:null 的失败记录）
6. beian 官网查询结果有**随机漏检**（同单位两次查询缺的域名不同）→ 网站类必跑双遍（r1/r2）合并
7. Excel 输出被用户打开时写入会 PermissionError → 脚本支持按SRC单独跑，提示关闭后重跑
8. GitHub 直连下载易超时 → 用 `https://gh-proxy.com/` 镜像前缀

## 完成后交付

向用户给出：⑥大表路径 + 各sheet行数、各步骤关键数字（单位数/种子数/资产数/指纹率/积分消耗）、
人工研判清单（存疑项）、以及整个过程中做出的策略决策（如SaaS长尾采样）及依据。
