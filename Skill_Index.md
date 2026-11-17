# 技能域索引（2026-11-13 域文件夹制）
> 规则：**域文件夹/skill 目录**两级制（`recon/src-asset/`），skill name = 目录名（无域前缀，全局唯一）。`shared/` = 共用知识库。
> 维护规则（2026-11-15 新增）：**改动任何 .md 文档后必须跑 `node shared/state/check-refs.mjs`**，输出断链即修复——防止 loop.md 式静默断链（曾导致每轮循环方法论丢失）。
> 机械防漏三件套（2026-11-15）：`pentest-state.mjs route check`（情境→知识模块，每轮必跑）/ `pentest-state.mjs gate`（阶段收口门禁，Merge前+写报告前必跑）/ `check-refs.mjs`（文档变更后必跑）。
> 变更史：11-09 域前缀一层平铺制 → 11-13 域文件夹制（根目录 21 项 → 7 域文件夹；Claude 端历史部署名即简名，仓库向其对齐）→ 11-14 移除 `js-reverse` / `jsreverser-playbook` 两个 skill 与 jsreverser-mcp（方法论并入 `shared/knowledge/appsec/js-reverse-guide.md`）。

## 编辑规范（改库必读，2026-11-13 定）
1. **适用范围标注**：每个新增知识/模板必须标注 **国内外通用** vs **仅国内SRC**（平台定级/收录规则/一洞多交/ICP资产证明/微信小程序生态=仅国内；手法与 payload 层=通用）。
2. **红队引用**：killchain 引用知识卡只取利用面/手法，显式排除 SRC 定级规则。
3. **国外线引用**：recon/bugbounty-* 引用通用模块并显式排除仅国内模块。
4. **改后循环自检**：文件存在 / 引用路径真实存在（跑 check-refs.mjs） / 短表路由可达 / 表格闭合 / 无BOM / 版本号 frontmatter+H1 同步 bump。
5. **产品挖掘归属**：AI 通用型产品漏洞挖掘归 **code-audit**（product 模式 + Phase P），不另立新 skill。
6. **改路由先改 `shared/knowledge-routing.yaml`**（唯一机器可读路由源），再同步 common-tables.md 进站短表；coverage 矩阵键必须用规范大类 `A_unauth…M_info`（verify-finding.mjs 验证器键），小类放格子 note。

## 各端接入方式（2026-11-13）
- **ZCode**（动态加载）：已删除 config.json 的 `skills.roots` 全局注册（避免全部技能描述常驻每会话上下文）。入口为用户级路由技能 `~/.zcode/skills/pentest/SKILL.md`：触发后按需 Read 本仓库对应 SKILL.md（先读 AGENTS.md Harness）。备份：`config.json.bak-20261113`
- **Claude**：拷贝入口 `E:\Agent\Claude\.claude\skills\`——**用户已决定不再向 Claude 端同步**（2026-11-13），旧时代副本（code-audit-legacy / pentest-ai-driven / src-asset-recon）仅待清理
- **DSH**：`E:\Agent\DSH-NEXT\.dsh\skills\` 平铺部署入口——**DSH 扫描器只认一层 SKILL.md，域文件夹会被忽略，必须平铺**。同步用 `bash /e/Agent/0x01_Skills/utils/dsh-admin/scripts/sync-from-repo.sh`（幂等，`--dry` 干跑；同步时自动把仓库内 `../../shared/` 引用 sed 适配为 DSH 平铺的 `../shared/`；首次执行 2026-11-13，20 skill 就位）

## 待办与设计定夺（2026-11-15 审计后立项）
- **[立项] api-recon 机械体系**：api-recon 全流程纯 markdown checkbox，无状态/gate 脚本，需独立开发状态管理（对齐 pentest-state 三件套模式）
- **[设计已定] ZCode PreToolUse hook**：工具确认采用**确认制非禁用制**——Phase 0-A 询问、选项默认"不使用"、中途用户明确启用即更新 `meta.tools`；hook 检测到"标记不使用+实际调用"时中断向用户确认，不静默放行/拒绝。拦截模式：`meta.tools.burp=false → mcp__burp__*`；`playwright=false → Bash(playwright-cli*) / Bash(npx playwright*) / Bash(python*playwright*) / mcp__playwright__*`
- **[待定夺] 脱敏口径矛盾**：report-generator"禁止任何形式脱敏/打码/截断（证据完整性）" vs safety-boundaries"截图/导出涉及真实数据时脱敏（数据安全）"——两文件相反，需用户裁决后统一
- **[待做] 课件 P1/P2 优化**（源课件：`E:\PenTest\0x07_Knowledge\T_Training\Y_Yinwu\隐雾SRC` 三期65讲）：verify-finding.mjs 补 SSTI/XXE 命中信号；code-audit 加解密伪造难度分级表；src-asset 三档模式/积分保护
- 文档内 `CLAUDE.md §x.x` 章节引用统一指向 `E:\Agent\Claude\.claude\CLAUDE.md`（真实路径，2026-11-15 修正；增删改门禁/上下文控制等编号章节在那里，不在本仓库）
- MCP：burp(9876 SSE) / antidebug-breaker / yakit —— 前两个已在 ZCode config 注册（jsreverser-mcp 已于 2026-11-14 移除注册并删除本体，其工具无关方法论并入 `shared/knowledge/appsec/js-reverse-guide.md`）

## 技能路由表（域文件夹 → skill name）

| 域文件夹 | skill name | 说明 |
|---|---|---|
| **recon/** 侦察测绘 | `src-asset` | 国内SRC资产收集六步管道 |
| | `asset-triage` | 国内薄弱资产精判 |
| | `bugbounty-asset` | 国外BB资产收集（镜像） |
| | `bugbounty-triage` | 国外BB资产精判（镜像） |
| **pentest/** Web渗透 | `vuln-hunting` | SRC漏洞挖掘（国内），ROI驱动 |
| | `api-recon` | 前端接口侦察 |
| | `mobile-pentest` | 移动端APK/IPA |
| **audit/** 审计逆向 | `code-audit` | 白盒审计（含 product 通用型产品模式） |
| **redteam/** 红队 | `killchain` | 红队评估 Kill Chain 编排器 |
| | `arsenal` | 红队武器开发 |
| **core/** 核心流程 | `pentest-flow` | OWASP 系统化渗透主力 |
| | `auto-handoff` | 跨会话交接 |
| | `report-generator` | 渗透报告/SRC提交单生成 |
| **utils/** 共用工具 | `playwright-cli` / `mcp-status` / `dsh-admin` / `antidebug-breaker` / `translate` | 工具与辅助 |
| 共用知识库 | `shared/` | appsec/redteam 知识模块 + playbooks + 状态脚本（被各 skill 以 `../../shared/` 引用）；JS逆向触发词路由至 `shared/knowledge/appsec/js-reverse-guide.md`；Flag制业务靶场打法沉淀于 `shared/knowledge/appsec/business-lab-flag-range.md` |

> **调用方式（2026-11-15 统一）**：本库技能未注册为 ZCode Skill()，**不存在 `Skill("xxx")` 调用**——跨技能引用一律 `Read E:\Agent\0x01_Skills\<域>/<name>/SKILL.md`（域/name 见上表）。JS逆向（2026-11-14 起非独立 skill）：按需 Read `shared/knowledge/appsec/js-reverse-guide.md`。
