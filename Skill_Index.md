# 技能域索引（2026-11-13 域文件夹制）
> 规则：**域文件夹/skill 目录**两级制（`recon/src-asset/`），skill name = 目录名（无域前缀，全局唯一）。`shared/` = 共用知识库。
> 变更史：11-09 域前缀一层平铺制 → 11-13 域文件夹制（根目录 21 项 → 7 域文件夹；Claude 端历史部署名即简名，仓库向其对齐）→ 11-14 移除 `js-reverse` / `jsreverser-playbook` 两个 skill 与 jsreverser-mcp（方法论并入 `shared/knowledge/appsec/js-reverse-guide.md`）。

## 各端接入方式（2026-11-13）
- **ZCode**（动态加载）：已删除 config.json 的 `skills.roots` 全局注册（避免全部技能描述常驻每会话上下文）。入口为用户级路由技能 `~/.zcode/skills/pentest/SKILL.md`：触发后按需 Read 本仓库对应 SKILL.md（先读 AGENTS.md Harness）。备份：`config.json.bak-20261113`
- **Claude**：`E:\Agent\Claude\.claude\skills\` 为拷贝入口（需按新名重新同步；旧时代副本 code-audit-legacy / pentest-ai-driven / src-asset-recon 等待清理）
- **DSH**：`E:\Agent\DSH-NEXT\.dsh\skills\` 拷贝入口（需按新名重新同步）
- 文档内 `CLAUDE.md §x.x` 章节引用统一指向 `E:\Agent\Claude\CLAUDE.md`（增删改门禁/上下文控制等编号章节在那里，不在本仓库）
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
| 共用知识库 | `shared/` | appsec/redteam 知识模块 + playbooks + 状态脚本（被各 skill 以 `../../shared/` 引用）；JS逆向触发词路由至 `shared/knowledge/appsec/js-reverse-guide.md` |

> Skill() 调用一律使用上表 skill name（如 `Skill("src-asset")`）；路径引用用 `域/name/`（如 `core/pentest-flow/SKILL.md`）。JS逆向（2026-11-14 起非独立 skill）：按需 Read `shared/knowledge/appsec/js-reverse-guide.md`。
