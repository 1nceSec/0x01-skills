# MODES — 本模式与本机其他 Agent 模式的关系

源机器（2026-11-17 盘点）共 5 套 Agent 模式，本仓库是其中 **ZCode 模式**的本体，同时是所有模式共享的方法论源头。

| # | 模式 | 宿主 | 技能库 / Harness 位置 | Benchmark 链路 |
|---|------|------|----------------------|----------------|
| 1 | **ZCode 模式（本仓库）** | ZCode Desktop | 入口 `~/.zcode/skills/pentest` → `E:\Agent\0x01_Skills`（域文件夹制）+ 根部 `AGENTS.md` Harness + `E:\Agent\0x00_Governance` 治理层 | ✅ `.system/benchmark-orchestrator` |
| 2 | Claude Code 模式 | Claude Code CLI，工作区 `E:\Agent\Claude` | `<workspace>/.claude/skills/`（16 技能平铺旧命名）+ 工作区 AGENTS.md（SFSRC 规范） | ✅ 同一份 orchestrator 副本 |
| 3 | DSH NEXT 模式 | DSH NEXT（Electron GUI 宿主） | `<app>/.dsh/skills/`（同源旧命名），cordis.patch.yml 接 4 个 MCP | ✅ 副本 |
| 4 | Trocar 模式 | Claude Code CLI + Grok Desktop 共用 | `E:\Agent\trocar-harness\`（pentest/hunt/redteam 三 mode + rules/boundaries） | ❌ 独立方法论仓 |
| 5 | Agents Anywhere | Electron 宿主 app | 无自有技能库 | ❌ |

## 关键事实

- **benchmark-orchestrator 三副本（ZCode / Claude Code / DSH）逐字节一致**（diff 验证），本仓库 `.system/benchmark-orchestrator/` 为 canonical，已做跨宿主可移植化（模板路径改为相对本文件目录，WORK_DIR 参数化为当前工作目录）。
- CC 模式部署：把 `.system/benchmark-orchestrator` 复制到 `<workspace>/.claude/skills/` 即可（DEPLOY.md §4）。
- 各模式的 `SKILL.md` 内容同源（api-recon / arsenal / vuln-hunting / killchain 等同名技能），域文件夹制（本仓库）为最新版；DSH 侧为旧平铺命名。
- 本仓库不包含：各宿主 app 本体、Burp / AntiDebug_Breaker-Agent 软件、`E:\Agent\SRC` 靶场工作产物、账号凭据。
