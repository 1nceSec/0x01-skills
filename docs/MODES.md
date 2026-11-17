# MODES — 模式口径与本机模式清单

## 什么是"模式"

**模式 = 一套带完整 workflow 的运行预设**：persona（角色/边界/报告纪律）+ 阶段化流程 + Gate 约束 + 状态管理 + Worker 协议 + 配套工具。宿主（ZCode / Claude Code / DSH）只是模式的运行载体，不是模式本身。

## 迁移范围：五个业务模式（全部在本仓库）

| # | 业务模式 | 仓库路径 | 触发词 | 支撑资产 |
|---|---------|---------|--------|---------|
| 1 | **渗透测试** | `core/pentest-flow/`（v8.2） | 渗透测试 / pentest / 安全测试 / 安全评估 | 20+ python 工具（replay.py / scan 系）+ `dicts/` + `playbooks/loop.md` + `references/` + `requirements.txt`；状态 `shared/state/pentest-state.mjs`；黑板 `shared/blackboard-schema.json` |
| 2 | **漏洞挖掘** | `pentest/vuln-hunting/` | 漏洞挖掘 / SRC / 挖洞 / bug bounty | `playbooks/loop.md`；配合 `shared/knowledge/*` 知识卡 |
| 3 | **代码审计** | `audit/code-audit/` | 代码审计 / 白盒 / 源码审计 | `references/frameworks|languages/`（spring/django/express/go…） |
| 4 | **红队评估** | `redteam/killchain/` | 红队 / red team / 攻防演练 | `playbooks/stages.md` + `redteam-blackboard-schema.json`；状态 `shared/state/redteam-state.mjs` |
| 5 | **Benchmark 跑分** | `.system/benchmark-orchestrator/`（v2.1） | benchmark / tsec / 跑分 / ctf benchmark | `worker-prompt.md`（自包含解题策略）+ `knowledge/` CTF 知识卡 + `benchmark-state-schema.json` |

所有模式共用：根部 `AGENTS.md` 安全 Harness（最高准则）+ `governance/` 治理层 + `Skill_Index.md` 路由 + 入口 Skill（`configs/entry-skills/`）。

## 源机器上的其他模式族（参考，不随本仓库迁移）

| 模式族 | 位置 | 与本仓库关系 |
|---|---|---|
| Claude Code 工作区副本 | `E:\Agent\Claude\.claude\skills\`（pentest-ai-driven v8.1 等 16 技能） | 同源**旧版本**（pentest-ai-driven v8.1 < 仓内 pentest-flow v8.2），迁移以本仓库为准 |
| dsh-redteam-model 十模式 | `E:\Agent\0x02_Plugins\dsh-redteam-model\modes\`（redteam/pentest/code-audit/binary-analysis/attack-defense/av-evasion/incident-response/cloud-security/ctf-solver/asset-mapping） | 独立项目（deepseek-harness 插件，自带 LICENSE/node_modules），对应关系：pentest↔pentest、code-audit↔code-audit、ctf-solver↔benchmark-orchestrator（近似），方法论已互相吸收 |
| Trocar 三模式 | `E:\Agent\trocar-harness\modes\`（pentest/hunt/redteam） | 独立轻量仓（Claude Code CLI + Grok Desktop 共用），hunt≈vuln-hunting 口径 |

## Harness 与治理层（非模式，全体共用）

- `AGENTS.md`：授权边界锁死 / HTTP 方法分级 / 验证即止 / 响应熔断 / 全程留痕，测试期间最高准则；
- `governance/`：部署为 `E:\Agent\0x00_Governance\`，浏览器红线等规则的最终权威；
- 入口 Skill：`configs/entry-skills/pentest-SKILL.md`，按任务词路由到五个模式之一。
