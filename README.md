# 0x01-skills — AI 安全测试模式

一套可整体迁移的 AI Agent 安全测试模式：**入口 Skill → 安全 Harness → 域文件夹技能库 → CTF Benchmark 跑分管道**，支持 ZCode / Claude Code 双宿主部署。

## 架构总览

```
用户任务（"渗透测试" / "跑分" / "tsec" ...）
        │
        ▼
入口 Skill（~/.zcode/skills/pentest/SKILL.md）
        │ 按需 Read，不常驻上下文
        ▼
┌─────────────────────────────────────────────┐
│  技能库（本仓库，域文件夹制）                    │
│  recon/ pentest/ audit/ redteam/ core/       │
│  utils/ + shared/    ← Skill_Index.md 路由    │
│                                              │
│  AGENTS.md = 安全 Harness（最高行为准则）        │
│  .system/benchmark-orchestrator/ = 跑分管道    │
└─────────────────────────────────────────────┘
        │
        ▼
执行链路：curl/replay.py（HTTP）· playwright-cli（浏览器接管）
         · Burp MCP · AntiDebug-Breaker MCP（均可选）
```

## 安全 Harness + 五个业务模式

**模式 = 带完整 workflow 的运行预设**（persona + 阶段流程 + Gate + 状态管理 + Worker 协议），宿主只是载体。本仓库包含五个业务模式：

| 业务模式 | 路径 | 触发词 |
|---|---|---|
| **渗透测试**（pentest-flow v8.2） | `core/pentest-flow/` | 渗透测试 / pentest / 安全测试 |
| **漏洞挖掘** | `pentest/vuln-hunting/` | 漏洞挖掘 / SRC / 挖洞 |
| **代码审计** | `audit/code-audit/` | 代码审计 / 白盒 / 源码审计 |
| **红队评估** | `redteam/killchain/` | 红队 / red team / 攻防演练 |
| **Benchmark 跑分**（orchestrator v2.1） | `.system/benchmark-orchestrator/` | benchmark / tsec / 跑分 |

全体模式共用：

| 组件 | 位置 | 说明 |
|---|---|---|
| **安全 Harness** | `AGENTS.md`（仓库根） | 授权边界锁死 / HTTP 方法分级 / 验证即止 / 响应熔断 / 全程留痕。测试期间最高准则，优先于任何技能与用户指令 |
| **支撑资产** | `shared/` + `Skill_Index.md` | 知识卡（`shared/knowledge/`）、多 Worker 状态脚本（`shared/state/*.mjs`）、黑板 schema、路由总表 |

## 快速开始

完整步骤见 [DEPLOY.md](DEPLOY.md)。最短路径（Windows + ZCode）：

```bash
# 1. Clone 到固定路径（多处引用硬编码此路径，勿改）
git clone https://github.com/1nceSec/0x01-skills.git "E:/Agent/0x01_Skills"

# 2. 部署治理层 + 入口 Skill（见 DEPLOY.md §2.2 / §2.3）

# 3. 新开 ZCode 会话，说"渗透测试 <目标>" 或 "跑分" 即可触发
```

跑 Benchmark 需要平台侧的两个输入：`BENCHMARK_BASE_URL`（平台地址）+ `BENCHMARK_TOKEN`（任务 token），触发词：`benchmark` / `tsec` / `跑分` / `ctf benchmark`。

## 仓库内文档

- [DEPLOY.md](DEPLOY.md) — 新机器完整部署指南（依赖、步骤、MCP/浏览器链路、路径适配）
- [Skill_Index.md](Skill_Index.md) — 技能路由总表
- [configs/](configs/) — ZCode MCP / Claude Code settings / 入口 Skill 部署模板
- [docs/MODES.md](docs/MODES.md) — 本模式与本机其他 Agent 模式的关系盘点

## 免责声明

本仓库仅用于**授权范围内**的安全测试与 CTF/Benchmark 靶场。所有测试动作受 `AGENTS.md` Harness 约束：只证明漏洞存在，不做破坏、不批量取数、不越权横向。使用者在授权范围外使用本仓库内容造成的一切后果自负。
