# DEPLOY — 新机器部署指南

> 目标：在新电脑上从零还原完整模式——**五个业务模式**（渗透测试 / 漏洞挖掘 / 代码审计 / 红队评估 / Benchmark 跑分）+ 安全 Harness + 共享支撑资产。
> 模式 = 带完整 workflow 的运行预设（persona + 阶段流程 + Gate + 状态 + Worker 协议），宿主只是载体。
> 主线宿主：**ZCode Desktop**；备选宿主：**Claude Code CLI**（§4）。
> 基准环境（源机器实测）：Windows 10/11 · Node v24 · Python 3.12 · Git。

---

## 1. 前置依赖

| 依赖 | 版本 | 必需性 | 说明 |
|---|---|---|---|
| ZCode Desktop | 最新 | 主线必需 | 登录账号并配置模型（自带浏览器插件体系） |
| Git | 任意较新 | 必需 | clone 本仓库 |
| Node.js | ≥ 20（实测 v24） | 必需 | `shared/state/*.mjs` 状态脚本、antidebug-breaker MCP |
| Python | 3.12 | 必需 | `core/pentest-flow/replay.py` 等工具脚本（用 httpx） |
| playwright-cli | `@playwright/cli@0.1.22` | 推荐 | 浏览器自动化（§2.4） |
| Burp Suite Pro | 任意 | 可选 | burp MCP 上游（§2.5） |
| AntiDebug_Breaker-Agent | 3.x | 可选 | JS 反调试 MCP 上游（§2.5，**不随本仓库分发**） |

## 1.5 五个业务模式 → 仓库路径对照

| 业务模式 | 路径 | 触发词 | 关键支撑资产 |
|---|---|---|---|
| 渗透测试 | `core/pentest-flow/` v8.2 | 渗透测试 / pentest | python 工具链（先 `pip install -r core/pentest-flow/requirements.txt`）+ `shared/state/pentest-state.mjs` |
| 漏洞挖掘 | `pentest/vuln-hunting/` | 漏洞挖掘 / SRC / 挖洞 | `shared/knowledge/` 知识卡 |
| 代码审计 | `audit/code-audit/` | 代码审计 / 白盒 | `references/frameworks|languages/` |
| 红队评估 | `redteam/killchain/` | 红队 / 攻防演练 | `shared/state/redteam-state.mjs` + blackboard schema |
| Benchmark 跑分 | `.system/benchmark-orchestrator/` v2.1 | benchmark / tsec / 跑分 | `worker-prompt.md` + `knowledge/` + `benchmark-state-schema.json`（§3） |

> 五个模式共享 `shared/` 支撑资产与 `Skill_Index.md` 路由——**整个仓库必须完整保留，不能只拷模式目录**。

---

## 2. 部署步骤（ZCode 主线）

### 2.1 Clone 技能库 —— 路径必须一致 ⚠️

入口 Skill、`shared/common-tables.md`、`shared/state/pentest-state.mjs`、`core/pentest-flow/references/report-template.md` 等 ~7 处**硬编码了 `E:\Agent\0x01_Skills`**。新机器是 Windows 时，强烈建议使用完全相同的路径：

```bash
mkdir -p /e/Agent
git clone https://github.com/1nceSec/0x01-skills.git "E:/Agent/0x01_Skills"
```

路径确实放不了 E 盘 → 先完成部署，再按 §5 批量替换。

### 2.2 部署治理层

`utils/playwright-cli/SKILL.md` 等技能将 `E:\Agent\0x00_Governance\AGENTS.md` 引为最终权威：

```bash
mkdir -p /e/Agent/0x00_Governance
cp -r "E:/Agent/0x01_Skills/governance/." "E:/Agent/0x00_Governance/"
```

### 2.3 部署入口 Skill（ZCode 用户级）

```bash
mkdir -p "C:/Users/<你的用户名>/.zcode/skills/pentest"
cp "E:/Agent/0x01_Skills/configs/entry-skills/pentest-SKILL.md" \
   "C:/Users/<你的用户名>/.zcode/skills/pentest/SKILL.md"
```

- 该文件触发词：渗透测试 / pentest / 漏洞挖掘 / SRC / 红队 / 代码审计 等。
- 它负责引导 Agent 先 Read `AGENTS.md`（Harness），再按 `Skill_Index.md` 路由加载具体技能——**入口不常驻上下文，技能按需加载**。

### 2.4 浏览器链路（playwright-cli + 扩展）

```bash
npm install -g @playwright/cli@0.1.22
```

浏览器红线（已写死在入口 Skill 与 `utils/playwright-cli/SKILL.md`）：**只准 attach 接管本机原生浏览器**，禁止临时 user-data-dir / 命令行自启 / 按进程名杀浏览器。

1. 在 Edge（国内目标）/ Chrome（国外目标）安装 Playwright 浏览器桥接扩展；
2. 扩展会生成连接 token，设置环境变量与之一致：
   `PLAYWRIGHT_MCP_EXTENSION_TOKEN=<扩展生成的token>`（源机器默认值已写在两个 SKILL.md 中，扩展 token 不同时同步改这两处）；
3. 用法：`playwright-cli attach --extension=msedge`，会话内命令带 `-s=msedge`，结束 `detach`。

### 2.5 MCP（可选，按需）

ZCode MCP 配置位于 `C:/Users/<用户名>/.zcode/cli/config.json` 的 `mcp.servers`，模板见 [configs/zcode-mcp.template.json](configs/zcode-mcp.template.json)：

- **burp**（SSE）：需要 Burp Suite Pro 装好 MCP 上游并监听 `127.0.0.1:9876`，`Authorization: Bearer <token>` 填 Burp 侧生成的值；
- **antidebug-breaker**（stdio/node）：需要单独安装 AntiDebug_Breaker-Agent（本仓库不含其软件本体），`args` 指向其 `mcp/src/index.js`。

两者都不是跑 Benchmark 的必需项；纯 HTTP（curl / replay.py）+ 浏览器链路已覆盖绝大多数 web 题。

### 2.6 验证部署

新开 ZCode 会话，逐项验证：

1. 说"渗透测试 http://example.com" → Agent 应先 Read `AGENTS.md`，再按任务 Read 对应 SKILL.md；
2. `playwright-cli attach --extension=msedge` 能接管浏览器；
3. 说"跑分"并提供 BENCHMARK_BASE_URL / BENCHMARK_TOKEN → 进入 orchestrator Phase 0。

---

## 3. 跑 Benchmark（TSec / 腾讯靶场）

触发词：`benchmark` / `tsec` / `跑分` / `ctf benchmark` → 加载 `.system/benchmark-orchestrator/SKILL.md`（v2.1）。

**需要提供**：
- `BENCHMARK_BASE_URL`：Benchmark 平台地址
- `BENCHMARK_TOKEN`：跑分任务 token（请求头 `BENCHMARK_TOKEN`）

**管道行为**（无需人工干预）：
1. Phase 0：拉题目列表 → 按 difficulty 分组 → 无条件批量取 hint → 初始化 `benchmark-state.json`；
2. Phase 1-3：Easy(≤15步) → Medium(≤25步) → Hard(≤40步) 三阶段扫荡，最多 3 容器 + 3 Worker 并行，task-notification 驱动补填；
3. Phase 4：Mop Up 回扫 partial/pending/infra_blocked；
4. 终止后 close 所有容器并输出成绩单。上下文压缩后从 `benchmark-state.json` 恢复。

**产物**：当前工作目录 `benchmark/` 下 `benchmark-state.json`、`worker-*.json`。

**安全红线**（内置）：仅限靶场环境；RCE 仅 `whoami` / `id` / `cat flag`；不写真实数据、不做持久化破坏。Harness `AGENTS.md` 的 CONFIG 验证地址（`verification_domain`）为源平台配置，换平台时按其公告修改。

---

## 4. Claude Code 备选部署（五模式全套）

1. 工作区建议沿用 `E:\Agent\Claude\`（或任意目录；orchestrator 的 WORK_DIR 已参数化为"当前会话工作目录/benchmark"）；
2. **同样先整仓 clone 到 `E:\Agent\0x01_Skills`**（五个模式的 SKILL.md 相互引用 `shared/` 支撑资产，仓库必须完整在位）；
3. 把五个模式的技能目录放进 CC 技能注册目录（目录名 = SKILL.md frontmatter 的 name）：
   ```bash
   CC="<CC工作区>/.claude/skills"
   cp -r "E:/Agent/0x01_Skills/core/pentest-flow"            "$CC/pentest-flow"
   cp -r "E:/Agent/0x01_Skills/pentest/vuln-hunting"          "$CC/vuln-hunting"
   cp -r "E:/Agent/0x01_Skills/audit/code-audit"              "$CC/code-audit"
   cp -r "E:/Agent/0x01_Skills/redteam/killchain"             "$CC/killchain"
   cp -r "E:/Agent/0x01_Skills/.system/benchmark-orchestrator" "$CC/benchmark-orchestrator"
   pip install -r "E:/Agent/0x01_Skills/core/pentest-flow/requirements.txt"
   ```
   > 技能正文里引用的 `shared/state/*.mjs`、`shared/knowledge/` 按**仓库路径** Read，不要拷进 .claude/skills（避免两份漂移）。
   > 源机器 CC 工作区里的 `pentest-ai-driven v8.1` 是旧版本，新机一律用仓内 `pentest-flow v8.2`。
4. Harness：把 `AGENTS.md` 放 CC 工作区根（或按你的全局规则挂载）；权限参考 [configs/claude-code-settings.template.json](configs/claude-code-settings.template.json)；
5. 源机器的全局 `E:\Agent\CLAUDE.md`（个人偏好配置）**不随本仓库分发**，按需自建。

---

## 5. 路径适配（放不到 E:\Agent 时）

用相同目录名放到其他盘符/路径后，批量替换硬编码引用：

```bash
cd <新路径>
grep -rl "E:\\\\Agent\\\\0x01_Skills" --include="*.md" --include="*.mjs" . | while read f; do
  sed -i 's/E:\\Agent\\0x01_Skills/<新路径>/g; s|E:/Agent/0x01_Skills|<新路径>|g' "$f"
done
# 入口 Skill（§2.3 复制出去的那份）单独改一遍
# 治理层引用 E:\Agent\0x00_Governance 同理处理
```

已知含硬编码的文件：入口 Skill、`utils/playwright-cli/SKILL.md`（治理权威路径）、`utils/mcp-status/SKILL.md`（另含 DSH 专属路径，非 ZCode 用户可整文件忽略）、`shared/common-tables.md`、`shared/state/pentest-state.mjs`、`core/pentest-flow/references/report-template.md`。

Linux/macOS：除路径替换外，Shell/PowerShell 命令需自行适配；技能中的 curl/python/node 用法本身跨平台。

---

## 6. 本仓库不包含的东西

| 项 | 原因 | 获取 |
|---|---|---|
| AntiDebug_Breaker-Agent 软件本体（51M） | 第三方软件，不宜随仓分发 | 自行安装后配 MCP（§2.5） |
| Burp Suite Pro | 商业软件 | 自购 |
| 源机器全局 CLAUDE.md / ZCode 账号配置 | 个人凭据与偏好 | 新机自行登录/配置 |
| `E:\Agent\SRC`（各靶场工作产物） | 平台专项数据，非模式本体 | 不需要 |
| DSH NEXT / trocar-harness 等其他宿主模式 | 见 docs/MODES.md | 各自独立部署 |
