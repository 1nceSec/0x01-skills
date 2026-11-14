---
name: dsh-admin
description: 管理本机 DSH 的插件与 skills：列出/停用/启用/删除/新增 skills（.system 隐藏法），列出/启停 Cordis 插件行，安装/卸载 bundle。用户说"管理插件/skill"、"列出skills"、"列出插件"、"停用/启用/删除某个skill或插件"、"安装/卸载bundle/插件"时调用。
---

# DSH 插件与 Skill 管理

先分清两个体系，别混操作：

| 体系 | 是什么 | 管理方式 |
|---|---|---|
| skills | ponytail、mcp-status 等 32 个目录，纯文件 | 文件操作（见下） |
| Cordis 插件 | profile 里 206 个插件行，几乎全是系统核心 | `plugin_manager` 工具或 GUI 设置→插件 |
| MCP server | burp/yakit/antidebug-breaker/codegraphcontext 共 4 个 | 不归本 skill 管，用 mcp-status skill |

## Skills（文件式）

- 根目录 `E:\Agent\DSH-NEXT\.dsh\skills\`（DSH_HOME，全局对所有工作区生效）；另外还扫项目 `.dsh/skills`、`.agents/skills`、`~/.agents/skills`。
- 一个 skill = 一个目录 + `SKILL.md`；YAML frontmatter 必须含 `name` + `description`；`name` 匹配 `^[a-z0-9]+(-[a-z0-9]+)*$` 且与目录同名；**重名会被覆盖**（新建前先查重）。
- 无 SKILL.md 的目录（如 `shared`）被扫描器忽略，可放共享资源。
- 改动热生效：skills 目录会热刷新，下次模型调用即见变化（2026-10-30 实测：写入 dsh-admin 后当场出现在技能目录）；已注入上下文的 skill 正文不回滚。

常用操作（pwsh）：

```powershell
# 列出全部 skills
Get-ChildItem 'E:\Agent\DSH-NEXT\.dsh\skills' -Directory | Select-Object -ExpandProperty Name

# 停用（非破坏性：扫描器跳过 .system 子目录，2026-10-30 本会话实测+源码双重确认）
Move-Item 'E:\Agent\DSH-NEXT\.dsh\skills\<name>' 'E:\Agent\DSH-NEXT\.dsh\skills\.system\'

# 启用
Move-Item 'E:\Agent\DSH-NEXT\.dsh\skills\.system\<name>' 'E:\Agent\DSH-NEXT\.dsh\skills\'

# 删除（不可逆，先确认）
Remove-Item 'E:\Agent\DSH-NEXT\.dsh\skills\<name>' -Recurse -Force
```

停用/启用即刻生效（目录热刷新），无需新会话。
GUI 管理：设置面板里有「Skills」页（@local/mcp-status-panel 提供），可勾选启停；启停失败或端点不可用时仍按上面命令操作。

## 从技能仓库同步（0x01_Skills → DSH）

- 源仓库 `E:\Agent\0x01_Skills\` 已改为**域文件夹制**（recon/pentest/audit/redteam/core/utils + shared），DSH 扫描器只认一层 → **DSH 端保持平铺**，由脚本展开同步。
- 一键同步（幂等，先清旧名后平铺拷入，并做路径适配 `../../shared/`→`../shared/`，只动渗透技能清单不碰 ponytail 等）：

```bash
bash /e/Agent/0x01_Skills/utils/dsh-admin/scripts/sync-from-repo.sh          # 实跑
bash /e/Agent/0x01_Skills/utils/dsh-admin/scripts/sync-from-repo.sh --dry   # 干跑
```

- 2026-11-13 首次执行完成：20 个 skill 平铺就位（src-asset/asset-triage/bugbounty-*/vuln-hunting/api-recon/mobile-pentest/code-audit/js-reverse/killchain/arsenal/pentest-flow/auto-handoff/report-generator/playwright-cli/mcp-status/dsh-admin/antidebug-breaker/jsreverser-playbook/translate），shared 知识库同步至 `skills/shared/`。
- 2026-11-14 js-reverse + jsreverser-playbook 移除（jsreverser-mcp 已删，工具无关方法论并入 `shared/knowledge/appsec/js-reverse-guide.md`）；同步脚本 OLD 清单自动清理 DSH 端两个目录。

## Cordis 插件（plugin_manager 工具）

需要 Full access 权限或逐次审批；**改动影响整个 profile 的所有会话**。

- `list_plugins`：列出全部插件行（看 `enabled` 字段）；`list_bundles`：列出已安装 bundle。
- `set_plugin` / `set_bundle`：启停一行（entry id 形如 `include:xxx`）；返回 `overridden` 表示被更高优先级层压住，需改对应层。
- `install_bundle`：target 传工作区里 bundle 包目录的**绝对路径**（package.json + cordis.patch.yml + 资源）；`remove_bundle` 卸载。
- `list_bundles` 全景：`availability=profile` 且 `installed=true` 是已装 bundle（当前 7 个：dsh-ui-appearance、dsh-mcp-connector、@local/mcp-status-panel（源码链接自 E:\Agent\DSH-Work\mcp-status-panel）、experimental-terminal / session-search / inspector-profile / agent-team-profile，均可启停/卸载；更新 @local 包 = 直接改工作区源文件 + 重启，链接目录无需 reinstall）；`availability=installation` 是可装未装的官方/实验 bundle；`dsh-base`/`dsh-web-app` 是核心底座，勿动。
- ⚠️ `readOnlyReason: management-required` 的行是系统核心（llm/session/agent/web-ui 等），不要动；`enabled: false` 的行多为按条件启用的工具/实验特性行，属正常状态，不是残留问题。
- 写新 bundle 的模板与流程参考 cordis-plugin-development skill；**不要手改 profile 的 package.json / cordis.patch.yml**。
- GUI 侧入口：设置 → 插件（ui-plugin-manager / ui-settings-plugins 面板）。

## 4 个 MCP server（不在此管）

配置在 `E:\Agent\DSH-NEXT\.dsh\profiles\desktop\cordis.patch.yml` 尾部 insert 列表（burp/yakit 走 mcp-proxy 桥）；连接状态检查与修复用 mcp-status skill。
