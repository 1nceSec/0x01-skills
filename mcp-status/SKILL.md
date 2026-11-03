---
name: mcp-status
description: 查询四个 MCP 服务器（burp / antidebug-breaker / codegraphcontext / yakit）的连接状态。当用户问"mcp状态"、"mcp连接情况"、"看下mcp"或怀疑某个 MCP 工具失联时调用。
---

# MCP 连接状态检查

DSH 的 4 个 MCP 服务器通过 `cordis.patch.yml`（`E:\Agent\DSH-NEXT\.dsh\profiles\desktop\cordis.patch.yml`）以内核 mcp-client 方式接入，**GUI 连接器面板不显示它们**（面板只显示连接器注册表体系）。真实状态以"实测工具调用 + 日志"为准。

## 检查流程

### 1. 逐个实测轻量工具（能返回 = 已连接）

| 服务器 | 调用 | 预期 |
|---|---|---|
| burp | `mcp__burp__burp_version` | 返回 Pro 版本号 |
| codegraphcontext | `mcp__codegraphcontext__list_indexed_repositories` | `{"success":true,...}` |
| antidebug-breaker | `mcp__antidebug-breaker__adb_capabilities` | JSON；看 `bridge.connected` 和 `extension.connected` |

注意：两种"已注册但不可用"的形态要区分（2026-10-30 实测）：
- 工具在 schema 中**不存在** → 重试耗尽已被注销（终态）。
- 工具**能调用但瞬间报空错误**（durationMs < 100、error.message 为空）→ burp 的 mcp-proxy 上游 SSE 会话被 Burp 回收（burpmcp-ultra 仅支持 SSE，会话闲置约 30 分钟失效，代理不会自动重建）。按修复手段 2 热重载即可，**无需重启**。

### 2. yakit 特殊处理

yakit 的上游服务不常开。用 PowerShell 检查端口：`netstat -ano | Select-String ':11432.*LISTENING'`。
- 未监听 → yakit MCP 服务没开，桥配置正常，提示用户开启即可
- 已监听但工具不通 → 看日志定位

### 3. 日志佐证（可选，定位失败原因）

```powershell
Get-Content (Get-ChildItem "E:\Agent\DSH-NEXT\.dsh\logs" -Filter "desktop-next*.jsonl" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName -Encoding UTF8 | ForEach-Object { $l = $_ | ConvertFrom-Json; if ($l.source -match 'mcp-client') { "{0} [{1}] {2}" -f $l.time.Substring(11,8), $l.level, $l.message.Substring(0,140) } } | Select-Object -Last 15
```

关注 `giving up after 10 consecutive failed reconnect attempts` = 已注销，需要重载。

## 上游依赖（MCP 层正常但功能不可用时查这里）

| 服务器 | 上游依赖 | 端口 |
|---|---|---|
| burp | Burp Suite Pro 必须开着（BurpMCP-Ultra 扩展） | 9876 |
| antidebug-breaker | 浏览器（Chromium）开着且 AntiDebug 扩展已启用，桥重启后会自动回连 | 19876 |
| codegraphcontext | E:\Environment\Python312 + codegraphcontext 包；KuzuDB 单写者——Claude 侧同款实例不能同时跑 | — |
| yakit | yakit 客户端的 MCP 服务开关 | 11432 |

## 修复手段（按顺序）

1. **上游没开** → 开启 burp / yakit / 浏览器即可，等自动重连
2. **重试耗尽已注销** → 对 `cordis.patch.yml` 里对应条目做**实质性配置变更**（如 `toolCallTimeoutMs: 60000` ↔ `90000`）触发热重载；纯注释修改无效。改完等 15-25 秒再实测
3. **antidebug 显示 EXTENSION_NOT_CONNECTED** → MCP 层正常，浏览器扩展没连；确认浏览器开着、扩展已启用，或重载一次该条目让桥重启
4. 仍失败 → 读日志报错信息（如 KuzuDB 锁 = 有别的 codegraphcontext 进程，`Get-CimInstance Win32_Process -Filter "Name like 'python%'"` 找到并结束它）
