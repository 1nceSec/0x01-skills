# Hook 输出格式规范

PreToolUse hook 输出必须用 `hookSpecificOutput` 嵌套，不能用顶层字段。

## 正确格式

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "reason shown to user and AI",
    "additionalContext": "injected into AI context as system-reminder"
  }
}
```

## 行为对照

| 操作 | 效果 |
|---|---|
| exit(0) + `permissionDecision: "deny"` | 阻断工具，用户终端看到error，AI看到reason+context |
| exit(0) + 只有 `additionalContext` | 工具正常执行，AI看到system-reminder，用户不可见 |
| exit(2) | 粗暴阻断，hookSpecificOutput被忽略，避免使用 |

## 无效格式（不要用）

- `{continue: false, reason: "..."}` + exit(2) → AI只看到通用 "Execution stopped by hook"
- 顶层 `{permissionDecision, additionalContext}` → 框架不识别
- exit(2) + stderr / exit(0) + stderr → 用户看不到

## 用户可见性

只有 `permissionDecision: "deny"` 产生的error对用户可见。
