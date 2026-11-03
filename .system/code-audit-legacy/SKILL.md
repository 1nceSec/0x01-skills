---
name: code-audit-legacy
description: >
  白盒代码审计skill。基于CodeGraphContext MCP进行source-to-sink数据流分析，
  自动定位危险函数调用、未校验输入、硬编码凭证等安全问题。
  支持Java/Python/JS/Go/PHP，输出疑似漏洞点+黑盒验证建议。
triggers:
  - 代码审计
  - 白盒审计
  - 源码审计
  - code audit
  - 白盒测试
  - source code
  - 审计代码
inputs_required:
  - path: 代码目录或仓库路径
inputs_optional:
  - language: 主要语言（自动检测）
  - focus: 重点关注的漏洞类型
---

# 白盒代码审计 Skill

## 核心哲学

从代码结构出发，通过数据流追踪定位真实可利用漏洞，而非堆砌误报。

- **Source→Sink追踪**：用户输入从哪进来、经过什么处理、到达什么危险函数
- **最小化误报**：有完整调用链证据才报告，不报"理论上可能"
- **与黑盒联动**：定位漏洞点后输出可用于pentest-ai-driven验证的具体接口+参数

---

## 1. 启动协议

1. **检查 CodeGraphContext MCP 连接**：尝试 `get_repository_stats`，如果连接失败则提醒用户执行 `/mcp` 重连。用户确认无法重连后才切换到降级模式
2. **索引代码**：`watch_directory` 或 `add_code_to_graph` 将目标代码入图
3. **技术栈识别**：`get_repository_stats` 确认语言/框架/依赖
4. **攻击面定位**：识别入口点（Controller/Route/Handler/Servlet）
5. **确认审计范围**：与用户确认重点模块或全量扫描

### 降级模式（CodeGraphContext 不可用时）

CodeGraphContext MCP 连接失败时，退回 Grep/Read/Glob 组合：
- `find_code` → `Grep` 搜索函数名/注解/路由定义
- `analyze_code_relationships` → `Grep` 搜索调用者 + `Read` 追踪调用链
- `find_java_spring_endpoints` → `Grep` 搜索 `@RequestMapping`/`@GetMapping`/`@PostMapping` 等注解
- `find_datasource_nodes` → `Grep` 搜索数据库连接串/配置文件
- `find_dead_code` / `calculate_cyclomatic_complexity` → 跳过，人工判断

降级模式下审计深度受限，在输出中标注"未使用代码图分析，数据流追踪可能不完整"。

---

## 2. 审计流程

### 阶段1：攻击面映射

使用CodeGraphContext工具：
- `find_code` — 搜索路由定义、Controller注解、API endpoint
- `find_java_spring_endpoints` — Spring项目专用endpoint发现
- `find_java_spring_beans` — 识别注入的Service/Repository
- `analyze_code_relationships` — 调用关系图

输出：接口清单（URL + Handler方法 + 参数）

### 阶段2：危险Sink定位

按语言搜索高危函数调用：

| 漏洞类型 | Java Sink | Python Sink | JS/Node Sink |
|---------|-----------|-------------|--------------|
| SQLi | `Statement.execute`, `createQuery`, `jdbcTemplate.query`, `${}` in XML | `cursor.execute(f"`)`, `raw()` | `query(` + 字符串拼接 |
| RCE | `Runtime.exec`, `ProcessBuilder`, `ScriptEngine.eval` | `os.system`, `subprocess`, `eval` | `child_process.exec`, `eval` |
| SSRF | `HttpClient`, `URL.openConnection`, `RestTemplate` | `requests.get(var)`, `urllib` | `axios(var)`, `fetch(var)` |
| 文件操作 | `new File(userInput)`, `FileInputStream` | `open(var)`, `os.path.join(var)` | `fs.readFile(var)` |
| XSS | `response.getWriter().write(var)`, 无转义输出 | `render_template_string` | `innerHTML=`, `dangerouslySetInnerHTML` |
| 反序列化 | `ObjectInputStream.readObject`, `XMLDecoder` | `pickle.loads`, `yaml.load` | `JSON.parse` + prototype |

使用 `find_code` + `execute_cypher_query` 搜索上述模式。

### 阶段3：数据流追踪

对每个发现的Sink点：
1. `analyze_code_relationships` 回溯调用者
2. 确认数据是否来自用户可控输入（Source）
3. 检查中间是否有过滤/转义/参数化处理
4. 无有效防护 → 标记为疑似漏洞

### 阶段4：辅助检查

- `find_dead_code` — 废弃但未删除的危险代码（可能绕过鉴权访问）
- `find_datasource_nodes` — 数据源配置（硬编码密码、连接串泄露）
- `calculate_cyclomatic_complexity` — 高复杂度函数（逻辑漏洞高发区）
- `passive_intel`（如有Burp集成）— 匹配代码中的敏感信息

---

## 3. 输出格式

每个发现输出：

```
### [严重程度] 漏洞类型 — 简述

**位置**：`文件路径:行号` → `函数名`
**Source**：用户输入来源（URL参数/请求体/Header）
**Sink**：危险函数调用
**数据流**：Source → [中间处理] → Sink
**防护缺失**：缺少什么（参数化/转义/白名单）
**黑盒验证建议**：
  - 接口：POST /api/xxx
  - 参数：xxx=payload
  - 预期响应：报错/延时/回显
```

---

## 4. 与pentest-ai-driven联动

审计完成后：
1. 输出"黑盒验证清单"——每个疑似漏洞对应的接口+测试payload
2. 如果当前在渗透测试流程中，自动将验证清单注入测试队列
3. 优先验证 Source→Sink 链完整且无防护的点

---

## 5. 审计优先级

| 优先级 | 审计项 |
|--------|--------|
| P0 | SQL注入、RCE、反序列化、任意文件读写 |
| P1 | SSRF、XXE、权限绕过（鉴权注解缺失）、硬编码凭证 |
| P2 | XSS、CSRF、信息泄露、日志注入、不安全的加密 |
| P3 | 逻辑漏洞（竞态条件、整数溢出、业务绕过） |

---

## 6. 注意事项

- 一次聚焦一个模块/功能，不试图一次审完整个项目
- 超过500行的文件分块读取
- CodeGraphContext 可用时优先用图查询，降级模式下用 Grep/Read
- 发现的硬编码凭证只记录位置，不输出实际值

---

## 跨Session交接

审计中断或session结束时，触发 `auto-handoff` skill 生成交接文档。新session恢复时，重新索引代码目录（`watch_directory`）再继续。
