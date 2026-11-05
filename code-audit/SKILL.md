---
name: code-audit
description: 代码审计/白盒审计/源码审计（code audit/source code review/审计源码）：攻击者视角，拿到源码→建攻击面模型与信任边界→定向猎杀→出 PoC；每个 finding 必须有 PoC 或完整验证方案，不报"疑似"；支持独立审计/配合渗透测试(pentest)/配合 SRC 三种模式。
when_to_use: 代码审计/白盒审计/源码审计/code audit/白盒测试/source code review/审计代码/审计源码
triggers:
  - 代码审计
  - 白盒审计
  - 源码审计
  - code audit
  - 白盒测试
  - source code review
  - 审计代码
  - 审计源码
inputs_required:
  - path: 源码目录路径
inputs_optional:
  - language: 主要语言（自动检测）
  - focus: 指定漏洞类型或模块
  - mode: standalone / pentest / src（默认standalone）
  - target_url: 活目标URL（有则实际验证）
---
> 开工前先跑 pentest-ai-driven Phase 0-0 自检。

# 白盒代码审计

攻击者视角。先理解，再猎杀。没有PoC的发现不算发现。

## 核心原则

1. **先理解再动手** — 不盲grep sink，先建架构模型再定向hunting
2. **No PoC No Finding** — 每个漏洞必须有验证方案或实际PoC
3. **零硬依赖** — Grep/Read/Glob就能跑，CodeGraphContext有就增强
4. **知识卡按需加载** — Phase 1识别技术栈后只加载对应语言/框架知识卡
5. **一次一模块** — 不试图一遍审完整个项目，按攻击面优先级逐模块推进

---

## Phase 0: 启动

1. **源码路径确认** — 检查目录存在、识别代码结构
2. **技术栈自动检测**:
   - 包管理文件: `pom.xml`/`build.gradle`(Java), `package.json`(JS/TS), `requirements.txt`/`pyproject.toml`(Python), `composer.json`(PHP), `go.mod`(Go)
   - 框架特征: Spring注解、Express路由、Django settings、Laravel配置
3. **审计模式确认**（AskUserQuestion选项）:
   - `standalone` — 纯代码审计，独立出报告
   - `pentest` — 配合pentest-ai-driven，输出验证清单注入测试队列
   - `src` — 配合vuln-hunting，聚焦高价值可利用漏洞
4. **活目标确认** — 有URL则Phase 4实际验证，无则给验证方案
5. **工具确认** — 有活目标时按CLAUDE.md§1.6确认Burp/Playwright
6. **范围确认**:
   - 全量 / 指定模块 / 指定漏洞类型
   - 代码量>15k行 → 建议聚焦高风险模块
7. **加载知识卡** — 根据检测到的语言/框架，从`references/`加载对应知识卡

### 输出目录

审计产物统一放项目temp目录（按CLAUDE.md§1.10），包括:
- `_audit_context.md` — 攻击面+架构理解
- `_findings.md` — 已确认漏洞
- `_verify_checklist.md` — 黑盒验证清单（pentest/src模式）

---

## Phase 1: 攻击面映射

快速扫描（10分钟级），画出"外部输入从哪里进、到哪里去"。

### 1.1 入口点发现

按框架搜索路由/Handler定义:

| 框架 | 搜索模式 |
|------|---------|
| Spring | `@RequestMapping` `@GetMapping` `@PostMapping` `@PutMapping` `@DeleteMapping` `@RestController` |
| Express/Koa | `router.get` `router.post` `app.get` `app.post` |
| Flask/FastAPI | `@app.route` `@router.get` `@router.post` |
| Django | `urlpatterns` `path(` `re_path(` |
| Laravel | `Route::get` `Route::post` `Route::resource` |
| PHP原生 | `$_GET` `$_POST` `$_REQUEST` `$_FILES` |
| Go Gin/Echo | `r.GET` `r.POST` `e.GET` `e.POST` |
| GraphQL | `type Query` `type Mutation` schema定义 |

同时搜索: API文档文件（swagger/openapi yaml/json）、WebSocket handler、定时任务、消息队列消费者。

### 1.2 高价值标记

在入口点基础上，Grep搜索以下模式并标记:

| 标记 | 搜索什么 |
|------|---------|
| `[DB]` | 原生SQL拼接、`${}` in MyBatis XML、`raw()`/`execute()`直接调用 |
| `[CMD]` | `Runtime.exec` `ProcessBuilder` `os.system` `subprocess` `child_process` `exec(` |
| `[FILE]` | 文件上传处理、`new File(` `open(` `fs.readFile` + 用户输入拼接 |
| `[DESER]` | `ObjectInputStream` `XMLDecoder` `pickle.loads` `yaml.load` `unserialize` |
| `[SSRF]` | HTTP客户端调用中包含变量的URL参数 |
| `[TMPL]` | 模板渲染中使用非转义输出、`render_template_string` `Velocity` `Freemarker` |
| `[AUTH]` | 鉴权相关: 登录逻辑、JWT处理、Session管理、OAuth配置 |
| `[CRYPTO]` | 加密/哈希: 弱算法(MD5/SHA1用于密码)、硬编码密钥 |

### 1.3 防护机制识别

- 全局过滤器/拦截器（WAF、XSS filter、SQL filter）
- ORM使用率（全ORM vs 混用原生SQL）
- 参数校验框架（@Valid、joi、marshmallow）
- CSP/CORS配置
- 鉴权模型（注解式/中间件式/手动检查/无）

### 1.4 Phase 1 产出

攻击面清单写入 `_audit_context.md` 第一部分:

```markdown
# 攻击面映射

## 技术栈
Java 17 / Spring Boot 3.x / MyBatis / MySQL

## 入口点清单 (共N个)
| # | 方法 | URL | Handler | 标记 | 鉴权 |
|---|------|-----|---------|------|------|
| 1 | POST | /api/user/upload | FileController:upload | [FILE] | @RequireLogin |
| 2 | GET | /api/report/export | ReportController:export | [DB][FILE] | 无 |
...

## 高价值目标 (优先审计)
1. ReportController:export — [DB][FILE]且无鉴权
2. FileController:upload — 文件上传，需查后缀校验
...

## 防护概况
- 全局: SpringSecurity + 自定义AuthInterceptor（拦截/api/**，白名单/api/public/**）
- SQL: MyBatis为主，3处原生JDBC
- XSS: 无全局过滤器
- 文件上传: 后缀白名单校验（待确认是否可绕过）
```

---

## Phase 2: 架构理解

对Phase 1标记的高价值区域做深度分析。**不报漏洞，纯粹建立理解。**

只分析Phase 1标记了高价值点的模块，CRUD getter/setter跳过。

### 对每个高价值模块分析:

1. **信任边界**
   - 哪些输入被当作可信（session里的userId vs URL参数中的id）
   - 哪些数据经过了校验、哪些直接使用
   - 鉴权发生在哪一层（Controller/Service/DAO）

2. **数据流追踪**
   - 用户输入 → 校验/转换 → 业务处理 → 危险操作的完整路径
   - Read实际代码，不靠猜测

3. **防护有效性**
   - 过滤是黑名单还是白名单
   - 有没有遗漏的绕过路径（编码、大小写、双写、截断）
   - 校验是在前端还是后端，是否可绕过

4. **鉴权覆盖**
   - 哪些接口漏掉了鉴权注解/中间件
   - 鉴权逻辑本身有没有缺陷（JWT算法混淆、越权检查缺失）

### Phase 2 产出

追加到 `_audit_context.md`:

```markdown
# 架构理解

## 模块: ReportController
### 信任边界
- reportId从URL参数取，无owner校验 → IDOR候选
- userId从session取 → 可信
### 数据流
- GET /api/report/export?reportId=123
  → ReportService.export(reportId)
  → ReportMapper.selectById(reportId)  ← 参数化，SQLi安全
  → 结果写入临时文件 → 返回FileInputStream
  → 文件路径: /tmp/report_{reportId}.xlsx ← reportId拼入路径，但已是整数
### 防护分析
- 无鉴权注解，不在AuthInterceptor白名单中（应被拦截？需验证）
- reportId虽拼入路径但类型为Long，路径穿越不可行
### 攻击假设
- 如果AuthInterceptor配置有误，此接口可未登录访问
- reportId无owner校验，任意用户可导出他人报告（IDOR）
```

---

## Phase 3: 定向猎杀

基于Phase 2的理解，**按优先级逐类型hunting**。

### 猎杀优先级

| P | 类型 | 审计策略 |
|---|------|---------|
| P0 | RCE链 | 反序列化gadget、SSTI、表达式注入(SpEL/OGNL/EL)、命令拼接 |
| P0 | SQLi | 绕ORM的原生SQL、动态表名/列名、MyBatis `${}`、存储过程 |
| P1 | 文件操作 | 上传→执行链(后缀校验绕过+存储路径+是否可访问)、路径穿越、文件包含 |
| P1 | SSRF | URL参数→外部请求、协议限制、内网段过滤 |
| P1 | 认证绕过 | 硬编码凭证、JWT弱密钥/算法混淆、Session固定、OAuth配置 |
| P2 | 越权 | IDOR(对象引用不带owner校验)、水平/垂直越权 |
| P2 | XSS | 存储型优先、模板引擎转义配置、富文本处理 |
| P3 | 信息泄露 | 报错信息、日志记录敏感数据、调试接口、Actuator/Swagger暴露 |
| P3 | 逻辑漏洞 | 竞态条件、整数溢出、业务流程绕过 |

### 每个疑似点的审计步骤

```
1. Source确认 — 用户可控输入来自哪里
2. Sink确认 — 到达什么危险操作
3. 数据流完整性 — Source→Sink路径中间经过什么
4. 防护检查 — 有没有有效的过滤/校验/参数化
5. 绕过评估 — 防护能否绕过（编码/截断/大小写/逻辑缺陷）
6. 判定:
   - 无防护且链完整 → confirmed，进Phase 4
   - 有防护但可绕过 → confirmed，记录绕过方式，进Phase 4
   - 有防护且暂时无法绕过 → 标记为potential，记录原因，不入最终报告
   - 链不完整 → 放弃
```

### 语言/框架特有模式

审计时加载对应知识卡（`references/languages/`和`references/frameworks/`），覆盖:
- 语言特有危险函数和利用方式
- 框架特有配置缺陷
- 已知gadget chain和利用链
- 版本相关漏洞模式

---

## Phase 4: PoC + 输出

### 有活目标

实际构造请求验证:
- 走Burp代理（replay.py/curl）或Playwright浏览器
- 遵循AGENTS.md数据量限制（SQLi≤3条、越权≤5组等）
- 只读命令验证RCE（whoami/id/ipconfig）
- XSS用console.log不用alert

### 无活目标

给出完整验证方案（接口+参数+payload+预期响应），标注"未验证"。

### Finding输出格式

```markdown
### [Critical/High/Medium/Low] 漏洞类型 — 简述

**位置**: `文件路径:行号` → `函数名`
**Source**: 用户输入来源（URL参数/请求体/Header/Cookie）
**Sink**: 危险函数调用
**数据流**: Source → [中间节点] → Sink
**防护分析**: 无防护 / 有XX防护但可通过YY绕过
**PoC**:
  ```bash
  curl -sk 'https://target/api/report/export?reportId=OTHER_USER_ID' \
    -H 'Cookie: SESSION=attacker_session'
  ```
  响应: 200 + 他人报告内容
**影响**: 任意用户报告导出（水平越权）
```

### 联动输出（pentest/src模式）

生成 `_verify_checklist.md`:

```markdown
# 黑盒验证清单

| # | 漏洞类型 | 接口 | 参数 | payload | 预期 | 状态 |
|---|---------|------|------|---------|------|------|
| 1 | IDOR | GET /api/report/export | reportId | 其他用户ID | 200+他人数据 | 待验证 |
| 2 | SQLi | POST /api/search | keyword | ' AND 1=1-- | 返回差异 | 待验证 |
```

此清单可直接被pentest-ai-driven / vuln-hunting读取并注入测试队列。

---

## 与其他Skill联动

| 场景 | 联动方式 |
|------|---------|
| pentest中发现源码泄露 | pentest → 调用code-audit → 返回验证清单 → pentest继续打 |
| red-team需要Web突破 | red-team stages.md W1 → 调用code-audit → 产出RCE/后台权限线索 |
| vuln-hunting需要深度审计 | vuln-hunting → 调用code-audit → 聚焦高价值链 |
| 独立审计 | 直接出`_findings.md`报告 |

---

## 上下文控制

- 一次聚焦一个模块/漏洞类型，完成后等待指令或继续下一个
- 单文件超500行分块读取（每次100-300行）
- 优先Grep定位再Read最小范围，不整文件读
- Phase 1可并行搜索多个模式，Phase 2/3必须逐模块串行
- 每完成一个Phase，产出写入文件，不依赖上下文记忆

## 注意事项

- 硬编码凭证只记录位置，不输出实际值
- 发现的漏洞如涉及增删改接口，遵循CLAUDE.md§2.2和AGENTS.md对应规则
- pentest/src模式下，AGENTS.md全部规则生效（SQLi≤3条、越权≤5组硬停止等）
- standalone模式不受AGENTS.md约束（客户给的源码包，无活目标）

## 跨Session交接

审计中断时触发`auto-handoff`。恢复时读取`_audit_context.md`和`_findings.md`继续。
