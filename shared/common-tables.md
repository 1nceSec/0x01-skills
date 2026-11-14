# 共享数据表（pentest-flow / vuln-hunting 通用）

## 🔧 可用工具

**发包**：`replay.py`(主力,--batch/--chain/--diff) | `curl.exe -sk -x http://127.0.0.1:8080`(辅助)
**Burp MCP**：连接时可用 `auth_diff`/`collaborator`/`analyze_*` 等，详见 `shared/references/burp-mcp-tools.md`
**专项脚本**（skill目录下，按需调用）：
- `sqli_detect.py` — SQL注入探测
- `jwt_forge.py` — JWT伪造/弱密钥爆破
- `idor_sweep.py` — IDOR批量枚举
- `ssrf_probe.py` — SSRF探测
- `ssti_detect.py` — SSTI检测
- `path_traverse.py` — 路径遍历
- `rce_fuzz.py` — RCE Fuzz
- `api_crawler.py` — API爬取
- `onescan.py` — 常规敏感路径扫描
- `recon.py` — 侦察辅助

**知识库**：`E:/Agent/0x01_Skills/shared/knowledge/appsec/` 目录下34个漏洞类型模块，按需加载。

## 📋 进站短表（特征→模块映射）

| 目标特征 | 知识模块 |
|---------|---------|
| 有用户体系（注册/登录） | `idor-test.md` + `authbypass-test.md` |
| 有搜索/筛选/查询参数 | `injection-test.md` |
| 有文件上传/STS签名/对象存储 | `file-upload-test.md` |
| 有URL/图片预览/内容请求 | `ssrf-test.md` |
| 有评论/留言/富文本编辑器 | `xss-test.md` |
| 有支付/优惠券/积分/库存 | `logic-test.md` + `race-condition-test.md` |
| 接口返回字段多/详情接口 | `info-leak-test.md` |
| GraphQL接口 | `graphql-test.md` |
| OAuth/JWT/SAML认证 | `oauth-jwt-test.md` |
| WebSocket实时通信 | `websocket-test.md` |
| API网关/微服务 | `api-gateway-test.md` |
| CDN/缓存/Varnish | `cache-poisoning-test.md` |
| AI/LLM/Agent对话 | `agent-tool-exec-test.md` |
| 云IDE/Codex/AI编程台 | `cloud-ide-codex-rce-chain.md` |
| 前后端分离/反代 | `http-smuggling-test.md` |
| WAF拦截（被拦再开） | `waf-bypass.md` |
| Java中间件/反序列化 | `deserialization-test.md` + `jndi-injection-test.md` |
| EL/SpEL/OGNL表达式 | `el-injection-test.md` |
| Node.js后端 | `prototype-pollution-test.md` |
| Host头/密码重置投毒 | `http-host-header-test.md` |
| 路径/下载/文件参数 | `path-traversal-lfi-test.md` |
| XML/文件解析 | `xxe-test.md` |
| 子域名/CNAME异常 | `subdomain-takeover-test.md` |
| 开放重定向参数 | `open-redirect-test.md` |
| PHP弱类型 | `type-juggling-test.md` |
| 源码泄露/.git/.svn | `insecure-scm-test.md` |
| 有状态变更写操作 | `csrf-test.md` |
| 管理后台SPA自定义身份头 | `idor-test.md` |
| 云开发/BaaS/匿名session | `idor-test.md` |
| 开放支付/进件网关 | `idor-test.md` + `authbypass-test.md` |
| 入驻/招商H5 | `idor-test.md` |
| 多租户SaaS平台（共用登录入口） | `authbypass-test.md` + `idor-test.md`（机构缩写字典+用户枚举+申请多权限账号） |
| 登录页直接有账密框但提交走SSO/统一认证（未收敛SSO壳） | `authbypass-test.md`（SSO下第二套隐藏登录口+JWT控制台注入接管） |
| 列表/查询接口请求字段少、返回字段多 | `param-asymmetry-fuzz.md`（字段回拼→隐藏参数→ORDER BY注入） |
| 已知部分接口路径需扩面（list→add/save/delete；upload→uploadImage） | `param-asymmetry-fuzz.md`（联想fuzz+框架字典+404差异+权限绕过变体） |
| 微信小程序（jscode2session / session_key / encryptedData / iv） | `wx-miniprogram-sessionkey-test.md`（三要素伪造手机号任意登录+app.json路由绕过） |
| 有抽奖/答题/盲盒/内置游戏/签到积分 | `logic-test.md` §九（结果参数重置）+ `race-condition-test.md` |
| 有优惠券/会员充值/付费解锁/二维码 | `logic-test.md` §七/§八/§十一（券细分+支付细节+二维码攻击面） |
| 返回401/403 | 先分清：登录页→找业务面；API 403→现场打path/method/头（`param-asymmetry-fuzz.md` §三变体清单） |
| 公网Redis/rsync/FPM/AJP | `info-leak-test.md` + `ssrf-test.md` |

> 知识模块路径：`E:/Agent/0x01_Skills/shared/knowledge/appsec/`。更多：`recon-methodology.md`、`js-reverse-guide.md`、`ghost-bits-cast-test.md`、`打穿短表.md`

## 🔑 打穿短表精华（认A打B）

| 认什么 | 打哪 |
|--------|------|
| STS签名/Policy吃filename | 凭证填`*`/空/`/`，Policy通配覆盖 |
| 密文id + JS有公钥 | 加密相邻数字替换 → 出他人数据 |
| 列表按tenantId过滤 | 租户字段试0/-1/空 → 出他租户 |
| 前端写死appId+appKey | 不登录带钥打业务表 |
| 云开发/SSRF到元数据 | 不登录打元数据 → AK/SK |
| 管理后台SSO壳 | POST默认admin/123456 |
| SSO壳未收敛（首访不跳SSO、本地登录页/接口仍暴露） | 跟进SSO域找第二套登录口 → 参数字典弱口令出JWT → 控制台注入token接管后台 → 多角色用户名碰撞横向接管 → 垂直越权 |
| Node __proto__+EJS/Pug | 污染outputFunctionName → RCE |
| 二维码登录有token | 不登录拿token构造登录URL |
| OAuth白名单有跳转 | 参数转发带出code → 1-click接管 |
| SSRF确认 | → 云元数据(169.254.169.254) → AK/SK → S3列桶 → 内网横向 |
| IDOR确认 | → 批量枚举评估规模 → 垂直越权尝试管理员 |
| SQLi确认 | → 库名/表名证明深度 → 堆叠/写文件/UDF |
| JWT弱密钥确认 | → 伪造admin token → 全管理接口 |
| XSS存储确认 | → Cookie窃取PoC → 管理员后台 → 接管 |
| 上传成功 | → 可访问？→ 可执行？→ RCE？→ STS通配覆盖？ |
| 信息泄露 | → Actuator→heapdump→密码 | Swagger→全接口→逐个测 | .env→凭证 |
| 敏感目录存在(/files/ /upload/) | → 二级枚举(站名缩写+后缀) → 备份包/源码/配置 |
| JS加密调用(CryptoJS/AES/SM4) | → chunk全量覆盖 → 密钥来源追踪 → 解密凭证/伪造请求 |
| 任意文件读 | → /etc/passwd → 配置文件 → 数据库凭证 → 连接DB |
| 未授权接口 | → 枚举同前缀全部接口 → 寻找写操作(POST/PUT/DELETE) |
| 硬编码密钥 | → 搜同类密钥(AWS/OSS/Redis) → 验证每个密钥权限范围 |
| 竞态条件 | → 短信轰炸 → 优惠券叠加 → 0元购 → 余额溢出 |
| 验证码与账号未绑定（A码B用/置空/回显/跳步） | → 任意注册/任意登录/任意改密三连测（一处原理三处出货） |
| 小程序返回包带session_key | → 解密验证key → 改明文手机号重加密 → 任意用户登录/接管后台 |
| 列表接口返回字段多于请求字段 | → 字段回拼 → 自构隐藏排序参数 → ORDER BY注入（预编译盲区） |
| 403绕过成功 | → 路径变体穷举 → Header覆盖 → 方法切换 → 编码填充 |

> 完整打穿短表见 `E:/Agent/0x01_Skills/shared/knowledge/appsec/打穿短表.md`（90+条）

## 📂 Skill 分类总览

| 类别 | Skill | 说明 |
|------|-------|------|
| **安全测试** | `pentest-flow` | OWASP系统化渗透，主力skill，含26个脚本 |
| | `vuln-hunting` | SRC漏洞挖掘，ROI驱动，深度优先 |
| | `killchain` | 红队Kill Chain（Web RCE + AD域控） |
| | `code-audit` | 白盒代码审计 |
| | `mobile-pentest` | 移动端APK/IPA测试 |
| **安全工具** | `arsenal` | 红队武器（免杀/Shellcode/WebShell/C2） |
| | `antidebug-breaker` | 反调试/浏览器hook调试辅助 |
| | `api-recon` | API接口收集，含6个脚本 |
| **资产管理** | `src-asset` | SRC资产收集工具包 |
| | `asset-triage` | 薄弱资产精判/打点筛选 |
| **CTF/靶场** | `benchmark-orchestrator` | 腾讯Benchmark靶场管道调度 |
| **基础设施** | `shared` | 知识库（49篇）+ 数据表 + 状态管理 |
| | `auto-handoff` | 自动交接文档生成 |
| | `report-generator` | 渗透测试报告生成 |
| | `playwright-cli` | 浏览器自动化操作 |

## 🔧 pentest-flow 脚本索引

| 功能 | 脚本 | 用途 |
|------|------|------|
| **发包** | `replay.py` | 主力发包（--batch/--chain/--diff） |
| **侦察** | `recon.py` | 侦察辅助 |
| | `passive_recon.py` | 被动侦察 |
| | `api_crawler.py` | API端点爬取 |
| | `onescan.py` | 敏感路径扫描 |
| | `component_scan.py` | 组件/指纹识别 |
| **注入** | `sqli_detect.py` | SQL注入探测 |
| | `ssti_detect.py` | SSTI检测 |
| | `rce_fuzz.py` | RCE Fuzz |
| | `path_traverse.py` | 路径遍历 |
| | `ssrf_probe.py` | SSRF探测 |
| **越权/认证** | `idor_sweep.py` | IDOR批量枚举 |
| | `cross_auth_bypass.py` | 交叉越权检测 |
| | `jwt_forge.py` | JWT伪造/弱密钥爆破 |
| **分析/生成** | `resp_analyzer.py` | 响应分析 |
| | `backend_compare.py` | 后端差异对比 |
| | `hypothesis_runner.py` | 假设验证执行 |
| | `gen_ai_review.py` | AI辅助审查 |
| | `gen_attack_chains.py` | 攻击链生成 |
| | `gen_deep_queue.py` | 深度队列生成 |
| | `gen_target_report.py` | 目标报告生成 |
| | `aggregate_findings.py` | 发现汇总 |
| **内部辅助** | `_pentest_common.py` | 公共函数库 |
| | `_gate_check.py` | 门禁检查 |
| | `_ai_todo.py` | AI待办管理 |
| | `_ai_verdict_writer.py` | 判定结果写入 |
| | `_deep_queue_advance.py` | 深度队列推进 |
| | `memory.py` | 状态记忆 |
| | `run_all.py` | 批量运行入口 |

## 🗂️ 知识库索引（arsenal + redteam）

> appsec（34篇）已由上方"进站短表"索引，此处不重复。

### arsenal（红队武器）

| 模块 | 路径 |
|------|------|
| 免杀/规避技术 | `redteam/arsenal/SKILL.md` §Step 2 技术选型 |
| Loader设计 | `redteam/arsenal/SKILL.md` §Step 2 + 模板1/2 |
| 进程注入 | `redteam/arsenal/SKILL.md` §Step 2 + 模板3 |

### redteam（红队攻击链）

| 阶段 | 模块 | 路径 |
|------|------|------|
| **侦察** | AD域枚举 | `redteam/recon/ad-domain-enum.md` |
| | Windows工作组 | `redteam/recon/windows-workgroup.md` |
| **利用** | 默认密钥/弱凭证 | `redteam/exploit/crypto-default-keys.md` |
| | Java中间件漏洞 | `redteam/exploit/middleware-java.md` |
| | Web RCE向量 | `redteam/exploit/web-rce-vectors.md` |
| **提权** | Linux提权 | `redteam/privesc/linux.md` |
| | Windows提权 | `redteam/privesc/windows.md` |
| **横向** | 横向移动技术 | `redteam/lateral/techniques.md` |
| **持久化** | 持久化技术 | `redteam/persist/techniques.md` |
| **域攻击** | 委派攻击 | `redteam/ad-attack/delegation.md` |
| | 票据攻击 | `redteam/ad-attack/ticket.md` |

> 知识库根路径：`E:/Agent/0x01_Skills/shared/knowledge/`
