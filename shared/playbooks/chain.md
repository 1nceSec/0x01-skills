# 攻击链管理 + 方向切换（通用，三模式共享）

> 发现可串联漏洞时由 SKILL.md 路由加载，或由 `pentest-state chain next` 返回非空时触发。

## 攻击链 Todolist

攻击链是**带依赖关系的多步利用序列**。每步有前置条件（depends_on）和产出（yields），由 `pentest-state.mjs` 管理状态。

### 操作命令

```bash
# 添加步骤
node shared/state/pentest-state.mjs chain add '{"id":"sqli-user","step":"SQL注入获取用户表","target":"/api/search","depends_on":null,"yields":"user_credentials"}'

# 添加依赖步骤
node shared/state/pentest-state.mjs chain add '{"id":"lateral-admin","step":"用泄露凭据登录管理后台","target":"/admin/login","depends_on":"user_credentials","yields":"admin_session"}'

# 查看下一步（前置已满足的待执行步骤）
node shared/state/pentest-state.mjs chain next

# 标记完成
node shared/state/pentest-state.mjs chain done sqli-user

# 查看全链状态
node shared/state/pentest-state.mjs chain show
```

### 链式利用执行规则

1. **只执行 `chain next` 返回的步骤**——前置未满足的不跳步
2. 每步执行前过 E:/Agent/0x00_Governance/AGENTS.md 门禁（删除类禁止、数据量限制等）
3. 执行结果记录 trace：`pentest-state trace write main '{"chain_step":"<id>","result":"..."}'`
4. 成功 → `chain done <id>` → 检查是否解锁下游
5. 失败 → 不标记done，写入 failure_records，考虑替代路径
6. 替代路径：同一个 yields 目标可以有多条路径，任一成功即解锁下游

### 常见攻击链模式（治理合规口径：证明能力即停，深入利用一律禁止）

> 权威规则 `E:\Agent\0x00_Governance\AGENTS.md`：验证即止 / AK-SK获取即提交不使用 / 禁WebShell / 禁内网与云元数据。下表"链"指**评估可升级路径并写入报告**，不是继续执行。

| 链路 | 证明边界（到此即停） |
|---|---|
| SSRF→云 | 仅回连验证地址(src-ssrf.bytedance.net/ssrf)证明请求能力 → 提交；**禁**内网/云元数据探测，AK/SK若有泄露线索直接写报告由平台验证 |
| SQLi→提权 | 仅版本/库名证明深度 → 提交；**禁**读表/列/数据、堆叠、INTO OUTFILE/UDF |
| IDOR→接管 | 证明读取他人数据能力（累计≤5组）→ 提交；**禁**批量枚举、改密、接管会话 |
| 上传→RCE | 证明文件落地+可访问/可执行能力即停 → 删除验证文件 → 提交；**禁**WebShell/后门/持久化 |
| JWT→伪造 | 证明可伪造签名即停 → 提交；**禁**用伪造token访问管理接口或获取数据 |

发现漏洞后对照上表和打穿短表（Read `shared/common-tables.md`），有匹配就 `chain add`。

---

## 方向切换

### 触发条件
- 当前类别/阶段测完 → 切下一未覆盖类别/阶段
- 同一攻击面连续3轮无新发现 → 换攻击面
- 同一WAF拦截3次（从failure_records统计）
- 主Agent自判重复同一失败模式
- `chain next` 返回空且无pending intents → 需要新方向

### 反思三问（卡死时的系统性诊断）
1. 在用最常见方法吗？→ 越常见越被防
2. 开发者认为不可能的操作在哪？→ 突破口
3. 重复同一失败模式吗？→ 立即换维度

### 四维切换
换身份(角色/匿名/管理员) | 换版本(v1/v2/beta) | 换端(移动/桌面/小程序) | 换方法(HTTP方法/编码/JSON↔XML)

### 剑走偏锋（高价值非常规打法）
- 请求层：方法篡改/走私(CL-TE/TE-CL/H2降级)/Host注入/HTTP2单包攻击
- 认证层：JWT alg:none/RS256→HS256/kid注入/OAuth redirect_uri绕过/SAML签名包装/MFA跳步
- 注入层：二次注入/宽字节/NoSQL $where/SpEL/OGNL/列表筛选OR+total
- 业务层：并发竞争(HTTP/2单包)/负数溢出/流程跳步/券叠加
- 文件层：.htaccess落地/竞争上传/polyglot/Zip Slip/STS通配覆盖
- 新型：SSRF→云元数据→AK/SK | Agent工具真执行→RCE | 原型链污染→模板RCE | 缓存欺骗偷会话页
