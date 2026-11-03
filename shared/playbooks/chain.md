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
2. 每步执行前过 AGENTS.md 门禁（删除类禁止、数据量限制等）
3. 执行结果记录 trace：`pentest-state trace write main '{"chain_step":"<id>","result":"..."}'`
4. 成功 → `chain done <id>` → 检查是否解锁下游
5. 失败 → 不标记done，写入 failure_records，考虑替代路径
6. 替代路径：同一个 yields 目标可以有多条路径，任一成功即解锁下游

### 常见攻击链模式

| 链路 | 步骤 |
|---|---|
| SSRF→云 | 发现SSRF → 打元数据(169.254.169.254) → 获取AKSK → 列S3桶 |
| SQLi→提权 | 注入点 → 读用户表 → 管理员凭据 → 后台RCE |
| IDOR→接管 | 越权读 → 获取他人token/密码重置链接 → 账户接管 |
| 上传→RCE | 上传绕过 → WebShell落地 → 命令执行 |
| JWT→伪造 | 弱密钥/alg:none → 伪造管理员token → 全功能越权 |

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
