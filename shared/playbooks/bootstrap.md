# Phase 0: Bootstrap（通用，三模式共享）

> 由各 skill 的 SKILL.md 路由加载，仅任务启动时 Read 一次。
> 渗透测试 / 漏洞挖掘 / 红队评估 均从此入口。

## 0-A: 工具与账号确认（针对明确Web资产开测前执行，不得跳过）

> 触发时机：已确定具体Web测试目标后。资产收集（recon-src-asset）和精判（recon-asset-triage）阶段不触发此确认。

**必须**使用 `AskUserQuestion` 依次确认三个问题：

```
AskUserQuestion({
  questions: [
    {
      header: "Burp代理",
      question: "是否使用 Burp 代理？",
      multiSelect: false,
      options: [
        { label: "使用 Burp (Recommended)", description: "replay.py主力 + curl -x proxy辅助，流量过Burp HTTP History" },
        { label: "不使用 Burp", description: "直接curl/Playwright发包，不走代理" }
      ]
    },
    {
      header: "Playwright",
      question: "是否使用 Playwright 浏览器？",
      multiSelect: false,
      options: [
        { label: "使用 Playwright (Recommended)", description: "playwright-ext自动化浏览、功能遍历、JS审计" },
        { label: "不使用 Playwright", description: "纯命令行测试，不启动浏览器" }
      ]
    },
    {
      header: "测试账号",
      question: "是否有登录测试账号？",
      multiSelect: false,
      options: [
        { label: "无测试账号 (Recommended)", description: "未授权视角测试" },
        { label: "有测试账号", description: "有登录凭证，需要提供Cookie或账号密码" }
      ]
    }
  ]
})
```

用户选择后写入黑板 `meta.tools`。说不用的工具**整个任务全程禁用**（含所有Worker）。

## 0-B: 基础侦察

1. Burp启用时：`burp_version` 验证连接 → 提醒用户挂代理访问目标
2. `proxy_history`/`sitemap_query` 提取全部请求头（Host/Cookie/Token/UA/Accept/Origin/Referer一个不少）存基线
3. curl首页 + robots.txt + 常规敏感路径（/swagger /api-docs /actuator /graphql /console /druid）
4. **敏感文件深度枚举**：onescan扫到敏感目录（/files/ /upload/ /backup/等）后，必须做二级枚举（站名缩写+常见后缀）。参见 `info-leak-test.md` §2.0.1
5. JS审计：**全量下载主bundle + 所有chunk分包**（从HTML入口和主bundle提取chunk引用），提取API路径/路由配置/硬编码凭证/加密逻辑/盐/公钥。**发现加密调用后必须追踪密钥来源**（硬编码/环境变量/后端下发），完成完整加密链路分析。混淆JS/加密参数 → `Skill("audit-js-reverse")`。详见 `js_audit_guide.md` §6.0
6. 进站短表对照：Read `shared/common-tables.md`，标记需加载的知识模块

### 0-B.1: 多租户SaaS平台弱口令策略

识别到多租户SaaS平台（多机构共用同一登录入口）时，除通用字典外额外执行：

1. **机构缩写字典生成**：从页面title/favicon/域名/已知机构名提取缩写，生成如 `{机构拼音首字母}` 的用户名字典
2. **用户枚举接口优先利用**：如平台存在用户枚举接口（如 /admin/user/queryPage、/api/user/list），优先用该接口获取真实用户名再针对性做密码喷洒
3. **无账号时主动提醒**：多租户平台无注册功能且无法自行获取凭证时，**必须提醒用户向甲方申请至少两个不同权限等级的测试账号**，否则越权测试无法执行

### 0-B.2: JS审计中baseURL拼接规则

JS审计提取API端点时，必须先定位 `axios.create` 的 `baseURL` 配置，将其作为前缀拼接到所有相对路径上，确保测试的接口地址完整正确。常见模式：

```javascript
// axios.create({ baseURL: '/admin' }) + 相对路径 'user/queryPage'
// → 完整接口: /admin/user/queryPage（不是 /user/queryPage）
```

## 0-C: 初始化黑板

**渗透测试/漏洞挖掘**：Write `blackboard.json`（见 `shared/blackboard-schema.json` 的 init_template），填入：
- `meta`：target / cookie / headers / tools / round=0
- `attack_surfaces`：侦察发现的攻击面
- `intents`：基于攻击面和价值矩阵生成的初始 Intent
- `decision_log`：第一条决策记录

**红队评估**：Write `redteam-blackboard.json`，填入：
- `meta`：target_scope / roe / current_stage=recon / tools
- `assets`：初始目标资产
- `credentials`：已有凭证（如有 initial_access）
- `attack_path`：空
- `decision_log`：第一条决策记录

初始化攻击链和 traces：
```bash
node shared/state/pentest-state.mjs init
```

## 0-D: 功能点测绘与权限基线（多账号越权测试必做）

### a) Playwright自动遍历
- 登录高权限账号 → snapshot → 识别导航结构（侧边栏/Tab/卡片等）
- 提取所有可见菜单/导航项的文本和路由
- 逐个 `browser_navigate` + `browser_network_requests` 抓每页触发的API
- 建立**功能点→接口映射表**
- 退出 → 登录低权限账号 → 同样遍历
- diff两份映射表，标记高权限特有 / 共有 / 低权限特有

### b) 用户交叉验证
- 输出完整功能点清单给用户核对
- 用户告知遗漏 → Playwright补充

### c) 三源合并写入黑板
- Playwright遍历 + JS审计路由 + Burp流量接口，交叉合并去重
- 写入 `permission-diff.md`：每个功能点 + 接口列表 + 高/低权限标记
- 写入黑板 `attack_surfaces`：按功能点分组

### d) 任务分配
- 高权限特有功能 → 越权测试 Intent
- 所有功能点 → 注入/XSS/上传/逻辑等 OWASP 类别测试 Intent
- 低权限凭证逐个访问高权限接口验证越权

## 0-E: 参数持久化

从 Burp 流量提取关键参数（pageId/modelId/funccode/token等），写入 `subapp-params.sh` 复用，不依赖上下文记忆。

## Bootstrap 完成检查

- [ ] 工具确认结果已写入黑板
- [ ] 请求头基线已存（变量或文件）
- [ ] 黑板已初始化（meta + attack_surfaces/assets + intents/attack_path + decision_log）
- [ ] 攻击链已初始化（`pentest-state init`）
- [ ] 多账号时：permission-diff.md 已生成
- [ ] 参数文件已写入
- [ ] coverage checklist已生成（Phase 0.5）

全部通过 → 进入 Phase 1（广度扫描），Read 各 skill 自己的 loop/stages playbook 开始循环。

## 0-F: 生成 Coverage Checklist（Phase 0.5）

> Bootstrap侦察完成后、进入Reason-Act循环前执行。目的：系统化列出所有待测组合，杜绝遗漏。

### 步骤

1. **枚举攻击面**：从黑板 `attack_surfaces` 提取所有接口/页面
2. **匹配漏洞类型**：对每个接口，根据其特征（参数类型/请求方法/功能语义）+ 进站短表，判断适用的漏洞类型
3. **生成coverage矩阵**：写入黑板 `meta.coverage`，每个格子初始状态为 `pending` 或 `skip`（明确不适用的标skip，如纯JSON接口不测反射XSS）
4. **输出checklist给用户确认**：表格形式展示 接口×漏洞类型，标注skip理由，用户可补充/调整
5. **设置phase**：`meta.phase = "breadth"`

### 漏洞类型标识（coverage矩阵列名）

| 标识 | 漏洞类型 | 适用条件 |
|------|----------|----------|
| A_unauth | 未授权访问 | 所有接口 |
| B_idor | 越权/IDOR | 有ID参数的接口 |
| C_sqli | SQL注入 | 有查询/筛选/排序参数 |
| D_xss | XSS | 有输入回显的接口/页面 |
| E_ssrf | SSRF | 有URL/图片/回调参数 |
| F_upload | 文件上传 | 上传接口 |
| G_lfi | 路径遍历/LFI | 有文件路径/文件名参数 |
| H_ssti | SSTI | 有模板渲染的输入点 |
| I_rce | RCE/命令注入 | 有系统命令相关参数 |
| J_logic | 逻辑漏洞 | 支付/优惠券/积分/流程类 |
| K_race | 竞态条件 | 有状态变更的写操作 |
| L_csrf | CSRF | 有状态变更的写操作 |
| M_info | 信息泄露 | 返回字段多/详情接口 |

### skip判定原则

- 纯GET无参接口：只测 A_unauth + M_info，其余skip
- 纯JSON API无HTML回显：D_xss标skip（除非存储型经其他页面回显）
- 无文件参数：F_upload / G_lfi 标skip
- 只读接口：K_race / L_csrf 标skip
