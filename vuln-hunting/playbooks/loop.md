# Phase 1-N: Reason-Act 循环（SRC深度模式 — 两阶段制）

> 本文件由 SKILL.md 路由加载，每轮循环 Read 一次。
> 核心差异：ROI驱动、保守spawn、P3以下不报、链式升级是终点。
> Phase 1 广度扫描 → Phase 2 深度攻坚，由 `meta.phase` 控制。

---

## 阶段切换逻辑

- **`meta.phase = "breadth"`**：执行广度扫描（快速探测所有格子）
- **`meta.phase = "depth"`**：执行深度攻坚（打blocked/interesting，链式升级）
- **切换条件**：coverage矩阵中所有格子都不是 `pending` → 输出广度摘要 → 设 `meta.phase = "depth"`
- **终止条件**：Phase 2完成后无 `pending/blocked/interesting` → 终止评估

---

## Phase 1: 广度扫描

> 目标：所有接口×所有适用漏洞类型快速探测。每格≤2次请求。

### Step 1: Coordinator选格

```bash
node shared/state/pentest-state.mjs coverage stats   # → JSON: phase, total, pending, blocked, interesting...
node shared/state/pentest-state.mjs coverage next    # → JSON: url, vuln_type, method, params
```

- `coverage next` 返回 `done:true` → 切换Phase 2
- **每轮简报**：`已测X格 / 共Y格，发现Z个，阻断W个，待深入V个`

### Step 2: 快速探测

1. 标准探针（见AI战术参考），每格≤2次请求
2. **增删改操作：按CLAUDE.md §2.2执行，SRC模式尽量不用增删改**
3. 标记状态：tested / finding / blocked(记WAF特征) / interesting(记迹象) / skip

### Step 3: Auto Fact提取 + 记录

- Header/Body/Status扫描，新端点回填coverage矩阵
- 发现漏洞 → 过基础门 → findings-confirmed.md
- Worker每次curl后提取facts（客观现象）和intents（攻击假设，必须附evidence_refs引用fact id），写入worker-{id}.json

### Step 4: Spawn决策（广度阶段，SRC保守）

SRC广度阶段也保守spawn，需同时满足：
1. >=2个独立攻击面
2. 至少一个面已有初步结果
3. 同时≤2个Worker

→ 回到 Step 1，直到无pending

### 广度完成 → 输出摘要

```
## 广度扫描完成
- 总计：X格（tested:N / finding:N / blocked:N / interesting:N / skip:N）
- blocked列表：[接口×类型, 拦截特征]
- interesting列表：[接口×类型, 迹象描述]
即将进入深度攻坚。
```

---

## Phase 2: 深度攻坚（SRC核心阶段）

> SRC模式的核心价值在这里：对blocked/interesting做深度bypass和链式升级。

### Step 1: Coordinator选格 + ROI评估

```bash
node shared/state/pentest-state.mjs coverage next    # → JSON: url, vuln_type, status, note, remaining
node shared/state/pentest-state.mjs slice <url> <vuln_type>  # → 仅该格相关context
```

对`coverage next`返回的格子做ROI评分：

| 因子 | 1分 | 2分 | 3分 |
|------|-----|-----|-----|
| **Impact** | 中危 | 高危 | 严重 |
| **Confidence** | 盲猜 | 有迹象(interesting) | 强指标(blocked但有泄露) |
| **Effort** | 链式多步 | 多请求bypass | 一两个变体 |

**ROI = Impact × Confidence ÷ Effort**
- ROI ≥ 3 → 立即深挖
- ROI 1.5~3 → 无更高时执行
- ROI < 1.5 → 低优先

**每轮必答三问**：
1. slice返回了哪些信号？（related findings(含confidence)/facts/intents/hints/failures/同类型状态）
2. 哪个最可能突破？ROI=?
3. 需要加载哪个知识模块？

### Step 2: 深度执行

1. 选ROI最高的 blocked/interesting 格子
2. **加载知识模块**：blocked(WAF)→waf-bypass.md，其余→对应xxx-test.md
3. 系统性尝试bypass/深入验证
4. **止损**：单格≤5种不同手法无突破 → `parked`
5. 突破 → `finding`，**必须查打穿短表触发链式升级**（SRC强制）

### Step 3: 链式利用（主Agent亲自做）

- 打穿短表全部链式路径必须尝试
- SSRF→元数据→AKSK→列桶
- SQLi→库名→表名（≤3条数据）
- JWT弱密钥→伪造admin→全管理接口
- XSS存储→console.log PoC

### Step 4: Merge + 验证

1. Worker结果通过`bb merge`合并到blackboard（append-only：facts/intents/hints追加不覆盖，findings按id去重更新，changelog自动记录）
2. **intent校验**：`node shared/state/pentest-state.mjs intent validate` — evidence_refs必须引用已有facts
3. **Observer反思**：`node shared/state/pentest-state.mjs bb observe` — 确定性检测矛盾/盲点/陈旧假设/孤立fact/重复失败，有问题则记入decision_log并处理
4. **事件驱动Plan**：`node shared/state/pentest-state.mjs bb plan` — 根据黑板变更自动建议下一步，按priority执行最高优先级action
5. 验证门：基础门 → 深度三门（High/Critical）
6. 通过 → verified_findings(confidence:confirmed) + findings-confirmed.md
7. 未充分验证 → verified_findings(confidence:suspected, 附suspect_reason)
8. **打穿短表必须触发链式Intent**（SRC不只记录可能性）
9. 更新coverage矩阵、decision_log（含evidence_refs）
10. 攻击链检查：`node shared/state/pentest-state.mjs chain next`
11. 交接检查：round>=8 或spawn>=12 → auto-handoff

→ 回到 Step 1，直到无 blocked/interesting

---

## 验证体系（SRC三门递进）

### 基础门（所有发现必过）
1. 有curl命令 + 完整请求头 + 实际响应？→ 没有=不存在
2. 响应中包含声称的数据（逐字匹配）？
3. 不在严格垃圾洞清单中？
4. 评估严重等级（Critical/High/Medium），**P3以下不报**
5. 影响范围明确？→ "攻击者可以XXX" 或 "暴露了XXX信息"
6. PoC含复现步骤+curl+响应？

### 深度验证（High/Critical必过全部三门）
1. **Grounding**：主Agent亲自重放curl，确认响应中逐字包含关键证据
2. **Negation**：数据是不是当前用户自己的？是不是测试/示例数据？换参数/换账号能否复现？
3. **Interrogation**（SRC核心门）：假设结论是错的——SRC审核员会用什么理由拒绝？
4. **Chain**：查打穿短表，**必须尝试链式升级**

### 声明式提交
只报 `verified_findings` 中的。Worker发现一律先进 `pending_hypotheses` 或写为 suspected finding。
- **confirmed**：完整攻击链 + negation验证 → 入报告
- **suspected**：有迹象但验证不充分 → 附重放命令列清单，用户决定
格式：`FINDING: <severity>|<type>|<endpoint>|<title>|<confidence>`

---

## Compact恢复步骤

```bash
node shared/state/pentest-state.mjs coverage stats    # → 当前阶段+进度
node shared/state/pentest-state.mjs slice             # → 概览（coverage_summary + confirmed/suspected/facts/intents/hints计数）
node shared/state/pentest-state.mjs chain show        # → 攻击链状态
node shared/state/pentest-state.mjs hint list         # → 人工提示
```

根据stats的phase字段继续对应阶段。
