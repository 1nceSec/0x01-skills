# Reason-Act 循环（通用，pentest-flow / vuln-hunting 共享）

> 每轮循环开始时 Read 本文件一次。Bootstrap 后进入循环；Compact 恢复 / 跨 session 恢复后同样从本文件重新进入。
> 模式差异：pentest-flow 广度优先（覆盖>深度），vuln-hunting ROI 深度优先（深度>广度）。差异仅在"选格优先级"，循环骨架完全相同。
> **分层**：本文件 = 通用骨架（态势三问 / route check / RECORD / Merge / gate / 恢复）。pentest-flow 模式下额外 Read `core/pentest-flow/playbooks/loop.md` 获取两阶段制细节（选格 / 标准探针表 / 止损规则 / AI战术参考）。

## 循环骨架

```
REASON（态势判断） → ACT（执行验证） → RECORD（留痕收尾） → 下一轮
```

**每一轮必须完整走完三段，不允许只 ACT 不 RECORD。** 漏 RECORD = 覆盖追踪失真 = 后续轮次重复或遗漏。

## REASON：每轮开头必答态势三问

用脚本回答，不用记忆回答：

```bash
node shared/state/pentest-state.mjs coverage stats   # 问1：我在哪（phase/总格数/各状态计数）
node shared/state/pentest-state.mjs coverage next    # 问2：下一步打哪（pending格/interesting格）
node shared/state/pentest-state.mjs chain next       # 问3：攻击链有无已解锁的可执行步骤
node shared/state/pentest-state.mjs hint list        # 附加：有无人工注入判断
```

**情境信号复核（防知识模块漏加载，每轮必跑）**：

```bash
node shared/state/pentest-state.mjs route check      # 脚本推导本轮应加载的知识模块，输出未加载清单
```

- route check 输出的"未加载模块"必须本轮 Read（路径 `E:\Agent\0x01_Skills\shared\knowledge\<模块路径>`），并把模块 basename 写入黑板 `meta.modules_loaded`
- 速查卡速记（每轮 Reason 前必读一遍）：

```
无PoC≠漏洞 | Self-XSS=不报 | 深度/广度按模式 | 被拦不是终点 | 先读JS再动手
IDOR必须读到他人数据 | Worker发现一律进pending | verified只有主Agent能写
覆盖>深度(pentest-flow) / 深度>广度+ROI驱动(vuln-hunting) | 链式升级是终点 | 系统化是终点
```

## REASON：spawn 决策门

| 模式 | spawn 条件（三条全满足才 spawn） |
|------|--------------------------------|
| pentest-flow | 存在未覆盖OWASP类别 + 有初步探针结果 + 同时活跃 Worker ≤4 |
| vuln-hunting | ≥2个独立攻击面 + 有探针结果 + 主Agent不在该利用链中 |

- Worker 用 `shared/worker-prompt-template.md` 填变量注入，安全约束逐条写入
- Worker 只做独立攻击面初步探测；链式利用/bypass/高危验证主 Agent 亲自做
- Worker 产出 `worker-{id}.json`，Merge 前不进 verified_findings

## ACT：执行约束

- 发包主力 `replay.py`（Burp启用时）或 curl；广度阶段每格 ≤2 次请求
- ⚠️ **replay.py 默认走 Burp 代理（127.0.0.1:8080）**——Phase 0-A 选了"不使用 Burp"时，replay 必须**显式加 `--no-proxy`**（否则连不上代理会误判目标不可达），或 `export REPLAY_PROXY=""`；选了"使用 Burp"则确认 8080 在监听
- 每次发包前对照治理规则（`E:\Agent\0x00_Governance\AGENTS.md`）：HTTP 方法分级 / 数据上限（越权≤5组、注入≤5组）/ 响应熔断
- 命中验证即止条件（拿到唯一标志 / 回连验证地址成功）→ 立即停，转 RECORD

## ACT：拦截事件强制协议（401/403，机械记账，禁止静默跳过）

`replay.py` 检测到 401/403 响应时**自动写入 403-ledger.jsonl（open 账目）**——不依赖你记得，账已记下。此后：

1. **立即跑变体矩阵**：`python core/pentest-flow/bypass_403.py <url> --method <原方法>`（路径变形/后缀伪装/Header 欺骗/HEAD·OPTIONS，GET 级无害，≤28 请求，参考 `param-asymmetry-fuzz.md` §三）
2. **HIT** → replay.py 复验取证 → 记 fact + coverage 格 finding（403→200 即潜在越权绕过）
3. **矩阵全无突破** → 允许标 parked（bypass_403 已自动关账）；特殊情况人工关账用 `pentest-state b403 close "<METHOD> <url>" "<理由>"`
4. **gate 硬检查**：存在未关账 401/403 事件 → gate FAIL，禁止进入下一阶段
5. 403 是登录墙（未授权本就进不去的业务面）时**照跑矩阵**（成本≤28请求）后 park，不允许凭判断直接跳过
6. 知识深化：矩阵无果但格子值得深入 → Read `shared/knowledge/appsec/waf-bypass.md` / `param-asymmetry-fuzz.md`（403 现场上下文打法）

## RECORD：每轮收尾五件事（缺一不可）

1. **Auto Fact 提取**：curl 响应中的客观现象 → `facts[]`（含 id/description/target/vuln_type/raw_evidence）
2. **coverage 更新**：本格状态 pending→tested/finding/blocked/interesting/skip
3. **trace 留痕**：`node shared/state/pentest-state.mjs trace write main '{"round":N,"act":"...","result":"..."}'`
4. **decision_log**：追加本轮决策（含 evidence_refs 引用 fact id）
5. **输出协议**：末尾独占一行
   ```
   PHASE: <bootstrap|reason|execute|merge|verify>
   STATUS: <running|vuln_found|low_roi|need_input|error>
   FINDING: <severity>|<type>|<endpoint>|<title>|<confidence>
   ```

## 新发现 → 立即过验证门

**基础门（所有发现必过）**：有curl+完整头+实际响应 | 响应含声称数据（逐字匹配）| 不在垃圾洞/不报清单 | 影响范围明确 | PoC含复现步骤

**深度验证（High/Critical 必过三门）**：
- Grounding：主 Agent 亲自重放 curl 确认证据
- Negation：数据是否当前用户自己的/测试数据？换参数/换账号能否复现？
- Interrogation：假设结论是错的——什么证据能推翻？审核员会用什么理由拒绝？

**确定性验证器**：`node shared/state/verify-finding.mjs <finding.json>` — 代码判断，rejected 不入 verified_findings。

## Merge 阶段（有 Worker 产出时）

按序执行，任一步失败即停：

```bash
node shared/state/pentest-state.mjs bb merge worker-1.json   # 合并Worker产出
node shared/state/pentest-state.mjs intent validate          # intents的evidence_refs校验
node shared/state/pentest-state.mjs bb observe               # 矛盾/盲点/陈旧/孤立fact检测
node shared/state/verify-finding.mjs <finding.json>          # 每个finding过确定性验证器
node shared/state/pentest-state.mjs route check              # 合并新攻击面后重新复核情境路由
```

## 方向切换 / 卡死

→ Read `shared/playbooks/chain.md` §方向切换（触发条件 / 反思三问 / 四维切换 / 剑走偏锋）。发现可串联漏洞 → `chain add`（对照打穿短表）。

## Compact / 跨 session 恢复

```bash
node shared/state/pentest-state.mjs recover    # 从黑板+traces重建态势
node shared/state/pentest-state.mjs summary    # 生成handoff摘要
```

恢复后第一轮：重读本文件 + `coverage stats` + `route check`，不凭记忆继续。

## 阶段收口 gate（Merge 前、切换深度阶段前、写报告前必须跑）

```bash
node shared/state/pentest-state.mjs gate
```

输出 PASS/FAIL 检查清单。**gate 不过禁止进入下一阶段**——这是机械门禁，不是自查。

## 终止条件（对照脚本输出判断，不凭感觉）

| 模式 | 终止条件 |
|------|---------|
| pentest-flow | OWASP 10类别各至少1轮且 `meta.owasp_coverage` 全≠untested；intents 全部 completed/dead 且无新 attack_surfaces；用户终止 |
| vuln-hunting | ≥3个Critical/High+完整PoC；intents 全部 completed/dead 且无新 attack_surfaces；`meta.no_finding_streak`≥5；用户终止 |

终止后 → `gate` 最终跑一次 → `summary` → 报告（report-generator）。
