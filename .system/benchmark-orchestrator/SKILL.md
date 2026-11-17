---
name: benchmark-orchestrator
version: 2.1
description: >
  CTF Benchmark 管道调度skill。
  最多3题并行，无条件hint，三阶段扫荡（easy→medium→hard），步数上限。
  主Agent独占benchmark API + 容器生命周期，Worker只解题。
triggers:
  - benchmark
  - tsec
  - 跑分
  - ctf benchmark
inputs_required:
  - base_url: Benchmark平台地址（BENCHMARK_BASE_URL）
  - token: 跑分任务token（BENCHMARK_TOKEN）
inputs_optional:
  - total_budget: 总时间预算秒数（默认21600=6h）
---

# Benchmark Orchestrator v2.1 — 管道三阶段

> 最多3题并行（管道模式）。无条件取hint。Easy全扫→Medium全扫→Hard集中攻坚→Mop Up回扫。
> **主Agent独占 benchmark API，Worker只解题。**

## 架构

```
主Agent（调度器）
├── 独占 benchmark API（list/start/hint/submit/close）
├── 维护 benchmark-state.json
├── 管道调度：最多3个容器 + 3个Worker同时运行
├── 初始填满3 slot → task-notification到达 → harvest → 补填下一题
└── 调度逻辑是线性的（逐个处理notification），并发在Worker侧

Worker（解题单元）
├── 收到：题目 + container_addr + hint + 知识卡
├── 在步数上限内解题 → 找flag + 记录发现
├── 写 worker-{id}.json
└── 绝不碰 benchmark API
```

## 核心不变量

1. **只有主Agent调用 start/close/hint/submit** — Worker prompt中不含API信息
2. **最多3个活跃容器** — active_slots数组长度 ≤ 3
3. **Worker写独立结果文件** — 不碰 benchmark-state.json
4. **event-driven** — 不轮询、不sleep、不wait_for_workers。task-notification自动到达触发harvest+补填

---

## Phase 0: Bootstrap（主Agent亲自，一次性）

1. **拉题目列表**
   ```
   challenges = GET {base_url}/openapi/v1/challenges
       Header: BENCHMARK_TOKEN = {token}
   ```

2. **分类**：按description/unique_code前缀推断 category (web|reverse|crypto|pwn|misc)

3. **分三组排序**
   ```
   easy   = [ch for ch if difficulty=="easy"],   sorted by total_score DESC
   medium = [ch for ch if difficulty=="medium"], sorted by total_score DESC
   hard   = [ch for ch if difficulty=="hard"],   sorted by total_score DESC
   ```

4. **批量取hint（无条件，所有题）**
   ```
   for ch in easy + medium + hard:
       resp = GET {base_url}/openapi/v1/challenges/hint?unique_code={ch.unique_code}
       ch.hint = resp.hint or "无hint"
   ```

5. **初始化 benchmark-state.json**
   ```
   Write benchmark-state.json:
     meta: {task_id, token, base_url, start_time, total_score:0, total_flags:0,
            current_phase:1, current_index:0, status:"running"}
     easy: [...], medium: [...], hard: [...]
     completed: [], skipped: [], decision_log: []
   ```

6. **输出初始态势**
   ```
   "题目总数: {N}, 总分: {sum}
    Easy: {n1}题/{s1}分, Medium: {n2}题/{s2}分, Hard: {n3}题/{s3}分
    Hint已全部获取。进入Phase 1 Easy Sweep。"
   ```

---

## Phase 1-4: 三阶段扫荡 + Mop Up（管道模式）

### 管道调度核心

```
MAX_SLOTS = 3
active_slots = []  # [{ch, worker_id, agent_id}]  当前在做的题

function pipeline_run(queue, max_steps):
    """管道执行一组题目。queue是本阶段待做题列表。"""

    # 1. 初始填满：一次spawn最多3个Worker（同一消息并行发出）
    batch = []
    while len(active_slots) < MAX_SLOTS and queue has pending:
        ch = queue.pop_next_pending()
        start_container(ch)
        batch.append(ch)
    # 同一条消息里并行spawn所有batch中的Worker
    for ch in batch:
        agent_id = Agent(prompt=build_worker_prompt(ch, max_steps), 
                         description="[{ch.difficulty}] {ch.unique_code}")
        active_slots.append({ch, worker_id, agent_id})

    # 2. 事件循环：每收到一个task-notification就处理+补填
    while active_slots not empty:
        # task-notification自动到达（不轮询、不sleep）
        notification = next task-notification
        slot = find_slot_by(notification.agent_id)
        
        # harvest
        harvest_and_submit(slot.ch)
        
        # close容器
        close_container(slot.ch)
        active_slots.remove(slot)
        
        # 补填：queue中还有pending题就立即start+spawn
        if queue has pending and len(active_slots) < MAX_SLOTS:
            next_ch = queue.pop_next_pending()
            start_container(next_ch)
            agent_id = Agent(prompt=build_worker_prompt(next_ch, max_steps),
                             description="[{next_ch.difficulty}] {next_ch.unique_code}")
            active_slots.append({next_ch, worker_id, agent_id})
        
        # 更新state
        Write benchmark-state.json
```

### Phase 1: Easy Sweep
```
pipeline_run(queue=state.easy, max_steps=15)
```
目标：快速清完所有easy题。3题并行，notification到一个补一个。

### Phase 2: Medium Sprint
```
pipeline_run(queue=state.medium, max_steps=25)
```

### Phase 3: Hard Focus
```
pipeline_run(queue=state.hard, max_steps=40)
```
Hard题允许retry一次（harvest时判断）。

### Phase 4: Mop Up（回扫）
```
# 构建回扫队列（优先级依次递减）
mopup_queue = []

# 1. partial题：有flag但未满分
mopup_queue += [ch from completed if correct_flag_count > 0 and correct_flag_count < flag_count]

# 2. 仍pending的题（Phase 1-3单次无果未skip的）
mopup_queue += [ch from easy+medium+hard if ch.phase == "pending"]

# 3. infra_blocked → 重试container（最多3题）
mopup_queue += [ch from skipped if "infra_blocked" in ch.skip_reason][:3]

# 4. skip题中有useful findings的（最多5题）
mopup_queue += [ch from skipped if ch.last_findings != "" and not infra_blocked][:5]

# 所有回扫标记retry=True
for ch in mopup_queue: ch.is_retry = True
pipeline_run(queue=mopup_queue, max_steps=25)
```

### 阶段切换
每个Phase完成后输出：
```
"Phase {N} 完成。得分: {score}/{max}, Flags: {flags}/{total}, 
 Done: {n}, Skipped: {n}。进入Phase {N+1}。"
```
更新 state.meta.current_phase 和 decision_log。

---

## 容器管理：start_container / close_container

```
function start_container(ch):
    resp = POST {base_url}/openapi/v1/challenges/start?unique_code={ch.unique_code}
    if resp.error:
        if "invalid_state" in resp.error:
            POST {base_url}/openapi/v1/challenges/close?unique_code={ch.unique_code}
            resp = POST start again
        if resp.error:
            ch.phase = "skip"
            move_to_skipped(ch, reason="start_failed: " + resp.error)
            return False
    ch.container_addr = resp.container_addr
    return True

function close_container(ch):
    POST {base_url}/openapi/v1/challenges/close?unique_code={ch.unique_code}
```

---

## Harvest：harvest_and_submit(ch)

Worker的task-notification到达后，主Agent执行：

```
function harvest_and_submit(ch):

    # 1. 读Worker结果文件
    result = Read("worker-{worker_id}.json")
    if not result:
        ch.phase = "skip"
        move_to_skipped(ch, reason="no_result_file")
        return

    # 2. 提交flags
    for flag in result.flags:
        normalize_and_submit(ch, flag)

    # 3. 记录findings摘要（供retry时注入）
    ch.last_findings = summarize(result.facts + result.failures)
    ch.attempts += 1

    # 4. 判断结果
    if ch.is_completed:
        ch.phase = "done"
        move_to_completed(ch)
    elif result.status == "blocked":
        ch.phase = "skip"
        move_to_skipped(ch, reason="infra_blocked")
    elif ch.is_retry or ch.attempts >= 2:
        if not result.flags:
            ch.phase = "skip"
            move_to_skipped(ch, reason="no_progress_after_{ch.attempts}_attempts")
    # 否则保留pending，Phase内不自动retry（Mop Up会回扫）

    # 5. 清理worker文件
    Delete("worker-{worker_id}.json")
```

---

## Flag提交：normalize_and_submit

```
function normalize_and_submit(ch, raw_flag):
    candidates = [
        raw_flag,
        raw_flag.strip(),
        raw_flag.replace("\n", ""),
        "flag{" + raw_flag + "}",
        "FLAG{" + raw_flag + "}",
    ]
    # 已有flag{}包裹时，也试纯内容
    if raw_flag.startswith("flag{") and raw_flag.endswith("}"):
        candidates.append(raw_flag[5:-1])

    for flag in candidates:
        if flag in ch.flags_submitted: continue
        ch.flags_submitted.append(flag)
        resp = POST {base_url}/openapi/v1/challenges/submit
            Body: {unique_code: ch.unique_code, flag: flag}
        if resp.correct:
            state.meta.total_score += resp.awarded
            state.meta.total_flags += 1
            ch.correct_flag_count = resp.correct_flag_count
            if resp.correct_flag_count == resp.total_flag_count:
                ch.is_completed = True
            return resp
    return None
```

---

## Worker Prompt 构建

```
function build_worker_prompt(ch, max_steps, retry):
    template = Read("<本SKILL.md所在目录>/worker-prompt.md")
    knowledge_cards = select_knowledge_cards(ch)

    previous_attempt = ""
    if retry and ch.last_findings:
        previous_attempt = "上次尝试发现：" + ch.last_findings + "\n请换角度攻击，避免重复。"

    return template.replace({
        ${CHALLENGE_CODE}: ch.unique_code,
        ${DESCRIPTION}: ch.description or "无描述",
        ${DIFFICULTY}: ch.difficulty,
        ${CATEGORY}: ch.category,
        ${CONTAINER_ADDR}: join(ch.container_addr, ", "),
        ${HINT}: ch.hint or "无hint",
        ${MAX_STEPS}: max_steps,
        ${FLAG_COUNT}: ch.flag_count,
        ${CORRECT_FLAGS}: ch.correct_flag_count,
        ${PREVIOUS_ATTEMPT}: previous_attempt,
        ${KNOWLEDGE_CARDS}: knowledge_cards_content,
        ${WORK_DIR}: "<当前会话工作目录>/benchmark",
        ${WORKER_ID}: "w-{phase}-{index}",
    })
```

## 知识卡路由

```
function select_knowledge_cards(ch):
    base = "<本SKILL.md所在目录>/knowledge/"
    category_map = {
        "web":     [base+"ctf-web-manual.md", base+"cve-web-common.md"],
        "reverse": [base+"ctf-reverse.md"],
        "pwn":     [base+"ctf-pwn.md"],
        "crypto":  [base+"ctf-crypto.md"],
        "misc":    [base+"ctf-misc.md"],
    }
    cards = category_map.get(ch.category, [base+"ctf-web-manual.md"])

    # 关键词追加专项卡
    desc = (ch.description or "") + (ch.hint or "")
    if "flask" in desc.lower() or "jwt" in desc.lower():
        cards.append(base+"cve-flask-jwt.md")
    if "langflow" in desc.lower():
        cards.append(base+"cve-langflow-rce.md")

    return cards[:2]  # 最多2张
```

---

## 输出协议

每题完成后输出：
```
[{difficulty}] {unique_code}: {status} | score +{gained} | flags {correct}/{total}
```

每阶段完成后输出：
```
PHASE: {N} | SCORE: {total}/{max} | FLAGS: {f}/{total_f} | DONE: {n} | SKIP: {n}
```

---

## Compact恢复

上下文被压缩后：
1. Read benchmark-state.json
2. 读 meta.current_phase + meta.current_index → 恢复到哪个阶段
3. 读 meta.total_score / total_flags → 当前成绩
4. 读 meta.active_slots → 有无正在跑的Worker
5. 读 completed → 已解题目
6. 读 skipped → 已跳过题目
7. 如果 active_slots 非空 → 这些Worker可能还在跑，等它们的task-notification
8. 从当前阶段的queue中找下一个pending题，恢复pipeline_run循环

---

## 安全红线

- 仅限靶场环境，不对外部目标发请求
- RCE仅回显(whoami/id/cat flag)
- 不写真实数据，不做持久化破坏

## 终止条件

1. 所有题 done/skip → `status: "finished"`
2. 总预算耗尽 → `status: "timeout"`
3. 用户手动停止

终止后：close所有活跃容器 → 输出成绩单（总分/flag数/完成率/耗时/每题状态）

---

## 速查卡（每题前读）

```
管道模式：最多3个Worker并行 | hint已取 | notification到一个补一个
Easy≤15步 Medium≤25步 Hard≤40步
连续2次无进展→skip | 容器不可达→skip
Flag多格式提交 | partial+pending+infra+retriable→Mop Up回扫
Worker不碰API | 结果写worker-{id}.json
同一消息并行spawn填满slot | 不轮询不sleep等notification
```
